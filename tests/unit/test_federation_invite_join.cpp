// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
//
// +-------------------------------------------------------------------------+
// |        FEDERATED INVITE-THEN-JOIN CONFORMANCE TESTS                     |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms   |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec or a   |
// |  hard correctness invariant. If a test fails:                            |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |       spec itself has changed and citing the updated section.            |
// |                                                                         |
// |  These tests guard three bugs that caused Synapse to reject joins with  |
// |  "403: You are not invited to this room":                                |
// |                                                                         |
// |  1. membership_template_provider did not populate auth_events on the    |
// |     make_join template, so the joining server signed a PDU with empty   |
// |     auth_events that could not be validated.                             |
// |  2. membership_acceptor did not copy auth_event_ids from the envelope   |
// |     to the persisted event, breaking the BFS auth-chain walk.           |
// |  3. invite_handler did not store the invite in store.events/state, so   |
// |     for inbound-invite cases the event was unreachable during BFS.      |
// +-------------------------------------------------------------------------+

#include "../support/MasterKey.hpp"
#include "../support/MembershipFixtureSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "FederationSigningTestSupport.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/Event.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/events/EventSigner.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/FederationResponse.hpp"
#include "merovingian/federation/SignedFederationRequest.hpp"
#include "merovingian/federation/InboundRequest.hpp"
#include "merovingian/federation/InboundRequestProviders.hpp"
#include "merovingian/homeserver/CreateRoomOptions.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"
#include "merovingian/rooms/EventIdFormat.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(__NetBSD__)
#else
#endif

#define MEROVINGIAN_NETBSD_DIAG(msg) merovingian_netbsd_diag(msg)

// --- FED-1: own-domain events in a send_join response ------------------------
// Spec: Server-Server API v1.19, "Checks performed on receipt of a PDU": "2.
// Passes signature checks, otherwise it is dropped." There is no exception for
// events that name a sender on the receiving server. A resident server has no
// reason to send us events we authored that we do not already hold, so an
// event claiming our domain is verified against this server's OWN signing keys
// (current and retired — never fetched over the network), and dropped when the
// key is not one we hold or the signature does not verify.
namespace
{
[[nodiscard]] auto unsigned_member_event(std::string const& room_id, std::string const& user_id)
    -> merovingian::canonicaljson::Value
{
    auto raw = std::string{"{\"type\":\"m.room.member\",\"state_key\":\""};
    raw += user_id;
    raw += "\",\"room_id\":\"";
    raw += room_id;
    raw += "\",\"sender\":\"";
    raw += user_id;
    raw += "\",\"depth\":5,\"origin_server_ts\":1000,\"prev_events\":[],\"auth_events\":[],";
    raw += "\"hashes\":{\"sha256\":\"aGFzaA\"},\"content\":{\"membership\":\"join\"}}";
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parsed.value;
}

} // namespace

// --- FED-1: send_join response events are bound to the room being joined ----
// Spec: Server-Server API v1.19, "Joining Rooms": the send_join response's
// `state` is the room state before the join event and `auth_chain` is the
// auth chain for that state — both describe the room being joined and
// nothing else. rooms/v12.md: the m.room.create event has no room_id; "The
// room ID is the event ID of the event with sigil ! instead of $", and a
// create event that has a room_id is rejected (auth rule 1.2).
namespace
{

[[nodiscard]] auto parse_test_event(std::string const& raw) -> merovingian::canonicaljson::Value
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parsed.value;
}

[[nodiscard]] auto v12_create_event(std::string const& creator, std::string const& nonce)
    -> merovingian::canonicaljson::Value
{
    return parse_test_event(R"({"type":"m.room.create","state_key":"","sender":")" + creator +
                            R"(","depth":1,"origin_server_ts":1000,"prev_events":[],"auth_events":[],)"
                            R"("hashes":{"sha256":"aGFzaA"},"content":{"room_version":"12","nonce":")" +
                            nonce + R"("}})");
}

[[nodiscard]] auto derived_v12_room_id(merovingian::canonicaljson::Value const& create,
                                       merovingian::rooms::RoomVersionPolicy const& policy) -> std::string
{
    auto const eid = merovingian::events::make_reference_hash_event_id(create, policy);
    REQUIRE(eid.error.empty());
    REQUIRE_FALSE(eid.event_id.empty());
    return "!" + eid.event_id.substr(1);
}

} // namespace

SCENARIO("filter_send_join_events_for_room keeps only events for the room being joined",
         "[homeserver][federation][send_join][security][fed1]")
{
    GIVEN("a v10 send_join array mixing events for the joined room, another room, and no room at all")
    {
        auto const joined = std::string{"!joined:remote.example.org"};
        auto const other = std::string{"!local:example.org"};
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(unsigned_member_event(joined, "@bob:remote.example.org"));
        array.push_back(unsigned_member_event(other, "@alice:example.org"));
        array.push_back(parse_test_event(
            R"({"type":"m.room.power_levels","state_key":"","sender":"@evil:remote.example.org","depth":2,)"
            R"("origin_server_ts":1000,"prev_events":[],"auth_events":[],"content":{}})"));

        WHEN("the array is filtered for the joined room")
        {
            auto const kept = merovingian::homeserver::filter_send_join_events_for_room(array, joined, policy);

            THEN("only the joined room's event survives")
            {
                REQUIRE(kept.size() == 1U);
                auto const envelope = merovingian::events::parse_event_envelope(kept.front());
                REQUIRE(envelope.error.empty());
                REQUIRE(envelope.event.room_id == joined);
            }
        }
    }
}

SCENARIO("filter_send_join_events_for_room binds a v12 m.room.create event by its derived room ID",
         "[homeserver][federation][send_join][security][v12][fed1]")
{
    GIVEN("the v12 create event of the joined room and the create event of a different v12 room")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        REQUIRE(policy->create_event_is_room_id);
        auto const joined_create = v12_create_event("@creator:remote.example.org", "joined");
        auto const other_create = v12_create_event("@creator:remote.example.org", "other");
        auto const joined = derived_v12_room_id(joined_create, *policy);
        REQUIRE(derived_v12_room_id(other_create, *policy) != joined);

        auto array = merovingian::canonicaljson::Array{};
        array.push_back(other_create);
        array.push_back(joined_create);

        WHEN("the array is filtered for the joined room")
        {
            auto const kept = merovingian::homeserver::filter_send_join_events_for_room(array, joined, *policy);

            THEN("only the create event whose reference hash is the joined room ID survives")
            {
                REQUIRE(kept.size() == 1U);
                REQUIRE(derived_v12_room_id(kept.front(), *policy) == joined);
            }
        }
    }

    GIVEN("a v12 create event that carries a room_id field naming the joined room")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto const joined = derived_v12_room_id(v12_create_event("@creator:remote.example.org", "joined"), *policy);
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(parse_test_event(
            R"({"type":"m.room.create","state_key":"","room_id":")" + joined +
            R"(","sender":"@creator:remote.example.org","depth":1,"origin_server_ts":1000,"prev_events":[],)"
            R"("auth_events":[],"hashes":{"sha256":"aGFzaA"},"content":{"room_version":"12","nonce":"joined"}})"));

        WHEN("the array is filtered for the joined room")
        {
            auto const kept = merovingian::homeserver::filter_send_join_events_for_room(array, joined, *policy);

            THEN("the create event is dropped, as v12 auth rule 1.2 rejects it")
            {
                REQUIRE(kept.empty());
            }
        }
    }
}
