// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Spec: Matrix Server-Server API v1.19, PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
//
// Query parameter `omit_members`: "If true, indicates that that calling server can accept a reduced
// response, in which membership events are omitted from `state` and redundant events are omitted from
// `auth_chain`. If the room to be joined has no `m.room.name` nor `m.room.canonical_alias` events in
// its current state, the resident server should determine the room members who would be included in
// the `m.heroes` property of the room summary ... The resident server should include these members'
// membership events in the response `state` field, and include the auth chains for these membership
// events in the response `auth_chain` field."
//
// 200 response: `auth_chain` "If the `omit_members` query parameter was set to `true`, then any events
// that are returned in `state` may be omitted from `auth_chain`, whether or not membership events are
// omitted from `state`"; `members_omitted` "`true` if `m.room.member` events have been omitted from
// `state`"; `servers_in_room` "**Required** if `members_omitted` is true. A list of the servers active
// in the room (ie, those with joined members) before the join"; `state` "If the request had
// `omit_members` set to `true`, events of type `m.room.member` may be omitted from the response to
// reduce the size of the response. If this is done, `members_omitted` must be set to `true`."

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/membership_fixture_support.hpp"
#include "../support/registration_token.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/SignedFederationRequest.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

namespace cj = merovingian::canonicaljson;

auto constexpr local_server = "example.org";
auto constexpr remote_origin = "remote.example.org";
auto constexpr remote_key_id = "ed25519:auto";
auto constexpr remote_key_seed = "omit-members-test-seed";

[[nodiscard]] auto test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto remote_for_test() -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = remote_origin;
    remote.signing_key = {remote_origin, remote_key_id, 4'102'444'800'000U,
                          merovingian::federation::test::keypair_from_seed(remote_key_seed).public_key};
    remote.discovery.server_name = remote_origin;
    remote.discovery.well_known_host = remote_origin;
    remote.discovery.resolved_host = remote_origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_put(std::string const& target, std::string const& body)
    -> merovingian::federation::SignedFederationRequest
{
    auto req = merovingian::federation::SignedFederationRequest{};
    req.method = "PUT";
    req.target = target;
    req.origin = remote_origin;
    req.destination = local_server;
    req.key_id = remote_key_id;
    req.now_ts = 1000U;
    req.canonical_json_verified = true;
    req.body = body;
    req.signature = merovingian::federation::make_federation_signature(
        remote_origin, req.destination, req.method, target, body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return req;
}

[[nodiscard]] auto json_id_array(std::vector<std::string> const& ids) -> std::string
{
    auto out = std::string{"["};
    for (std::size_t i = 0U; i < ids.size(); ++i)
    {
        if (i != 0U)
        {
            out += ',';
        }
        out += "\"" + ids[i] + "\"";
    }
    out += "]";
    return out;
}

struct SignedJoinBody final
{
    std::string body{};
    std::string event_id{};
};

[[nodiscard]] auto make_signed_join_body(std::string const& room_id, std::string const& sender,
                                         std::vector<std::string> const& auth_events,
                                         std::vector<std::string> const& prev_events) -> SignedJoinBody
{
    auto const unsigned_json = std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id +
                               "\",\"sender\":\"" + sender + "\",\"state_key\":\"" + sender +
                               "\",\"content\":{\"membership\":\"join\"},\"depth\":60," +
                               "\"origin_server_ts\":2000,\"prev_events\":" + json_id_array(prev_events) +
                               ",\"auth_events\":" + json_id_array(auth_events) + "}";
    auto const body = merovingian::federation::test::make_signed_event_json(unsigned_json, remote_origin, remote_key_id,
                                                                            remote_key_seed, "12");
    auto const parsed = cj::parse_lossless(body);
    REQUIRE(parsed.error == cj::ParseError::none);
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);
    return {body, merovingian::events::make_reference_hash_event_id(parsed.value, *policy).event_id};
}

// A member event stored as the room's current state for `user_id`, as a resident that already
// accepted the member's join would hold it, and the member added to the roster.
auto plant_member(merovingian::homeserver::HomeserverRuntime& runtime, std::string const& room_id,
                  std::string const& creator, std::string const& user_id, std::string const& membership) -> std::string
{
    using namespace merovingian;
    auto& store = runtime.database.persistent_store;
    auto const* policy = rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);
    auto const event_id = "$member_" + user_id + ":example.org";
    auto const prev_events = tests::fixture_prev_event_ids(store, room_id);
    auto const auth_events = tests::fixture_auth_event_ids(store, room_id, creator, true);

    auto pdu = database::PersistentEvent{};
    pdu.event_id = event_id;
    pdu.room_id = room_id;
    pdu.sender_user_id = creator;
    pdu.prev_event_ids = prev_events;
    pdu.auth_event_ids = auth_events;
    pdu.json =
        std::string{"{\"type\":\"m.room.member\",\"state_key\":\""} + user_id + "\",\"content\":{\"membership\":\"" +
        membership + "\"},\"room_id\":\"" + room_id + "\",\"sender\":\"" + creator + "\",\"event_id\":\"" + event_id +
        "\",\"depth\":5,\"prev_events\":" + json_id_array(prev_events) +
        ",\"auth_events\":" + json_id_array(auth_events) + ",\"hashes\":{\"sha256\":\"x\"},\"origin_server_ts\":1000}";
    pdu.depth = 5U;
    pdu.stream_ordering = runtime.database.next_stream_ordering++;
    auto state = std::optional<database::PersistentStateEvent>{
        database::PersistentStateEvent{room_id, "m.room.member", user_id, event_id}
    };
    REQUIRE(database::store_event_with_state(store, std::move(pdu), std::move(state)));
    auto const state_before = homeserver::compute_state_before(store, room_id, *policy, prev_events);
    REQUIRE(state_before.ok);
    auto const state_after = homeserver::compute_state_after(state_before.state, event_id, "m.room.member", user_id);
    REQUIRE(homeserver::record_event_state(store, room_id, event_id, prev_events, state_after, true).has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));
    store.memberships.push_back({room_id, user_id, membership, 0U});
    if (membership == "join")
    {
        auto const room = std::ranges::find_if(runtime.database.rooms, [&](auto const& current) {
            return current.room_id == room_id;
        });
        REQUIRE(room != runtime.database.rooms.end());
        room->members.push_back(user_id);
    }
    return event_id;
}

[[nodiscard]] auto member_value(cj::Object const& object, std::string_view key) -> cj::Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

struct Answer final
{
    unsigned status{0U};
    cj::Object root{};
    // "type|state_key" of each event in the arrays.
    std::multiset<std::string> state{};
    std::multiset<std::string> auth_chain{};
    std::vector<std::string> state_ids{};
    std::vector<std::string> auth_chain_ids{};
};

auto describe_array(cj::Object const& root, std::string_view key, std::multiset<std::string>& out) -> void
{
    auto const* value = member_value(root, key);
    REQUIRE(value != nullptr);
    auto const* array = std::get_if<cj::Array>(&value->storage());
    REQUIRE(array != nullptr);
    for (auto const& entry : *array)
    {
        auto const* event = std::get_if<cj::Object>(&entry.storage());
        REQUIRE(event != nullptr);
        auto const* type = member_value(*event, "type");
        auto const* state_key = member_value(*event, "state_key");
        REQUIRE(type != nullptr);
        out.insert(std::get<std::string>(type->storage()) + "|" +
                   (state_key == nullptr ? std::string{} : std::get<std::string>(state_key->storage())));
    }
}

[[nodiscard]] auto send_join(merovingian::homeserver::HomeserverRuntime& runtime, std::string const& room_id,
                             SignedJoinBody const& join, std::string const& query) -> Answer
{
    auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join.event_id + query;
    auto const response =
        merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_put(target, join.body));
    auto answer = Answer{};
    answer.status = response.status;
    INFO("response: " << response.body.substr(0U, 400U));
    REQUIRE(response.status == 200U);
    auto const parsed = cj::parse_lossless(response.body);
    REQUIRE(parsed.error == cj::ParseError::none);
    auto const* root = std::get_if<cj::Object>(&parsed.value.storage());
    REQUIRE(root != nullptr);
    answer.root = *root;
    describe_array(answer.root, "state", answer.state);
    describe_array(answer.root, "auth_chain", answer.auth_chain);
    return answer;
}

[[nodiscard]] auto count_members(std::multiset<std::string> const& events) -> std::ptrdiff_t
{
    return std::ranges::count_if(events, [](std::string const& entry) {
        return entry.starts_with("m.room.member|");
    });
}

} // namespace

SCENARIO("send_join answers with a reduced response when the joining server sets omit_members",
         "[federation][send_join][omit_members][conformance]")
{
    GIVEN("a v12 room with a local creator and eight members from four servers, and no name or alias")
    {
        REQUIRE(sodium_init() >= 0);
        // Spec (Joining Rooms, send_join): omit_members=true lets the resident drop member events from state and list
        // servers_in_room instead.
        auto started = merovingian::homeserver::start_runtime(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto const user = merovingian::homeserver::register_local_user(runtime, "host9", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;
        auto const remote_user = std::string{"@eve:"} + remote_origin;
        // Eight joined members across four servers, so five heroes cannot cover them and servers_in_room has to name
        // them.
        auto planted = std::vector<std::string>{};
        for (auto index = 0; index < 8; ++index)
        {
            planted.push_back("@m" + std::to_string(index) + ":srv" + std::to_string(index % 4) + ".example.net");
            std::ignore = plant_member(runtime, room_id, user.value, planted.back(), "join");
        }
        // The remote user holds an invite, which the join names as an auth event.
        auto const invite_id = plant_member(runtime, room_id, user.value, remote_user, "invite");
        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());
        auto const& store = runtime.database.persistent_store;
        // The joiner's invite is one of the join's auth events, so it must reach the joiner even when state omits it.
        auto const auth = merovingian::tests::fixture_auth_event_ids(store, room_id, remote_user, true);
        REQUIRE(std::ranges::find(auth, invite_id) != auth.end());
        auto const join = make_signed_join_body(room_id, remote_user, auth,
                                                merovingian::tests::fixture_prev_event_ids(store, room_id));

        WHEN("the request has omit_members=true")
        {
            // One request per WHEN against the same room, so the three query forms are compared on identical state.
            auto const answer = send_join(runtime, room_id, join, "?omit_members=true");

            THEN("members_omitted is true and servers_in_room, which is then required, lists the servers with joined "
                 "members")
            {
                auto const* omitted = member_value(answer.root, "members_omitted");
                REQUIRE(omitted != nullptr);
                REQUIRE(*std::get_if<bool>(&omitted->storage()) == true);
                auto const* servers = member_value(answer.root, "servers_in_room");
                REQUIRE(servers != nullptr);
                auto listed = std::set<std::string>{};
                for (auto const& server : std::get<cj::Array>(servers->storage()))
                {
                    listed.insert(std::get<std::string>(server.storage()));
                }
                REQUIRE(listed == std::set<std::string>{local_server, "srv0.example.net", "srv1.example.net",
                                                        "srv2.example.net", "srv3.example.net"});
            }
            // With no name or alias the heroes are the five members shown, and nobody else's membership is sent.
            AND_THEN("state keeps the room's other events and at most the five heroes' membership events")
            {
                REQUIRE(answer.state.contains("m.room.create|"));
                REQUIRE(answer.state.contains("m.room.power_levels|"));
                REQUIRE(answer.state.contains("m.room.join_rules|"));
                REQUIRE(count_members(answer.state) == 5);
                REQUIRE_FALSE(answer.state.contains("m.room.member|" + remote_user));
            }
            // Spec: auth_chain holds only what state lacks, so nothing sent in state is repeated there.
            AND_THEN(
                "the join's own auth event that state omits is in auth_chain, and no event of state is repeated there")
            {
                REQUIRE(answer.auth_chain.contains("m.room.member|" + remote_user));
                for (auto const& entry : answer.state)
                {
                    REQUIRE_FALSE(answer.auth_chain.contains(entry));
                }
            }
        }

        // Without the parameter the answer is the full one, and servers_in_room, which only goes with omit_members, is
        // absent.
        WHEN("the request has no omit_members")
        {
            auto const answer = send_join(runtime, room_id, join, "");

            THEN("members_omitted is false, servers_in_room is absent, and every membership event is in state")
            {
                auto const* omitted = member_value(answer.root, "members_omitted");
                REQUIRE(omitted != nullptr);
                REQUIRE(*std::get_if<bool>(&omitted->storage()) == false);
                REQUIRE(member_value(answer.root, "servers_in_room") == nullptr);
                // The creator, eight members and the remote user's invite.
                REQUIRE(count_members(answer.state) == 10);
                REQUIRE(answer.state.contains("m.room.member|" + remote_user));
            }
        }

        WHEN("the request has omit_members=false")
        {
            auto const answer = send_join(runtime, room_id, join, "?omit_members=false");

            THEN("the answer is the full one")
            {
                auto const* omitted = member_value(answer.root, "members_omitted");
                REQUIRE(omitted != nullptr);
                REQUIRE(*std::get_if<bool>(&omitted->storage()) == false);
                REQUIRE(count_members(answer.state) == 10);
            }
        }
    }
}
