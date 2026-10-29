// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Run 10 (Complement): the validation an inbound PUT /_matrix/federation/v2/invite applies to
// `invite_room_state`. Since spec v1.16 the list holds full signed PDUs, not stripped events.

#include "../federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/runtime_federation.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

constexpr auto origin_server = "remote.example.org";
constexpr auto creator_server = "creator.example.org";
constexpr auto key_id = "ed25519:auto";
constexpr auto origin_seed = "invite-room-state-origin-seed";
constexpr auto creator_seed = "invite-room-state-creator-seed";

[[nodiscard]] auto runtime_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 1U << 20U;
    config.remote_timeout_seconds = 30U;
    config.server_name = "local.example.org";
    return config;
}

[[nodiscard]] auto remote_for(std::string const& server, std::string const& seed)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = server;
    remote.signing_key = {server, key_id, 4'102'444'800'000U,
                          merovingian::federation::test::keypair_from_seed(seed).public_key};
    remote.discovery.server_name = server;
    remote.discovery.well_known_host = server;
    remote.discovery.resolved_host = server;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_put_request(std::string const& target, std::string const& body)
    -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "PUT";
    request.target = target;
    request.origin = origin_server;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = body;
    request.signature = merovingian::federation::make_federation_signature(
        request.origin, request.destination, request.method, request.target, request.body,
        merovingian::federation::test::keypair_from_seed(origin_seed).secret_key);
    return request;
}

[[nodiscard]] auto signed_event(std::string const& unsigned_json, std::string const& server, std::string const& seed,
                                std::string const& room_version) -> std::string
{
    auto json =
        merovingian::federation::test::make_signed_event_json(unsigned_json, server, key_id, seed, room_version);
    // Fixture: the event was signed.
    REQUIRE_FALSE(json.empty());
    return json;
}

// A room whose create event `creator` sent and `server` signed, the way a room-version-formatted PDU
// travels: full signed PDUs, the create event with no room_id.
struct StateFixture final
{
    std::string room_version{};
    std::string room_id{};
    std::string create{};
    std::string name{};
    std::string invite{};
    std::string invite_event_id{};
};

[[nodiscard]] auto make_fixture(std::string const& room_version, std::string const& create_server,
                                std::string const& create_seed) -> StateFixture
{
    auto fixture = StateFixture{};
    fixture.room_version = room_version;
    auto const creator = std::string{"@alice:"} + create_server;
    fixture.create = signed_event(std::string{R"({"auth_events":[],"content":{"room_version":")"} + room_version +
                                      R"("},"depth":1,"origin_server_ts":1000000,"prev_events":[],"sender":")" +
                                      creator + R"(","state_key":"","type":"m.room.create"})",
                                  create_server, create_seed, room_version);
    fixture.room_id =
        "!" + merovingian::federation::test::reference_hash_event_id(fixture.create, room_version).substr(1U);
    fixture.name =
        signed_event(std::string{R"({"auth_events":[],"content":{"name":"Stripped"},"depth":2,)"
                                 R"("origin_server_ts":1000001,"prev_events":[],"room_id":")"} +
                         fixture.room_id + R"(","sender":")" + creator + R"(","state_key":"","type":"m.room.name"})",
                     create_server, create_seed, room_version);
    fixture.invite = signed_event(std::string{R"({"auth_events":[],"content":{"membership":"invite"},"depth":3,)"
                                              R"("origin_server_ts":1000002,"prev_events":[],"room_id":")"} +
                                      fixture.room_id + R"(","sender":"@alice:)" + origin_server +
                                      R"(","state_key":"@bob:local.example.org","type":"m.room.member"})",
                                  origin_server, origin_seed, room_version);
    fixture.invite_event_id = merovingian::federation::test::reference_hash_event_id(fixture.invite, room_version);
    return fixture;
}

[[nodiscard]] auto join_entries(std::vector<std::string> const& entries) -> std::string
{
    auto out = std::string{"["};
    for (auto index = std::size_t{0U}; index < entries.size(); ++index)
    {
        out += index == 0U ? "" : ",";
        out += entries[index];
    }
    return out + "]";
}

struct InviteHarness final
{
    merovingian::federation::FederationRuntimeState runtime{
        merovingian::federation::make_federation_runtime_state(runtime_config())};
    std::vector<merovingian::federation::InviteRequest> seen{};
    std::size_t creator_lookups{0U};

    // The handlers below capture `this`, so the harness stays where it is built.
    InviteHarness(InviteHarness const&) = delete;
    auto operator=(InviteHarness const&) -> InviteHarness& = delete;
    InviteHarness(InviteHarness&&) = delete;
    auto operator=(InviteHarness&&) -> InviteHarness& = delete;
    ~InviteHarness() = default;

    InviteHarness()
    {
        merovingian::federation::upsert_remote(runtime, remote_for(origin_server, origin_seed));
        runtime.remote_key_resolver =
            [this](std::string_view server,
                   std::string_view requested) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server != creator_server || requested != key_id)
            {
                return std::nullopt;
            }
            ++creator_lookups;
            return remote_for(creator_server, creator_seed);
        };
        runtime.invite_handler = [this](merovingian::federation::InviteRequest const& request) {
            seen.push_back(request);
            auto result = merovingian::federation::InviteAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.signed_event_json = request.invite_event_json;
            return result;
        };
    }

    [[nodiscard]] auto send(StateFixture const& fixture, std::vector<std::string> const& room_state)
        -> merovingian::federation::FederationResponse
    {
        auto const body = std::string{R"({"event":)"} + fixture.invite + R"(,"invite_room_state":)" +
                          join_entries(room_state) + R"(,"room_version":")" + fixture.room_version + R"("})";
        auto const target = "/_matrix/federation/v2/invite/" + fixture.room_id + "/" + fixture.invite_event_id;
        return merovingian::federation::handle_inbound_federation_request(runtime, signed_put_request(target, body));
    }
};

} // namespace

// Spec: Matrix Server-Server API v1.19
// Section: PUT /_matrix/federation/v2/invite/{roomId}/{eventId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2inviteroomideventid
//
// "`invite_room_state` MUST now have its entries formatted according to the room's version" and
// "The `invite_room_state` has additional validation, which servers MAY apply to room versions 1
// through 11 and SHOULD apply to all other room versions. ... servers SHOULD return
// `M_INVALID_PARAM` if: The `m.room.create` event is missing from `invite_room_state`. One or more
// entries ... are not formatted according to the room's version. One or more events fails a
// signature check. One or more events does not reside in the same room as the invite."
SCENARIO(
    "A room version 12 invite is refused unless its invite_room_state is signed PDUs of its own room with a create "
    "event",
    "[federation][conformance][invite][invite-room-state]")
{
    GIVEN("a runtime whose invite handler records what reaches it, and a v12 room's signed state")
    {
        auto harness = InviteHarness{};
        auto const fixture = make_fixture("12", origin_server, origin_seed);

        WHEN("the invite carries the create event and another state event, both full signed PDUs")
        {
            auto const response = harness.send(fixture, {fixture.create, fixture.name});

            THEN("it is accepted and the handler is given both entries")
            {
                CAPTURE(response.body);
                // Spec MUST: a PDU-formatted invite_room_state carrying m.room.create is valid.
                REQUIRE(response.status == 200U);
                REQUIRE(harness.seen.size() == 1U);
                REQUIRE(harness.seen.front().invite_room_state_json.size() == 2U);
            }
        }

        WHEN("the create event is signed by a server other than the sender's, and only its key lookup can vouch for it")
        {
            auto const other = make_fixture("12", creator_server, creator_seed);
            auto const response = harness.send(other, {other.create, other.name});

            THEN("the key is fetched through the runtime's key resolver and the invite is accepted")
            {
                CAPTURE(response.body);
                // Spec SHOULD: every entry's signature is checked, with the signing server's published key.
                REQUIRE(response.status == 200U);
                REQUIRE(harness.creator_lookups >= 1U);
            }
        }

        WHEN("the create event is missing from invite_room_state")
        {
            auto const response = harness.send(fixture, {fixture.name});

            THEN("it is refused with 400 M_INVALID_PARAM and never reaches the handler")
            {
                // Spec SHOULD: M_INVALID_PARAM when the m.room.create event is missing.
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(harness.seen.empty());
            }
        }

        WHEN("the list is empty")
        {
            auto const response = harness.send(fixture, {});

            THEN("it is refused: an empty list holds no create event")
            {
                // Spec MUST: invite_room_state "MUST contain the m.room.create event for the room".
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(harness.seen.empty());
            }
        }

        WHEN("an entry is a stripped event rather than a PDU")
        {
            auto const stripped = std::string{R"({"content":{"name":"Stripped"},"sender":"@alice:)"} + origin_server +
                                  R"(","state_key":"","type":"m.room.name"})";
            auto const response = harness.send(fixture, {fixture.create, stripped});

            THEN("it is refused with 400 M_INVALID_PARAM")
            {
                // Spec SHOULD: M_INVALID_PARAM when an entry is not formatted according to the room's version.
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(harness.seen.empty());
            }
        }

        WHEN("an entry's signature does not verify")
        {
            auto broken = fixture.name;
            auto const marker = std::string{"\""} + key_id + "\":\"";
            auto const at = broken.find(marker);
            // Fixture: the entry carries the signature to break.
            REQUIRE(at != std::string::npos);
            broken[at + marker.size()] = broken[at + marker.size()] == 'A' ? 'B' : 'A';
            auto const response = harness.send(fixture, {fixture.create, broken});

            THEN("it is refused with 400 M_INVALID_PARAM")
            {
                // Spec SHOULD: M_INVALID_PARAM when an entry fails a signature check.
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(harness.seen.empty());
            }
        }

        WHEN("an entry belongs to another room")
        {
            auto const elsewhere = make_fixture("12", creator_server, creator_seed);
            auto const foreign_name =
                signed_event(std::string{R"({"auth_events":[],"content":{"name":"Elsewhere"},"depth":2,)"
                                         R"("origin_server_ts":1000001,"prev_events":[],"room_id":")"} +
                                 elsewhere.room_id + R"(","sender":"@alice:)" + origin_server +
                                 R"(","state_key":"","type":"m.room.name"})",
                             origin_server, origin_seed, "12");
            auto const response = harness.send(fixture, {fixture.create, foreign_name});

            THEN("it is refused with 400 M_INVALID_PARAM")
            {
                // Spec SHOULD: M_INVALID_PARAM when an entry does not reside in the same room as the invite.
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(harness.seen.empty());
            }
        }

        WHEN("the create event is another room's")
        {
            auto const other_create = signed_event(
                std::string{R"({"auth_events":[],"content":{"room_version":"12","topic":"another"},"depth":1,)"
                            R"("origin_server_ts":1000009,"prev_events":[],"sender":"@alice:)"} +
                    origin_server + R"(","state_key":"","type":"m.room.create"})",
                origin_server, origin_seed, "12");
            auto const response = harness.send(fixture, {other_create});

            THEN("its computed room ID differs from the invite's and the invite is refused")
            {
                // Spec SHOULD: for a version whose create event has no room_id, the room ID is computed from it.
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(harness.seen.empty());
            }
        }

        WHEN("the list is longer than any room's stripped state can be")
        {
            auto entries = std::vector<std::string>{fixture.create};
            for (auto index = 0; index < 40; ++index)
            {
                entries.push_back(fixture.name);
            }
            auto const response = harness.send(fixture, entries);

            THEN("it is refused before any signature is checked")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(harness.seen.empty());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: PUT /_matrix/federation/v2/invite/{roomId}/{eventId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2inviteroomideventid
//
// "servers SHOULD warn about invites which fail the validation rather than error in room versions 1
// through 11." The validation is a MAY for those versions, and servers still migrating send
// stripped entries, so they are accepted.
SCENARIO("A room version 10 invite with stripped invite_room_state is still accepted",
         "[federation][conformance][invite][invite-room-state]")
{
    GIVEN("a runtime whose invite handler records what reaches it, and a v10 invite")
    {
        auto harness = InviteHarness{};
        auto const fixture = make_fixture("10", origin_server, origin_seed);
        auto const stripped = std::string{R"({"content":{"name":"Stripped"},"sender":"@alice:)"} + origin_server +
                              R"(","state_key":"","type":"m.room.name"})";

        WHEN("the invite carries only a stripped event")
        {
            auto const response = harness.send(fixture, {stripped});

            THEN("it is accepted")
            {
                CAPTURE(response.body);
                // Spec MAY: validation of room versions 1 through 11 is optional; do not refuse older servers.
                REQUIRE(response.status == 200U);
                REQUIRE(harness.seen.size() == 1U);
            }
        }
    }
}
