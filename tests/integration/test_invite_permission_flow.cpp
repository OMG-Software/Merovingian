// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../FederationSigningTestSupport.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/FederationResponse.hpp"
#include "merovingian/federation/SignedFederationRequest.hpp"
#include "merovingian/federation/InboundRequest.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/StoredRoomVersion.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <sodium.h>

#include <algorithm>
#include <string>
#include <tuple>

// Invite permission (SS7). Spec: Matrix Client-Server API v1.19, "Invite permission":
// ../../docs/matrix-v1.19-spec/client-server-api.md#invite-permission
// "When invites to a given user are blocked, the user's homeserver MUST respond to the following endpoints with
// an HTTP 403 status code, with the Matrix error code M_INVITE_BLOCKED": PUT /v1/invite, PUT /v2/invite,
// POST /rooms/{roomId}/invite, POST /createRoom (a user of the invite list) and
// PUT /rooms/{roomId}/state/m.room.member/{stateKey} with membership invite. A missing, invalid or unsupported
// default_action means invites as normal.

namespace
{

using merovingian::homeserver::ClientServerRuntime;

auto constexpr remote_origin = "remote.example.org";
auto constexpr remote_key_id = "ed25519:auto";
auto constexpr remote_key_seed = "invite-permission-test-seed";
auto constexpr config_path_prefix = "/_matrix/client/v3/";

[[nodiscard]] auto test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto call(ClientServerRuntime& runtime, std::string const& method, std::string const& path,
                        std::string const& token, std::string const& body) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {method, std::string{config_path_prefix} + path, token, body});
}

// Registers `name` and returns its access token.
[[nodiscard]] auto register_user(ClientServerRuntime& runtime, std::string const& name) -> std::string
{
    REQUIRE(
        merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(name, "CorrectHorse7!")})
            .response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + name +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":"D"})"});
    auto const parsed = merovingian::tests::parse_object(login.response.body);
    auto const* token = merovingian::tests::string_member(parsed, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto set_invite_permission(ClientServerRuntime& runtime, std::string const& name,
                                         std::string const& token, std::string const& content) -> std::uint16_t
{
    return call(runtime, "PUT", "user/%40" + name + "%3Aexample.org/account_data/m.invite_permission_config", token,
                content)
        .response.status;
}

[[nodiscard]] auto create_room_for(ClientServerRuntime& runtime, std::string const& token,
                                   std::string const& room_version = "12") -> std::string
{
    auto const created = call(runtime, "POST", "createRoom", token,
                              R"({"preset":"private_chat","room_version":")" + room_version + R"("})");
    REQUIRE(created.response.status == 200U);
    auto const parsed = merovingian::tests::parse_object(created.response.body);
    auto const* room_id = merovingian::tests::string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto membership_row(ClientServerRuntime& runtime, std::string const& room_id, std::string const& user_id)
    -> std::string
{
    for (auto const& row : runtime.homeserver.database.persistent_store.memberships)
    {
        if (row.room_id == room_id && row.user_id == user_id)
        {
            return row.membership;
        }
    }
    return {};
}

[[nodiscard]] auto is_invite_blocked(merovingian::homeserver::DispatchResult const& answered) -> bool
{
    return answered.response.status == 403U && answered.response.body.find("M_INVITE_BLOCKED") != std::string::npos;
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
    req.destination = "example.org";
    req.key_id = remote_key_id;
    req.now_ts = 1000U;
    req.canonical_json_verified = true;
    req.body = body;
    req.signature = merovingian::federation::make_federation_signature(
        remote_origin, req.destination, req.method, target, body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return req;
}

struct SignedInvite final
{
    std::string event_json{};
    std::string event_id{};
};

// An invite from a user of the remote server to `state_key`, signed under `room_version`.
[[nodiscard]] auto make_signed_invite(std::string const& room_id, std::string const& state_key,
                                      std::string const& room_version) -> SignedInvite
{
    auto const unsigned_json = std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id +
                               "\",\"sender\":\"@carol:remote.example.org\",\"state_key\":\"" + state_key +
                               "\",\"content\":{\"membership\":\"invite\"},\"depth\":1," +
                               "\"origin_server_ts\":1000,\"prev_events\":[],\"auth_events\":[]}";
    auto const signed_event = merovingian::federation::test::make_signed_event_json(
        unsigned_json, remote_origin, remote_key_id, remote_key_seed, room_version);
    auto const parsed = merovingian::canonicaljson::parse_lossless(signed_event);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* policy = merovingian::rooms::find_room_version_policy(room_version);
    REQUIRE(policy != nullptr);
    auto const id = merovingian::events::make_reference_hash_event_id(parsed.value, *policy);
    return {signed_event, id.event_id};
}

[[nodiscard]] auto v2_invite(ClientServerRuntime& runtime, std::string const& room_id, std::string const& target_user)
    -> merovingian::federation::FederationResponse
{
    auto const invite = make_signed_invite(room_id, target_user, "10");
    auto const body = "{\"room_version\":\"10\",\"event\":" + invite.event_json + ",\"invite_room_state\":[]}";
    return merovingian::federation::handle_inbound_federation_request(
        runtime.homeserver.federation,
        signed_put("/_matrix/federation/v2/invite/" + room_id + "/" + invite.event_id, body));
}

} // namespace

SCENARIO("A client invite to a local user who blocks invites is refused with M_INVITE_BLOCKED",
         "[ss7][invite-permission][rooms][security]")
{
    GIVEN("alice, in a room, and bob, whose m.invite_permission_config blocks every invite")
    {
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        auto const room_id = create_room_for(runtime, alice);
        auto const bob_id = std::string{"@bob:example.org"};
        REQUIRE(set_invite_permission(runtime, "bob", bob, R"({"default_action":"block"})") == 200U);

        WHEN("alice invites bob with POST /rooms/{roomId}/invite")
        {
            auto const answered =
                call(runtime, "POST", "rooms/" + room_id + "/invite", alice, R"({"user_id":"@bob:example.org"})");

            THEN("the answer is 403 M_INVITE_BLOCKED and no membership is stored for bob")
            {
                CAPTURE(answered.response.body);
                REQUIRE(is_invite_blocked(answered));
                REQUIRE(membership_row(runtime, room_id, bob_id).empty());
            }
        }

        WHEN("alice invites bob with PUT /rooms/{roomId}/state/m.room.member/{stateKey}")
        {
            auto const answered = call(runtime, "PUT", "rooms/" + room_id + "/state/m.room.member/%40bob%3Aexample.org",
                                       alice, R"({"membership":"invite"})");

            THEN("the answer is 403 M_INVITE_BLOCKED and no membership is stored for bob")
            {
                CAPTURE(answered.response.body);
                REQUIRE(is_invite_blocked(answered));
                REQUIRE(membership_row(runtime, room_id, bob_id).empty());
            }
        }

        WHEN("bob removes default_action and alice invites him again")
        {
            REQUIRE(set_invite_permission(runtime, "bob", bob, "{}") == 200U);
            auto const answered =
                call(runtime, "POST", "rooms/" + room_id + "/invite", alice, R"({"user_id":"@bob:example.org"})");

            THEN("the invite is accepted and bob is invited")
            {
                CAPTURE(answered.response.body);
                REQUIRE(answered.response.status == 200U);
                REQUIRE(membership_row(runtime, room_id, bob_id) == "invite");
            }
        }

        WHEN("bob sets a default_action that is not block and alice invites him")
        {
            auto const content =
                GENERATE(std::string{R"({"default_action":"allow"})"}, std::string{R"({"default_action":"BLOCK"})"},
                         std::string{R"({"default_action":5})"}, std::string{R"({"default_action":["block"]})"},
                         std::string{R"({"default_action":null})"});
            REQUIRE(set_invite_permission(runtime, "bob", bob, content) == 200U);
            auto const answered =
                call(runtime, "POST", "rooms/" + room_id + "/invite", alice, R"({"user_id":"@bob:example.org"})");

            THEN("an invalid or unsupported value does not block")
            {
                CAPTURE(content, answered.response.body);
                REQUIRE(answered.response.status == 200U);
                REQUIRE(membership_row(runtime, room_id, bob_id) == "invite");
            }
        }
    }
}

SCENARIO("createRoom refuses an invite list that names a local user who blocks invites, creating nothing",
         "[ss7][invite-permission][create-room][security]")
{
    GIVEN("alice, carol who accepts invites, and bob, who blocks every invite")
    {
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        std::ignore = register_user(runtime, "carol");
        REQUIRE(set_invite_permission(runtime, "bob", bob, R"({"default_action":"block"})") == 200U);
        auto const rooms_before = runtime.homeserver.database.persistent_store.rooms.size();
        auto const events_before = runtime.homeserver.database.persistent_store.events.size();

        WHEN("alice creates a room inviting carol and bob")
        {
            auto const answered =
                call(runtime, "POST", "createRoom", alice,
                     R"({"preset":"private_chat","invite":["@carol:example.org","@bob:example.org"]})");

            THEN("the answer is 403 M_INVITE_BLOCKED and no room, event or invite exists")
            {
                CAPTURE(answered.response.body);
                REQUIRE(is_invite_blocked(answered));
                REQUIRE(runtime.homeserver.database.persistent_store.rooms.size() == rooms_before);
                REQUIRE(runtime.homeserver.database.persistent_store.events.size() == events_before);
                REQUIRE(runtime.homeserver.database.persistent_store.invites.empty());
            }
        }

        WHEN("alice creates a room inviting only carol")
        {
            auto const answered = call(runtime, "POST", "createRoom", alice,
                                       R"({"preset":"private_chat","invite":["@carol:example.org"]})");

            THEN("the room is created")
            {
                CAPTURE(answered.response.body);
                REQUIRE(answered.response.status == 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.rooms.size() == rooms_before + 1U);
            }
        }
    }
}

SCENARIO("A federation invite to a local user who blocks invites is refused with M_INVITE_BLOCKED",
         "[ss7][invite-permission][federation][security]")
{
    GIVEN("bob, who blocks every invite, and a remote server that signs invites")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        merovingian::federation::upsert_remote(runtime.homeserver.federation, remote_for_test());
        auto const bob = register_user(runtime, "bob");
        auto const bob_id = std::string{"@bob:example.org"};
        REQUIRE(set_invite_permission(runtime, "bob", bob, R"({"default_action":"block"})") == 200U);
        auto const remote_room = std::string{"!blocked_room:remote.example.org"};
        auto const events_before = runtime.homeserver.database.persistent_store.events.size();

        WHEN("the remote server sends PUT /_matrix/federation/v2/invite for bob")
        {
            auto const response = v2_invite(runtime, remote_room, bob_id);

            THEN("the answer is 403 M_INVITE_BLOCKED and nothing is stored for the invite")
            {
                CAPTURE(response.body);
                REQUIRE(response.status == 403U);
                REQUIRE(response.body.find("M_INVITE_BLOCKED") != std::string::npos);
                REQUIRE(membership_row(runtime, remote_room, bob_id).empty());
                REQUIRE(runtime.homeserver.database.persistent_store.events.size() == events_before);
                REQUIRE(runtime.homeserver.database.persistent_store.invites.empty());
            }
        }

        WHEN("the remote server sends PUT /_matrix/federation/v1/invite for bob into a room held here")
        {
            auto const alice = register_user(runtime, "alice");
            auto const room_id = create_room_for(runtime, alice, "10");
            auto const version =
                merovingian::homeserver::stored_room_version(runtime.homeserver.database.persistent_store, room_id);
            REQUIRE(version.has_value());
            auto const events_held = runtime.homeserver.database.persistent_store.events.size();
            auto const invite = make_signed_invite(room_id, bob_id, *version);
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.homeserver.federation,
                signed_put("/_matrix/federation/v1/invite/" + room_id + "/" + invite.event_id, invite.event_json));

            THEN("the answer is 403 M_INVITE_BLOCKED and nothing is stored for the invite")
            {
                CAPTURE(response.body);
                REQUIRE(response.status == 403U);
                REQUIRE(response.body.find("M_INVITE_BLOCKED") != std::string::npos);
                REQUIRE(membership_row(runtime, room_id, bob_id).empty());
                REQUIRE(runtime.homeserver.database.persistent_store.events.size() == events_held);
            }
        }

        WHEN("bob stops blocking invites and the remote server sends the v2 invite")
        {
            REQUIRE(set_invite_permission(runtime, "bob", bob, "{}") == 200U);
            auto const response = v2_invite(runtime, remote_room, bob_id);

            THEN("the invite is accepted and bob is invited")
            {
                CAPTURE(response.body);
                REQUIRE(response.status == 200U);
                REQUIRE(membership_row(runtime, remote_room, bob_id) == "invite");
            }
        }
    }
}

// Spec, "Invite permission": "invite events for this user already in the database, or received over federation,
// MUST NOT be served over client synchronisation endpoints such as GET /sync", and "Servers MAY return any
// suppressed invite events over GET /sync if invite blocking is later disabled." This server returns them.
SCENARIO("An invite stored before its user blocks invites is withheld from /sync and sliding sync",
         "[ss7][invite-permission][sync][security]")
{
    GIVEN("bob, invited to alice's room while he accepted invites, who then blocks every invite")
    {
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        auto const room_id = create_room_for(runtime, alice);
        REQUIRE(call(runtime, "POST", "rooms/" + room_id + "/invite", alice, R"({"user_id":"@bob:example.org"})")
                    .response.status == 200U);
        REQUIRE(membership_row(runtime, room_id, "@bob:example.org") == "invite");
        REQUIRE(set_invite_permission(runtime, "bob", bob, R"({"default_action":"block"})") == 200U);
        auto const sliding_sync = [&runtime, &bob, &room_id]() {
            return merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?timeout=0", bob,
                          R"({"conn_id":"ss7","room_subscriptions":{")" + room_id + R"(":{"timeline_limit":1}}})"});
        };

        WHEN("bob syncs with GET /sync and with sliding sync")
        {
            auto const synced = call(runtime, "GET", "sync?timeout=0", bob, {});
            auto const slid = sliding_sync();

            THEN("neither answer names the room he is invited to")
            {
                CAPTURE(synced.response.body, slid.response.body);
                REQUIRE(synced.response.status == 200U);
                REQUIRE(slid.response.status == 200U);
                REQUIRE(synced.response.body.find(room_id) == std::string::npos);
                REQUIRE(slid.response.body.find(room_id) == std::string::npos);
            }
        }

        WHEN("bob first syncs while blocking, then stops blocking invites and syncs again")
        {
            REQUIRE(sliding_sync().response.status == 200U);
            REQUIRE(set_invite_permission(runtime, "bob", bob, "{}") == 200U);
            auto const synced = call(runtime, "GET", "sync?timeout=0", bob, {});
            auto const slid = sliding_sync();

            THEN("both answers report the invite again")
            {
                CAPTURE(synced.response.body, slid.response.body);
                REQUIRE(synced.response.status == 200U);
                REQUIRE(slid.response.status == 200U);
                REQUIRE(synced.response.body.find("\"invite\":{\"" + room_id + "\"") != std::string::npos);
                REQUIRE(slid.response.body.find(room_id) != std::string::npos);
            }
        }
    }
}
