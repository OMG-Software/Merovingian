// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// Complement run 10: invites and their stripped room state over federation.
//
// Spec: Matrix Server-Server API v1.19, "Inviting to a room", "Knocking upon a room" and
// "Leaving Rooms (Rejecting Invites)".
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#inviting-to-a-room

#include "../federation_signing_test_support.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/membership_fixture_support.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

using namespace merovingian::tests;

namespace
{

constexpr auto remote_server = std::string_view{"remote.example.org"};

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
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

// A dispatch worker that is never started, so every transaction the server enqueues stays in its
// durable queue (store.federation_transactions) for the test to read.
auto install_unstarted_dispatch_worker(merovingian::homeserver::ClientServerRuntime& runtime) -> void
{
    REQUIRE(runtime.homeserver.outbound_client != nullptr);
    auto config = merovingian::federation::DispatchWorkerConfig{};
    config.origin = runtime.homeserver.config.server().server_name;
    config.key_id = "ed25519:test";
    runtime.homeserver.dispatch_worker = std::make_unique<merovingian::federation::DispatchWorker>(
        std::move(config), *runtime.homeserver.outbound_client,
        [](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        },
        merovingian::federation::DispatchClock{}, merovingian::federation::DispatchSleep{},
        &runtime.homeserver.database.persistent_store);
}

[[nodiscard]] auto call(merovingian::homeserver::ClientServerRuntime& runtime, std::string method, std::string target,
                        std::string const& token, std::string body = {}) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {std::move(method), std::move(target), token, std::move(body)});
}

[[nodiscard]] auto register_user(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& name)
    -> std::string
{
    auto const registration = call(runtime, "POST", "/_matrix/client/v3/register", {},
                                   merovingian::tests::registration_json(name, "CorrectHorse7!"));
    REQUIRE(registration.response.status == 200U);
    auto const body = parse_object(registration.response.body);
    return std::string{*string_member(body, "access_token")};
}

[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                               std::string const& body) -> std::string
{
    auto const created = call(runtime, "POST", "/_matrix/client/v3/createRoom", token, body);
    REQUIRE(created.response.status == 200U);
    return std::string{*string_member(parse_object(created.response.body), "room_id")};
}

auto add_roster_member(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& room_id,
                       std::string const& user_id) -> void
{
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    auto const room = std::ranges::find_if(runtime.homeserver.database.rooms, [&room_id](auto const& candidate) {
        return candidate.room_id == room_id;
    });
    REQUIRE(room != runtime.homeserver.database.rooms.end());
    room->members.emplace_back(user_id);
}

// The bodies of the transactions queued for `server` whose target contains `target_part`.
[[nodiscard]] auto queued_bodies(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view server,
                                 std::string_view target_part) -> std::vector<std::string>
{
    auto bodies = std::vector<std::string>{};
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    for (auto const& transaction : runtime.homeserver.database.persistent_store.federation_transactions)
    {
        if (transaction.server_name == server && transaction.target.find(target_part) != std::string::npos)
        {
            bodies.push_back(transaction.body);
        }
    }
    return bodies;
}

// The membership of each PDU, in a transaction queued for `server`, that is an m.room.member event
// for `user_id`.
[[nodiscard]] auto queued_memberships_for(merovingian::homeserver::ClientServerRuntime& runtime,
                                          std::string_view server, std::string_view user_id) -> std::vector<std::string>
{
    auto memberships = std::vector<std::string>{};
    for (auto const& body : queued_bodies(runtime, server, "/send/"))
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(body);
        auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
        auto const* pdus = root == nullptr ? nullptr : object_member_as_array(*root, "pdus");
        if (pdus == nullptr)
        {
            continue;
        }
        for (auto const& pdu : *pdus)
        {
            auto const* event = std::get_if<merovingian::canonicaljson::Object>(&pdu.storage());
            auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
            auto const* state_key = event == nullptr ? nullptr : string_member(*event, "state_key");
            auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
            auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
            if (type != nullptr && *type == "m.room.member" && state_key != nullptr && *state_key == user_id &&
                membership != nullptr)
            {
                memberships.emplace_back(*membership);
            }
        }
    }
    return memberships;
}

// The invite_room_state entries of the first /v2/invite queued for `server`, as parsed objects.
struct QueuedInvite final
{
    bool found{false};
    std::vector<merovingian::canonicaljson::Value> room_state{};
};

[[nodiscard]] auto queued_invite_for(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view server)
    -> QueuedInvite
{
    auto invite = QueuedInvite{};
    auto const bodies = queued_bodies(runtime, server, "/v2/invite/");
    if (bodies.empty())
    {
        return invite;
    }
    invite.found = true;
    auto const parsed = merovingian::canonicaljson::parse_lossless(bodies.front());
    auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(root != nullptr);
    auto const* state = object_member_as_array(*root, "invite_room_state");
    REQUIRE(state != nullptr);
    for (auto const& entry : *state)
    {
        invite.room_state.push_back(entry);
    }
    return invite;
}

// True when `entries` holds a full signed PDU of `type`: hashes and signatures, and no stripped
// shortcut such as `unsigned`.
[[nodiscard]] auto holds_signed_pdu(std::vector<merovingian::canonicaljson::Value> const& entries,
                                    std::string_view type) -> bool
{
    return std::ranges::any_of(entries, [&](merovingian::canonicaljson::Value const& entry) {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        if (event == nullptr)
        {
            return false;
        }
        auto const* entry_type = string_member(*event, "type");
        return entry_type != nullptr && *entry_type == type && object_member(*event, "hashes") != nullptr &&
               object_member(*event, "signatures") != nullptr && object_member(*event, "depth") != nullptr &&
               object_member(*event, "unsigned") == nullptr;
    });
}

} // namespace

// Spec: Matrix Server-Server API v1.19, PUT /v2/invite/{roomId}/{eventId}: "invite_room_state ... MUST
// contain the `m.room.create` event for the room. All events listed MUST additionally be formatted
// according to the room version specification." Changed in v1.16. Both ways a client invites a remote
// user (the invite endpoint, and createRoom's `invite` list) send it.
SCENARIO("An invite sent to another server carries the room's stripped state as signed PDUs",
         "[integration][federation][invite][invite-room-state][outbound-invite]")
{
    GIVEN("alice's named room on this server and a user of another server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const alice = register_user(runtime, "alice");
        auto const bob = std::string{"@bob:"} + std::string{remote_server};

        WHEN("alice invites the remote user with POST /invite")
        {
            auto const room_id = create_room(runtime, alice, R"({"preset":"private_chat","name":"Stripped"})");
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                         std::string{R"({"user_id":")"} + bob + R"("})")
                        .response.status == 200U);
            auto const invite = queued_invite_for(runtime, remote_server);

            THEN("the invite names the create event and the other stripped-state types as full signed PDUs")
            {
                REQUIRE(invite.found);
                // Spec MUST: invite_room_state contains m.room.create, formatted as the room version's PDU.
                REQUIRE(holds_signed_pdu(invite.room_state, "m.room.create"));
                REQUIRE(holds_signed_pdu(invite.room_state, "m.room.join_rules"));
                REQUIRE(holds_signed_pdu(invite.room_state, "m.room.name"));
            }
        }

        WHEN("alice creates a room with the remote user in its invite list")
        {
            std::ignore =
                create_room(runtime, alice,
                            std::string{R"({"preset":"private_chat","name":"Stripped","invite":[")"} + bob + R"("]})");
            auto const invite = queued_invite_for(runtime, remote_server);

            THEN("that invite carries the create event as a full signed PDU too")
            {
                REQUIRE(invite.found);
                // Spec MUST: invite_room_state contains m.room.create, formatted as the room version's PDU.
                REQUIRE(holds_signed_pdu(invite.room_state, "m.room.create"));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Room Events": a server sends the events it creates to every
// server in the room. An invite for a user of THIS server is a room event like any other, so a room's
// other servers learn of it (Complement TestFederationRejectInvite).
SCENARIO("An invite for a local user is sent to the room's other servers",
         "[integration][federation][invite][local-invite-fanout]")
{
    GIVEN("alice's room on this server, which bob of another server has joined")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const alice = register_user(runtime, "alice");
        std::ignore = register_user(runtime, "charlie");
        auto const room_id = create_room(runtime, alice, R"({"preset":"private_chat"})");
        auto const bob = std::string{"@bob:"} + std::string{remote_server};
        add_roster_member(runtime, room_id, bob);
        auto const own_server = std::string{runtime.homeserver.config.server().server_name};

        WHEN("alice invites charlie, who is also a user of this server")
        {
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                         std::string{R"({"user_id":"@charlie:)"} + own_server + R"("})")
                        .response.status == 200U);

            THEN("bob's server is sent the invite")
            {
                auto const sent = queued_memberships_for(runtime, remote_server, "@charlie:" + own_server);
                REQUIRE(std::ranges::find(sent, "invite") != sent.end());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Leaving Rooms (Rejecting Invites)" and "Room Events": the
// kick that rescinds an invite is an event of the room. The invitee's server is not among the room's
// joined servers, so it is sent it explicitly. Complement TestFederationRoomsInvite, "Inviter user can
// rescind invite over federation".
SCENARIO("Rescinding an invite to a remote user sends the kick to the invitee's server",
         "[integration][federation][invite][rescind-invite]")
{
    GIVEN("alice's room on this server, to which she has invited a user of another server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const alice = register_user(runtime, "alice");
        auto const room_id = create_room(runtime, alice, R"({"preset":"private_chat"})");
        auto const bob = std::string{"@bob:"} + std::string{remote_server};
        REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                     std::string{R"({"user_id":")"} + bob + R"("})")
                    .response.status == 200U);

        WHEN("alice kicks the invited user")
        {
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/kick", alice,
                         std::string{R"({"user_id":")"} + bob + R"("})")
                        .response.status == 200U);

            THEN("the invitee's server is sent the leave, though it never joined")
            {
                auto const sent = queued_memberships_for(runtime, remote_server, bob);
                REQUIRE(std::ranges::find(sent, "leave") != sent.end());
            }
        }
    }
}

namespace
{

constexpr auto inviting_server = std::string_view{"inviter.example.org"};
// A version 12 room ID: a bare reference hash, no server name to fall back on (MSC4291).
constexpr auto bare_room_id = std::string_view{"!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};
constexpr auto bare_room_id_encoded = std::string_view{"%21AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};

// A local user, alice, holding a pending invite to a room on another server from one of its users.
struct InvitedUser final
{
    std::string token{};
    std::string user_id{};
    std::string room_id{};
};

[[nodiscard]] auto invited_user(merovingian::homeserver::ClientServerRuntime& runtime) -> InvitedUser
{
    auto invited = InvitedUser{};
    invited.token = register_user(runtime, "alice");
    invited.user_id = "@alice:" + std::string{runtime.homeserver.config.server().server_name};
    invited.room_id = std::string{bare_room_id};
    auto const inviter = "@inviter:" + std::string{inviting_server};
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    REQUIRE(merovingian::database::store_membership_projection(
        runtime.homeserver.database.persistent_store, invited.room_id,
        {
            invited.user_id, "invite", 1000U,
            merovingian::database::PersistentInvite{
                                                    invited.room_id, invited.user_id, inviter, "$invite", "{}", {}, 1000U}
    }));
    return invited;
}

[[nodiscard]] auto membership_of(merovingian::homeserver::ClientServerRuntime& runtime, InvitedUser const& user)
    -> std::string
{
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    for (auto const& membership : runtime.homeserver.database.persistent_store.memberships)
    {
        if (membership.room_id == user.room_id && membership.user_id == user.user_id)
        {
            return membership.membership;
        }
    }
    return {};
}

[[nodiscard]] auto invite_record_exists(merovingian::homeserver::ClientServerRuntime& runtime, InvitedUser const& user)
    -> bool
{
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    return merovingian::database::find_invite(runtime.homeserver.database.persistent_store, user.room_id, user.user_id)
        .has_value();
}

// The inviting server, as a loopback TLS peer this server's federation client is pointed at.
struct InvitingServer final
{
    merovingian::tests::tls_mock::TlsTestCertificate certificate{
        merovingian::tests::tls_mock::write_test_tls_certificate()};
    merovingian::homeserver::TlsServerContextResult tls{
        merovingian::homeserver::make_tls_server_context(certificate.certificate_file, certificate.private_key_file)};
    merovingian::net::TcpAcceptor acceptor{};

    explicit InvitingServer(merovingian::homeserver::ClientServerRuntime& runtime)
    {
        REQUIRE(tls.ok());
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        REQUIRE(acceptor.bound_port() > 0U);
        runtime.homeserver.test_forced_outbound_resolution[std::string{inviting_server}] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
    }
};

[[nodiscard]] auto make_leave_template(InvitedUser const& user) -> std::string
{
    return std::string{R"({"room_version":"12","event":{"type":"m.room.member","state_key":")"} + user.user_id +
           R"(","room_id":")" + user.room_id + R"(","sender":")" + user.user_id +
           R"(","depth":6,"origin_server_ts":1100,"prev_events":[],"auth_events":[],)"
           R"("content":{"membership":"leave"}}})";
}

} // namespace

// Spec: Matrix Server-Server API v1.19, "Leaving Rooms (Rejecting Invites)": "Remote invites/knocks from
// other homeservers do not involve the server in the graph and therefore need another approach to reject
// the invite." The leaving server sends /make_leave to a resident server (which "may be the server which
// sent the invite"), signs the template and sends it with /send_leave. A version 12 room ID names no
// server, so the inviter is the only one to ask. Complement TestFederationRejectInvite.
SCENARIO("Rejecting an invite from another server goes through make_leave and send_leave to the inviter",
         "[integration][federation][invite][reject-invite]")
{
    GIVEN("alice, who holds an invite from a user of another server to a version 12 room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = invited_user(runtime);
        auto inviter = InvitingServer{runtime};
        auto const leave_target = "/_matrix/client/v3/rooms/" + std::string{bare_room_id_encoded} + "/leave";

        WHEN("alice rejects the invite and the inviting server accepts the leave")
        {
            auto captured = std::vector<std::string>{};
            auto server = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                    inviter.acceptor, *inviter.tls.context,
                    {
                        {"/make_leave/",
                         merovingian::tests::tls_mock::json_http_response("200 OK",                 make_leave_template(alice))},
                        {"/send_leave/", merovingian::tests::tls_mock::json_http_response("200 OK", "{}")                      }
                },
                    &captured);
            }};
            auto const left = call(runtime, "POST", leave_target, alice.token, "{}");
            server.join();

            THEN("the leave went to the inviting server and alice is no longer invited")
            {
                CAPTURE(left.response.body);
                // Spec MUST: the invite is rejected with make_leave then send_leave to a resident server.
                REQUIRE(left.response.status == 200);
                REQUIRE(captured.size() == 2U);
                REQUIRE(captured[0].find("/_matrix/federation/v1/make_leave/") != std::string::npos);
                REQUIRE(captured[1].find("/_matrix/federation/v2/send_leave/") != std::string::npos);
                REQUIRE(membership_of(runtime, alice) == "leave");
                REQUIRE_FALSE(invite_record_exists(runtime, alice));
            }
        }

        WHEN("alice rejects the invite after the inviter left the room, so its server answers make_leave with 404")
        {
            auto captured = std::vector<std::string>{};
            auto server = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                    inviter.acceptor, *inviter.tls.context,
                    {
                        {"/make_leave/", merovingian::tests::tls_mock::json_http_response(
                                             "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"Unknown room"})")}
                },
                    &captured);
            }};
            auto const left = call(runtime, "POST", leave_target, alice.token, "{}");
            server.join();

            THEN("the invite is dropped from alice's records, and no event is sent")
            {
                CAPTURE(left.response.body);
                // The spec defines no other route for rejecting a remote invite, so the invite is
                // withdrawn locally rather than left to stay on alice's client for ever.
                REQUIRE(left.response.status == 200);
                REQUIRE(captured.size() == 1U);
                REQUIRE(membership_of(runtime, alice) == "leave");
                REQUIRE_FALSE(invite_record_exists(runtime, alice));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Joining Rooms": the joining server asks a resident server for a
// join template, and "the resident server may be the server which sent the invite". A client that
// accepts an invite sends POST /join/{roomId} with no server named (Complement
// TestFederationRoomsInvite), and a version 12 room ID has no domain to fall back on.
SCENARIO("Joining a room with no server named uses the server that sent the pending invite",
         "[integration][federation][invite][join-after-invite]")
{
    GIVEN("alice, who holds an invite from a user of another server to a version 12 room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = invited_user(runtime);
        auto inviter = InvitingServer{runtime};

        WHEN("alice joins the room naming no server")
        {
            auto captured = std::vector<std::string>{};
            auto server = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                    inviter.acceptor, *inviter.tls.context,
                    {
                        {"/make_join/", merovingian::tests::tls_mock::json_http_response(
                                            "403 Forbidden", R"({"errcode":"M_FORBIDDEN","error":"No"})")}
                },
                    &captured);
            }};
            auto const joined = call(runtime, "POST", "/_matrix/client/v3/join/" + std::string{bare_room_id_encoded},
                                     alice.token, "{}");
            server.join();

            THEN("the inviting server is asked for a join template")
            {
                CAPTURE(joined.response.body);
                // Spec MAY: the server that sent the invite is a candidate resident server.
                REQUIRE(captured.size() == 1U);
                REQUIRE(captured[0].find("/_matrix/federation/v1/make_join/") != std::string::npos);
                REQUIRE(joined.response.status != 404);
            }
        }
    }

    GIVEN("alice, who holds no invite to a version 12 room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");

        WHEN("alice joins the room naming no server")
        {
            auto const joined =
                call(runtime, "POST", "/_matrix/client/v3/join/" + std::string{bare_room_id_encoded}, alice, "{}");

            THEN("there is no server to ask and the room is unknown")
            {
                REQUIRE(joined.response.status == 404);
            }
        }
    }
}

namespace
{

[[nodiscard]] auto quoted_list(std::vector<std::string> const& ids) -> std::string
{
    auto out = std::string{"["};
    for (auto const& id : ids)
    {
        out += (out.size() == 1U ? "" : ",") + std::string{"\""} + id + "\"";
    }
    return out + "]";
}

[[nodiscard]] auto current_state_event_id(merovingian::database::PersistentStore const& store,
                                          std::string const& room_id, std::string_view type, std::string_view state_key)
    -> std::optional<std::string>
{
    for (auto const& entry : store.state)
    {
        if (entry.room_id == room_id && entry.event_type == type && entry.state_key == state_key)
        {
            return entry.event_id;
        }
    }
    return std::nullopt;
}

// An m.room.member PDU `sender` sends about `target`, as a conformant resident server would: it names the
// room's forward extremities and the auth events the spec's selection rules call for (power levels, the
// sender's and the target's current membership; the create event is implied in version 12).
[[nodiscard]] auto member_envelope(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& room_id,
                                   std::string const& sender, std::string const& target, std::string_view membership,
                                   std::string const& event_id, std::uint64_t depth)
    -> merovingian::federation::InboundPduEnvelope
{
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    auto const& store = runtime.homeserver.database.persistent_store;
    auto envelope = merovingian::federation::InboundPduEnvelope{};
    envelope.event_id = event_id;
    envelope.room_id = room_id;
    envelope.sender = sender;
    envelope.event_type = "m.room.member";
    envelope.state_key = target;
    envelope.depth = depth;
    envelope.origin = std::string{remote_server};
    envelope.prev_event_ids = merovingian::tests::fixture_prev_event_ids(store, room_id);
    // Spec "Auth events selection": the join rules are selected only for a join, invite or knock.
    auto const wants_join_rules = membership == "join" || membership == "invite" || membership == "knock";
    for (auto const& [type, key] : {
             std::pair<std::string_view, std::string_view>{"m.room.power_levels",                                          ""    },
             {"m.room.member",                                                sender},
             {"m.room.member",                                                target},
             {wants_join_rules ? "m.room.join_rules" : "m.room.power_levels", ""    }
    })
    {
        if (auto const id = current_state_event_id(store, room_id, type, key);
            id.has_value() && std::ranges::find(envelope.auth_event_ids, *id) == envelope.auth_event_ids.end())
        {
            envelope.auth_event_ids.push_back(*id);
        }
    }
    envelope.json = "{\"auth_events\":" + quoted_list(envelope.auth_event_ids) + ",\"content\":{\"membership\":\"" +
                    std::string{membership} + "\"},\"depth\":" + std::to_string(depth) +
                    ",\"origin_server_ts\":1,\"prev_events\":" + quoted_list(envelope.prev_event_ids) +
                    ",\"room_id\":\"" + room_id + "\",\"sender\":\"" + sender + "\",\"state_key\":\"" + target +
                    "\",\"type\":\"m.room.member\"}";
    return envelope;
}

[[nodiscard]] auto membership_row(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& room_id,
                                  std::string const& user_id) -> std::string
{
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    for (auto const& membership : runtime.homeserver.database.persistent_store.memberships)
    {
        if (membership.room_id == room_id && membership.user_id == user_id)
        {
            return membership.membership;
        }
    }
    return {};
}

[[nodiscard]] auto sync_invites_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                     std::string const& room_id) -> bool
{
    auto const synced = call(runtime, "GET", "/_matrix/client/v3/sync", token);
    REQUIRE(synced.response.status == 200);
    auto const body = parse_object(synced.response.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* invite = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "invite");
    return invite != nullptr && object_member_as_object(*invite, room_id) != nullptr;
}

} // namespace

// Spec: Matrix Server-Server API v1.19, "Inviting to a room": the invite is accepted unless the invitee is
// banned, and a ban is lifted by an unban (a leave) sent by a user with power to ban. The unban is a PDU
// about a user of this server, which this server was sent as the target (spec, "Transactions"), even
// though the ban left it with no user joined to the room. Complement TestUnbanViaInvite.
SCENARIO("A local user banned from a remote room can be invited again once unbanned",
         "[integration][federation][invite][unban-invite]")
{
    GIVEN("a room whose only admin is on another server, from which that admin has banned carol of this server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const alice = register_user(runtime, "alice");
        auto const carol = register_user(runtime, "carol");
        auto const own_server = std::string{runtime.homeserver.config.server().server_name};
        auto const carol_id = "@carol:" + own_server;
        auto const bob = std::string{"@bob:"} + std::string{remote_server};
        auto const room_id = create_room(
            runtime, alice,
            std::string{R"({"preset":"public_chat","power_level_content_override":{"users":{")"} + bob + R"(":100}}})");
        REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + room_id, carol, "{}").response.status == 200U);
        auto const bob_joined = runtime.homeserver.federation.membership_acceptor(
            merovingian::federation::FederationEndpoint::send_join, room_id, "$bob_join:remote.example.org",
            member_envelope(runtime, room_id, bob, bob, "join", "$bob_join:" + std::string{remote_server}, 10U));
        CAPTURE(bob_joined.reason);
        REQUIRE(bob_joined.accepted);
        REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", alice, "{}").response.status ==
                200U);
        auto const banned = runtime.homeserver.federation.pdu_sink(
            member_envelope(runtime, room_id, bob, carol_id, "ban", "$ban:" + std::string{remote_server}, 11U));
        REQUIRE(banned.status == merovingian::federation::PduIngestionStatus::accepted);
        REQUIRE(membership_row(runtime, room_id, carol_id) == "ban");

        WHEN("the unban arrives in a transaction, and the admin then invites carol again")
        {
            auto const unbanned = runtime.homeserver.federation.pdu_sink(
                member_envelope(runtime, room_id, bob, carol_id, "leave", "$unban:" + std::string{remote_server}, 12U));
            auto invite = merovingian::federation::InviteRequest{};
            invite.room_id = room_id;
            invite.event_id = "$invite:" + std::string{remote_server};
            invite.room_version = "12";
            invite.origin = std::string{remote_server};
            invite.invite_event_json =
                member_envelope(runtime, room_id, bob, carol_id, "invite", invite.event_id, 13U).json;
            auto const invited = runtime.homeserver.federation.invite_handler(invite);

            THEN("the unban was applied, the invite is accepted, and carol's sync shows the invite")
            {
                CAPTURE(unbanned.reason, invited.reason);
                // Spec: an unban is the target's membership becoming leave.
                REQUIRE(unbanned.status == merovingian::federation::PduIngestionStatus::accepted);
                REQUIRE(invited.accepted);
                REQUIRE(membership_row(runtime, room_id, carol_id) == "invite");
                REQUIRE(sync_invites_room(runtime, carol, room_id));
            }
        }

        WHEN("an invite arrives while the ban still stands")
        {
            auto invite = merovingian::federation::InviteRequest{};
            invite.room_id = room_id;
            invite.event_id = "$invite:" + std::string{remote_server};
            invite.room_version = "12";
            invite.origin = std::string{remote_server};
            invite.invite_event_json =
                member_envelope(runtime, room_id, bob, carol_id, "invite", invite.event_id, 12U).json;
            auto const invited = runtime.homeserver.federation.invite_handler(invite);

            THEN("it is refused and the ban is kept")
            {
                // Spec: a banned user cannot be invited ("target user's current membership state is ban").
                REQUIRE_FALSE(invited.accepted);
                REQUIRE(membership_row(runtime, room_id, carol_id) == "ban");
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Leaving Rooms (Rejecting Invites)" and "Transactions": the
// inviter's kick of a user who has not joined is sent to the invitee's server, which holds nothing of
// the room but the invite. The inviter's server is the one that can withdraw it. Complement
// TestFederationRoomsInvite, "Inviter user can rescind invite over federation".
SCENARIO("An invite withdrawn by the server that sent it is rescinded for the invited user",
         "[integration][federation][invite][rescind-invite][inbound-rescind]")
{
    GIVEN("carol of this server, invited to a room on another server whose state this server does not hold")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const carol = register_user(runtime, "carol");
        auto const carol_id = "@carol:" + std::string{runtime.homeserver.config.server().server_name};
        auto const bob = std::string{"@bob:"} + std::string{remote_server};
        auto const room_id = std::string{bare_room_id};
        auto invite = merovingian::federation::InviteRequest{};
        invite.room_id = room_id;
        invite.event_id = "$invite:" + std::string{remote_server};
        invite.room_version = "12";
        invite.origin = std::string{remote_server};
        invite.invite_event_json =
            R"({"auth_events":[],"content":{"membership":"invite"},"depth":3,"origin_server_ts":1,"prev_events":[],)"
            R"("room_id":")" +
            room_id + R"(","sender":")" + bob + R"(","state_key":")" + carol_id + R"(","type":"m.room.member"})";
        REQUIRE(runtime.homeserver.federation.invite_handler(invite).accepted);
        REQUIRE(sync_invites_room(runtime, carol, room_id));

        WHEN("the inviter's server sends the leave that withdraws the invite")
        {
            auto envelope = merovingian::federation::InboundPduEnvelope{};
            envelope.event_id = "$rescind:" + std::string{remote_server};
            envelope.room_id = room_id;
            envelope.sender = bob;
            envelope.event_type = "m.room.member";
            envelope.state_key = carol_id;
            envelope.depth = 4U;
            envelope.origin = std::string{remote_server};
            envelope.room_version = "12";
            envelope.prev_event_ids = {invite.event_id};
            envelope.json = R"({"auth_events":[],"content":{"membership":"leave"},"depth":4,"origin_server_ts":2,)"
                            R"("prev_events":[")" +
                            invite.event_id + R"("],"room_id":")" + room_id + R"(","sender":")" + bob +
                            R"(","state_key":")" + carol_id + R"(","type":"m.room.member"})";
            auto const result = runtime.homeserver.federation.pdu_sink(envelope);

            THEN("carol is no longer invited")
            {
                CAPTURE(result.reason);
                // Spec: a kick of an invited user makes their membership leave.
                REQUIRE(membership_row(runtime, room_id, carol_id) == "leave");
                REQUIRE_FALSE(sync_invites_room(runtime, carol, room_id));
            }
        }

        WHEN("a different server, which did not invite carol, sends a leave for her")
        {
            auto envelope = merovingian::federation::InboundPduEnvelope{};
            envelope.event_id = "$rescind:other.example.org";
            envelope.room_id = room_id;
            envelope.sender = "@mallory:other.example.org";
            envelope.event_type = "m.room.member";
            envelope.state_key = carol_id;
            envelope.depth = 4U;
            envelope.origin = "other.example.org";
            envelope.room_version = "12";
            envelope.prev_event_ids = {invite.event_id};
            envelope.json = R"({"auth_events":[],"content":{"membership":"leave"},"depth":4,"origin_server_ts":2,)"
                            R"("prev_events":[")" +
                            invite.event_id + R"("],"room_id":")" + room_id +
                            R"(","sender":"@mallory:other.example.org","state_key":")" + carol_id +
                            R"(","type":"m.room.member"})";
            std::ignore = runtime.homeserver.federation.pdu_sink(envelope);

            THEN("carol's invite stands")
            {
                REQUIRE(membership_row(runtime, room_id, carol_id) == "invite");
                REQUIRE(sync_invites_room(runtime, carol, room_id));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, PUT /v1/send_knock: `knock_room_state` is "Required" and "MUST
// contain the `m.room.create` event for the room. All events listed MUST additionally be formatted
// according to the room version specification." Changed in v1.16. As the resident, this server fills
// it from the room's current state.
SCENARIO("A knock accepted by this server answers with the room's stripped state as signed PDUs",
         "[integration][federation][knock][knock-room-state]")
{
    GIVEN("alice's named room on this server, which allows knocking")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const alice = register_user(runtime, "alice");
        auto const room_id = create_room(runtime, alice, R"({"preset":"public_chat","name":"Knock Here"})");
        REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.join_rules/", alice,
                     R"({"join_rule":"knock"})")
                    .response.status == 200U);
        auto const bob = std::string{"@bob:"} + std::string{remote_server};

        WHEN("a server's send_knock for bob is accepted")
        {
            auto const knocked = runtime.homeserver.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_knock, room_id, "$bob_knock:remote.example.org",
                member_envelope(runtime, room_id, bob, bob, "knock", "$bob_knock:" + std::string{remote_server}, 10U));

            THEN("the answer's knock_room_state holds the create event and the name as signed PDUs")
            {
                CAPTURE(knocked.reason);
                REQUIRE(knocked.accepted);
                auto entries = std::vector<merovingian::canonicaljson::Value>{};
                for (auto const& entry_json : knocked.knock_room_state_json)
                {
                    auto const parsed = merovingian::canonicaljson::parse_lossless(entry_json);
                    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                    entries.push_back(parsed.value);
                }
                // Spec MUST: knock_room_state contains m.room.create, formatted as the room version's PDU.
                REQUIRE(holds_signed_pdu(entries, "m.room.create"));
                REQUIRE(holds_signed_pdu(entries, "m.room.name"));
                REQUIRE(holds_signed_pdu(entries, "m.room.join_rules"));
            }
        }
    }
}

// Spec: Client-Server API v1.19, "Stripped state" and GET /sync `invite_state`: the invitee's client is
// shown stripped state events (content, sender, state_key, type), not the full PDUs a server-server
// invite carries since v1.16.
SCENARIO("An invited user's sync shows the invite's room state stripped, whatever form it arrived in",
         "[integration][federation][invite][invite-room-state][invite-state-sync]")
{
    GIVEN("carol of this server, invited by another server with the room's create event as a full signed PDU")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const carol = register_user(runtime, "carol");
        auto const carol_id = "@carol:" + std::string{runtime.homeserver.config.server().server_name};
        auto const bob = std::string{"@bob:"} + std::string{remote_server};
        auto const room_id = std::string{bare_room_id};
        auto invite = merovingian::federation::InviteRequest{};
        invite.room_id = room_id;
        invite.event_id = "$invite:" + std::string{remote_server};
        invite.room_version = "12";
        invite.origin = std::string{remote_server};
        invite.invite_event_json =
            R"({"auth_events":[],"content":{"membership":"invite"},"depth":3,"origin_server_ts":1,"prev_events":[],)"
            R"("room_id":")" +
            room_id + R"(","sender":")" + bob + R"(","state_key":")" + carol_id + R"(","type":"m.room.member"})";
        invite.invite_room_state_json = {
            R"({"auth_events":[],"content":{"room_version":"12"},"depth":1,"hashes":{"sha256":"AAAA"},)"
            R"("origin_server_ts":1,"prev_events":[],"sender":")" +
            bob + R"(","signatures":{")" + std::string{remote_server} + R"(":{"ed25519:auto":"AAAA"}},)" +
            R"("state_key":"","type":"m.room.create"})"};
        REQUIRE(runtime.homeserver.federation.invite_handler(invite).accepted);

        WHEN("carol syncs")
        {
            auto const synced = call(runtime, "GET", "/_matrix/client/v3/sync", carol);

            THEN("the create event appears with only its client-visible properties")
            {
                REQUIRE(synced.response.status == 200);
                auto const body = parse_object(synced.response.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                auto const* invites = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "invite");
                auto const* room = invites == nullptr ? nullptr : object_member_as_object(*invites, room_id);
                auto const* state = room == nullptr ? nullptr : object_member_as_object(*room, "invite_state");
                auto const* events = state == nullptr ? nullptr : object_member_as_array(*state, "events");
                REQUIRE(events != nullptr);
                auto found_create = false;
                for (auto const& entry : *events)
                {
                    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
                    REQUIRE(event != nullptr);
                    auto const* type = string_member(*event, "type");
                    if (type != nullptr && *type == "m.room.create")
                    {
                        found_create = true;
                        // Spec: stripped state events have content, sender, state_key and type only.
                        REQUIRE(event->size() == 4U);
                        REQUIRE(object_member(*event, "hashes") == nullptr);
                        REQUIRE(object_member(*event, "signatures") == nullptr);
                    }
                }
                REQUIRE(found_create);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Room Events" / "Joining Rooms": a server that accepted a remote
// user's send_join sends every later event of the room to that user's server. The invite for a local
// user is one of them (Complement TestFederationRejectInvite), as is the leave that rejects it.
SCENARIO("After a remote user joins through send_join, a local user's invite and rejection reach that user's server",
         "[integration][federation][invite][local-invite-fanout][local-invite-after-send-join]")
{
    GIVEN("alice's room on this server, which bob of another server joined through send_join")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const alice = register_user(runtime, "alice");
        auto const charlie = register_user(runtime, "charlie");
        auto const own_server = std::string{runtime.homeserver.config.server().server_name};
        auto const charlie_id = "@charlie:" + own_server;
        auto const room_id = create_room(runtime, alice, R"({"preset":"private_chat"})");
        auto const bob = std::string{"@bob:"} + std::string{remote_server};
        REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                     std::string{R"({"user_id":")"} + bob + R"("})")
                    .response.status == 200U);
        auto const bob_joined = runtime.homeserver.federation.membership_acceptor(
            merovingian::federation::FederationEndpoint::send_join, room_id, "$bob_join:remote.example.org",
            member_envelope(runtime, room_id, bob, bob, "join", "$bob_join:" + std::string{remote_server}, 10U));
        CAPTURE(bob_joined.reason);
        REQUIRE(bob_joined.accepted);

        WHEN("alice invites charlie, a user of this server, and charlie rejects the invite")
        {
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                         std::string{R"({"user_id":")"} + charlie_id + R"("})")
                        .response.status == 200U);
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", charlie, "{}")
                        .response.status == 200U);

            THEN("bob's server is sent the invite and then the leave")
            {
                auto const sent = queued_memberships_for(runtime, remote_server, charlie_id);
                REQUIRE(std::ranges::find(sent, "invite") != sent.end());
                REQUIRE(std::ranges::find(sent, "leave") != sent.end());
            }
        }
    }
}

namespace
{

// The invited user's server, as a loopback TLS peer. `answer` is the whole HTTP response it gives to
// PUT /v2/invite.
struct InviteeServer final
{
    InvitingServer peer;
    std::vector<std::string> captured{};
    std::thread thread{};

    InviteeServer(merovingian::homeserver::ClientServerRuntime& runtime, std::string answer)
        : peer{runtime}
    {
        thread = std::thread{[this, answer = std::move(answer)]() {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(peer.acceptor, *peer.tls.context,
                                                                       {
                                                                           {"/v2/invite/", answer}
            },
                                                                       &captured);
        }};
    }
    ~InviteeServer()
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }
    InviteeServer(InviteeServer const&) = delete;
    auto operator=(InviteeServer const&) -> InviteeServer& = delete;
    InviteeServer(InviteeServer&&) = delete;
    auto operator=(InviteeServer&&) -> InviteeServer& = delete;
};

[[nodiscard]] auto accepting_answer() -> std::string
{
    return merovingian::tests::tls_mock::json_http_response("200 OK", R"({"event":{}})");
}

} // namespace

// Spec: Matrix Server-Server API v1.19, "Inviting to a room": "when a user invites another user on a
// different homeserver, a request to that homeserver to have the event signed and verified must be made",
// and "Once the event has been signed by both the inviting homeserver and the invited homeserver, it can
// be sent to all of the servers in the room". Complement TestFederationRejectInvite: the room's other
// server must not see an invite its invitee's server has not yet got.
SCENARIO("An invite to a user of another server is offered to that server before the room's servers or the client "
         "hear of it",
         "[integration][federation][invite][remote-invite-handshake]")
{
    GIVEN("alice's room on this server, which delia of a third server has joined, and bob of another server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const alice = register_user(runtime, "alice");
        auto const room_id = create_room(runtime, alice, R"({"preset":"private_chat"})");
        auto const delia = std::string{"@delia:"} + std::string{remote_server};
        add_roster_member(runtime, room_id, delia);
        auto const bob = std::string{"@bob:"} + std::string{inviting_server};
        auto const invite_target = "/_matrix/client/v3/rooms/" + room_id + "/invite";
        auto const invite_body = std::string{R"({"user_id":")"} + bob + R"("})";

        WHEN("alice invites bob and bob's server accepts the invite")
        {
            auto invitee = InviteeServer{runtime, accepting_answer()};
            auto const invited = call(runtime, "POST", invite_target, alice, invite_body);
            invitee.thread.join();

            THEN("bob's server was asked before alice was answered, and delia's server hears of the invite")
            {
                CAPTURE(invited.response.body);
                REQUIRE(invited.response.status == 200U);
                REQUIRE(invitee.captured.size() == 1U);
                REQUIRE(invitee.captured[0].find("/_matrix/federation/v2/invite/") != std::string::npos);
                REQUIRE(membership_row(runtime, room_id, bob) == "invite");
                auto const sent = queued_memberships_for(runtime, remote_server, bob);
                REQUIRE(std::ranges::find(sent, "invite") != sent.end());
                // Nothing is left for the queue to retry: the server has been told.
                REQUIRE(queued_bodies(runtime, inviting_server, "/v2/invite/").empty());
            }
        }

        WHEN("alice invites bob and bob's server refuses the invite")
        {
            auto invitee = InviteeServer{runtime, merovingian::tests::tls_mock::json_http_response(
                                                      "403 Forbidden", R"({"errcode":"M_FORBIDDEN","error":"No"})")};
            auto const invited = call(runtime, "POST", invite_target, alice, invite_body);
            invitee.thread.join();

            THEN("alice is refused, no invite is stored, and delia's server is told nothing")
            {
                CAPTURE(invited.response.body);
                REQUIRE(invited.response.status == 403U);
                REQUIRE(membership_row(runtime, room_id, bob).empty());
                REQUIRE(queued_memberships_for(runtime, remote_server, bob).empty());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Inviting to a room", for the invites of a createRoom request.
// Complement TestFederationRoomsInvite, "Invited user has 'is_direct' flag in prev_content after joining":
// the invitee joins as soon as createRoom has answered, with no server named.
SCENARIO("A createRoom invite to a user of another server reaches that server before createRoom answers",
         "[integration][federation][invite][remote-invite-handshake][create-room-invite]")
{
    GIVEN("alice and bob, a user of another server whose server accepts invites")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const alice = register_user(runtime, "alice");
        auto const bob = std::string{"@bob:"} + std::string{inviting_server};

        WHEN("alice creates a room with bob in its invite list")
        {
            auto invitee = InviteeServer{runtime, accepting_answer()};
            std::ignore =
                create_room(runtime, alice, std::string{R"({"preset":"private_chat","invite":[")"} + bob + R"("]})");
            invitee.thread.join();

            THEN("bob's server had been asked by the time createRoom answered, and nothing is queued for it")
            {
                REQUIRE(invitee.captured.size() == 1U);
                REQUIRE(invitee.captured[0].find("/_matrix/federation/v2/invite/") != std::string::npos);
                REQUIRE(queued_bodies(runtime, inviting_server, "/v2/invite/").empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, GET /sync: `rooms.leave` is "the rooms that the user has left or
// been banned from", and an incremental sync reports a leave that happened after `since`. Rejecting an
// invite is such a leave. Complement TestFederationRoomsInvite, "Invited user can reject invite over
// federation for empty room".
SCENARIO("A rejected remote invite appears under rooms.leave of the next incremental sync",
         "[integration][federation][invite][reject-invite][reject-invite-sync]")
{
    GIVEN("alice, who holds an invite from a user of another server, and a sync that showed it")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = invited_user(runtime);
        auto inviter = InvitingServer{runtime};
        auto const first = call(runtime, "GET", "/_matrix/client/v3/sync", alice.token);
        REQUIRE(first.response.status == 200U);
        auto const since = std::string{*string_member(parse_object(first.response.body), "next_batch")};

        WHEN("alice rejects the invite and the inviting server accepts the leave")
        {
            auto server = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                    inviter.acceptor, *inviter.tls.context,
                    {
                        {"/make_leave/",
                         merovingian::tests::tls_mock::json_http_response("200 OK",                 make_leave_template(alice))},
                        {"/send_leave/", merovingian::tests::tls_mock::json_http_response("200 OK", "{}")                      }
                });
            }};
            auto const left =
                call(runtime, "POST", "/_matrix/client/v3/rooms/" + std::string{bare_room_id_encoded} + "/leave",
                     alice.token, "{}");
            server.join();
            REQUIRE(left.response.status == 200U);
            auto const next = call(runtime, "GET", "/_matrix/client/v3/sync?since=" + since, alice.token);

            THEN("the next sync lists the room under rooms.leave")
            {
                REQUIRE(next.response.status == 200U);
                auto const body = parse_object(next.response.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                auto const* leave = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "leave");
                REQUIRE(leave != nullptr);
                auto const* left_room = object_member_as_object(*leave, alice.room_id);
                REQUIRE(left_room != nullptr);
                // The client learns it left from a member event for itself with membership "leave", in
                // the timeline or the state; the invite that preceded it does not say so.
                auto reports_leave = false;
                for (auto const section : {"state", "timeline"})
                {
                    auto const* part = object_member_as_object(*left_room, section);
                    auto const* events = part == nullptr ? nullptr : object_member_as_array(*part, "events");
                    for (auto const& entry : events == nullptr ? merovingian::canonicaljson::Array{} : *events)
                    {
                        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
                        auto const* state_key = event == nullptr ? nullptr : string_member(*event, "state_key");
                        auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
                        auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
                        reports_leave = reports_leave || (state_key != nullptr && *state_key == alice.user_id &&
                                                          membership != nullptr && *membership == "leave");
                    }
                }
                REQUIRE(reports_leave);
            }
        }
    }
}
