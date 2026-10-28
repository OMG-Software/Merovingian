// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// Regression for Complement run 3 (0.12.59): the /send transaction carrying a locally sent
// event had no `origin` and no `origin_server_ts`, which the Transaction object marks
// Required. A receiver that checks them, this server among them, answered
// `400 transaction origin is required`, so no event sent here ever reached another
// Merovingian server; Synapse tolerated the omission, which hid it.
//
// Spec: Matrix Server-Server API v1.19, PUT /_matrix/federation/v1/send/{txnId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv1sendtxnid

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/membership_fixture_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
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

// A dispatch worker that is never started, so every transaction the server enqueues stays in
// its durable queue (store.federation_transactions) for the test to read.
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

} // namespace

SCENARIO("A locally sent event reaches other servers in a transaction carrying origin and origin_server_ts",
         "[integration][federation][outbound][pdu-transaction]")
{
    GIVEN("alice's room on this server, which bob on another server has joined")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const registration = call(runtime, "POST", "/_matrix/client/v3/register", {},
                                       merovingian::tests::registration_json("alice", "CorrectHorse7!"));
        REQUIRE(registration.response.status == 200U);
        auto const registration_body = parse_object(registration.response.body);
        auto const token = std::string{*string_member(registration_body, "access_token")};
        auto const created =
            call(runtime, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
        REQUIRE(created.response.status == 200U);
        auto const created_body = parse_object(created.response.body);
        auto const room_id = std::string{*string_member(created_body, "room_id")};
        {
            auto const lock = std::lock_guard{runtime.homeserver.mutex};
            auto const room =
                std::ranges::find_if(runtime.homeserver.database.rooms, [&room_id](auto const& candidate) {
                    return candidate.room_id == room_id;
                });
            REQUIRE(room != runtime.homeserver.database.rooms.end());
            room->members.emplace_back("@bob:remote.example.org");
        }

        WHEN("alice sends a message")
        {
            auto const sent = call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t1",
                                   token, R"({"msgtype":"m.text","body":"hello bob"})");
            REQUIRE(sent.response.status == 200U);
            auto const sent_body = parse_object(sent.response.body);
            auto const event_id = std::string{*string_member(sent_body, "event_id")};

            THEN("bob's server is sent a transaction with origin, origin_server_ts and the event")
            {
                auto const lock = std::lock_guard{runtime.homeserver.mutex};
                auto found = false;
                for (auto const& transaction : runtime.homeserver.database.persistent_store.federation_transactions)
                {
                    if (transaction.server_name != remote_server ||
                        transaction.body.find("hello bob") == std::string::npos)
                    {
                        continue;
                    }
                    found = true;
                    auto const parsed = merovingian::canonicaljson::parse_lossless(transaction.body);
                    auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                    REQUIRE(root != nullptr);
                    // Spec MUST: origin is "the server_name of the homeserver sending this transaction".
                    auto const* origin = string_member(*root, "origin");
                    REQUIRE(origin != nullptr);
                    REQUIRE(*origin == runtime.homeserver.config.server().server_name);
                    // Spec MUST: origin_server_ts is an integer.
                    auto const* timestamp = int_member(*root, "origin_server_ts");
                    REQUIRE(timestamp != nullptr);
                    REQUIRE(*timestamp > 0);
                    auto const* pdus = object_member_as_array(*root, "pdus");
                    REQUIRE(pdus != nullptr);
                    REQUIRE(pdus->size() == 1U);
                }
                REQUIRE(found);
                REQUIRE_FALSE(event_id.empty());
            }
        }
    }
}

namespace
{

// The membership of the single PDU in a transaction queued for `server`, for each such
// transaction whose PDU is an m.room.member event about `user_id`.
[[nodiscard]] auto queued_memberships_for(merovingian::homeserver::ClientServerRuntime& runtime,
                                          std::string_view server, std::string_view user_id) -> std::vector<std::string>
{
    auto memberships = std::vector<std::string>{};
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    for (auto const& transaction : runtime.homeserver.database.persistent_store.federation_transactions)
    {
        if (transaction.server_name != server)
        {
            continue;
        }
        auto const parsed = merovingian::canonicaljson::parse_lossless(transaction.body);
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

[[nodiscard]] auto register_user(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& name)
    -> std::string
{
    auto const registration = call(runtime, "POST", "/_matrix/client/v3/register", {},
                                   merovingian::tests::registration_json(name, "CorrectHorse7!"));
    REQUIRE(registration.response.status == 200U);
    auto const body = parse_object(registration.response.body);
    return std::string{*string_member(body, "access_token")};
}

} // namespace

// Spec: Server-Server API v1.19, "Room Events" / Transactions: a server sends the events it
// creates to the other servers in the room. A membership event composed here (a join, a leave,
// a ban) went nowhere: only messages and state sent through /send and /state were fanned out,
// so another server never learnt that one of our users left (Complement
// TestRestrictedRoomsRemoteJoin, "Join should fail when left allowed room"). A ban or kick also
// goes to the target's server, which is no longer among the room's members once it applies.
SCENARIO("A membership event composed here reaches the room's other servers and the target's server",
         "[integration][federation][outbound][membership-fanout]")
{
    GIVEN("alice's public room on this server, which bob on another server has joined")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const alice = register_user(runtime, "alice");
        auto const created =
            call(runtime, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        REQUIRE(created.response.status == 200U);
        auto const created_body = parse_object(created.response.body);
        auto const room_id = std::string{*string_member(created_body, "room_id")};
        auto const bob = std::string{"@bob:"} + std::string{remote_server};
        {
            auto const lock = std::lock_guard{runtime.homeserver.mutex};
            auto const room =
                std::ranges::find_if(runtime.homeserver.database.rooms, [&room_id](auto const& candidate) {
                    return candidate.room_id == room_id;
                });
            REQUIRE(room != runtime.homeserver.database.rooms.end());
            room->members.emplace_back(bob);
        }
        auto const own_server = std::string{runtime.homeserver.config.server().server_name};

        WHEN("carol, a user of this server, joins the room")
        {
            auto const carol = register_user(runtime, "carol");
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + room_id, carol, "{}").response.status == 200U);

            THEN("bob's server is sent carol's join")
            {
                auto const sent = queued_memberships_for(runtime, remote_server, "@carol:" + own_server);
                REQUIRE(std::ranges::find(sent, "join") != sent.end());
            }
        }

        WHEN("alice leaves the room")
        {
            REQUIRE(
                call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", alice, "{}").response.status ==
                200U);

            THEN("bob's server is sent alice's leave")
            {
                auto const sent = queued_memberships_for(runtime, remote_server, "@alice:" + own_server);
                REQUIRE(std::ranges::find(sent, "leave") != sent.end());
            }
        }

        WHEN("alice bans bob")
        {
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", alice,
                         std::string{R"({"user_id":")"} + bob + R"("})")
                        .response.status == 200U);

            THEN("bob's server is sent the ban, though bob is no longer among the room's members")
            {
                auto const sent = queued_memberships_for(runtime, remote_server, bob);
                REQUIRE(std::ranges::find(sent, "ban") != sent.end());
            }
        }
    }
}

namespace
{

constexpr auto joiner_server = std::string_view{"b.example.org"};
constexpr auto bystander_server = std::string_view{"c.example.org"};

// Every PDU queued in a transaction for `server`, as canonical JSON.
[[nodiscard]] auto queued_pdus_for(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view server)
    -> std::vector<std::string>
{
    auto queued = std::vector<std::string>{};
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    for (auto const& transaction : runtime.homeserver.database.persistent_store.federation_transactions)
    {
        if (transaction.server_name != server)
        {
            continue;
        }
        auto const parsed = merovingian::canonicaljson::parse_lossless(transaction.body);
        auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
        auto const* pdus = root == nullptr ? nullptr : object_member_as_array(*root, "pdus");
        if (pdus == nullptr)
        {
            continue;
        }
        for (auto const& pdu : *pdus)
        {
            auto const serialized = merovingian::canonicaljson::serialize_canonical(pdu);
            REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
            queued.push_back(serialized.output);
        }
    }
    return queued;
}

[[nodiscard]] auto canonical_form(std::string const& json) -> std::string
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const serialized = merovingian::canonicaljson::serialize_canonical(parsed.value);
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

// A membership PDU as a conformant peer would file it: it names the room's forward
// extremities and the auth events the spec's selection rules call for.
[[nodiscard]] auto membership_envelope(merovingian::homeserver::ClientServerRuntime& runtime,
                                       std::string const& room_id, std::string const& user_id,
                                       std::string_view membership, std::string const& event_id, std::uint64_t depth)
    -> merovingian::federation::InboundPduEnvelope
{
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    auto const quoted_list = [](std::vector<std::string> const& ids) {
        auto out = std::string{"["};
        for (auto const& id : ids)
        {
            out += (out.size() == 1U ? "" : ",") + std::string{"\""} + id + "\"";
        }
        return out + "]";
    };
    auto const& store = runtime.homeserver.database.persistent_store;
    auto envelope = merovingian::federation::InboundPduEnvelope{};
    envelope.event_id = event_id;
    envelope.room_id = room_id;
    envelope.sender = user_id;
    envelope.event_type = "m.room.member";
    envelope.state_key = user_id;
    envelope.depth = depth;
    envelope.prev_event_ids = merovingian::tests::fixture_prev_event_ids(store, room_id);
    // A room is created at version 12, where the create event is implied by the room ID and
    // must not be named in auth_events.
    envelope.auth_event_ids = merovingian::tests::fixture_auth_event_ids(store, room_id, user_id, true);
    if (membership == "leave")
    {
        // Spec, "Auth events selection": the join rules are selected only for a join, invite or knock.
        for (auto const& entry : store.state)
        {
            if (entry.room_id == room_id && entry.event_type == "m.room.join_rules")
            {
                std::erase(envelope.auth_event_ids, entry.event_id);
            }
        }
    }
    envelope.json = "{\"auth_events\":" + quoted_list(envelope.auth_event_ids) + ",\"content\":{\"membership\":\"" +
                    std::string{membership} + "\"},\"depth\":" + std::to_string(depth) +
                    ",\"origin_server_ts\":1,\"prev_events\":" + quoted_list(envelope.prev_event_ids) +
                    ",\"room_id\":\"" + room_id + "\",\"sender\":\"" + user_id + "\",\"state_key\":\"" + user_id +
                    "\",\"type\":\"m.room.member\"}";
    return envelope;
}

[[nodiscard]] auto accept_membership(merovingian::homeserver::ClientServerRuntime& runtime,
                                     merovingian::federation::FederationEndpoint endpoint,
                                     merovingian::federation::InboundPduEnvelope const& envelope)
    -> merovingian::federation::MembershipAcceptResult
{
    REQUIRE(runtime.homeserver.federation.membership_acceptor);
    return runtime.homeserver.federation.membership_acceptor(endpoint, envelope.room_id, envelope.event_id, envelope);
}

struct FanoutRoom final
{
    std::string room_id{};
    std::string alice_token{};
    std::string bob{};
    std::string carol{};
};

// alice's room on this server in which carol, of the bystander server C, is already joined.
[[nodiscard]] auto make_fanout_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view preset)
    -> FanoutRoom
{
    auto room = FanoutRoom{};
    install_unstarted_dispatch_worker(runtime);
    merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
    room.alice_token = register_user(runtime, "alice");
    auto const created = call(runtime, "POST", "/_matrix/client/v3/createRoom", room.alice_token,
                              std::string{R"({"preset":")"} + std::string{preset} + R"("})");
    REQUIRE(created.response.status == 200U);
    room.room_id = std::string{*string_member(parse_object(created.response.body), "room_id")};
    room.bob = "@bob:" + std::string{joiner_server};
    room.carol = "@carol:" + std::string{bystander_server};
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    auto const found = std::ranges::find_if(runtime.homeserver.database.rooms, [&room](auto const& candidate) {
        return candidate.room_id == room.room_id;
    });
    REQUIRE(found != runtime.homeserver.database.rooms.end());
    found->members.emplace_back(room.carol);
    return room;
}

} // namespace

// Spec: Server-Server API v1.19, "Joining Rooms": "The resident server must also send the event
// to other servers participating in the room." "Leaving Rooms (Rejecting Invites)": "The
// resident server will then send the event to other servers in the room." The Knocking section
// states no such sentence, but a knock is a room event like the others (Server-Server API,
// "Transactions"), so the servers in the room must be told of it too. The requesting server
// already has the event, so it is not sent it back.
SCENARIO("A membership event accepted for a requesting server is sent on to the room's other servers",
         "[integration][federation][outbound][membership-acceptor-fanout]")
{
    using merovingian::federation::FederationEndpoint;

    GIVEN("alice's public room on this server, in which carol of server C is joined")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = make_fanout_room(runtime, "public_chat");

        WHEN("server B's send_join for bob is accepted")
        {
            auto const joined = accept_membership(runtime, FederationEndpoint::send_join,
                                                  membership_envelope(runtime, room.room_id, room.bob, "join",
                                                                      "$bob_join:" + std::string{joiner_server}, 10U));
            REQUIRE(joined.accepted);

            THEN("server C is sent the stored copy of the join, and server B is sent nothing")
            {
                auto const sent = queued_pdus_for(runtime, bystander_server);
                REQUIRE_FALSE(joined.signed_event_json.empty());
                REQUIRE(std::ranges::find(sent, canonical_form(joined.signed_event_json)) != sent.end());
                auto const memberships = queued_memberships_for(runtime, bystander_server, room.bob);
                REQUIRE(std::ranges::find(memberships, "join") != memberships.end());
                REQUIRE(queued_pdus_for(runtime, joiner_server).empty());
            }
        }

        WHEN("server B's send_leave for bob, who had joined, is accepted")
        {
            REQUIRE(accept_membership(runtime, FederationEndpoint::send_join,
                                      membership_envelope(runtime, room.room_id, room.bob, "join",
                                                          "$bob_join:" + std::string{joiner_server}, 10U))
                        .accepted);
            auto const left = accept_membership(runtime, FederationEndpoint::send_leave,
                                                membership_envelope(runtime, room.room_id, room.bob, "leave",
                                                                    "$bob_leave:" + std::string{joiner_server}, 11U));
            REQUIRE(left.accepted);

            THEN("server C is sent the stored copy of the leave, and server B is sent nothing")
            {
                auto const sent = queued_pdus_for(runtime, bystander_server);
                REQUIRE(std::ranges::find(sent, canonical_form(left.signed_event_json)) != sent.end());
                auto const memberships = queued_memberships_for(runtime, bystander_server, room.bob);
                REQUIRE(std::ranges::find(memberships, "leave") != memberships.end());
                REQUIRE(queued_pdus_for(runtime, joiner_server).empty());
            }
        }
    }

    GIVEN("alice's room on this server that allows knocking, in which carol of server C is joined")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = make_fanout_room(runtime, "public_chat");
        REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room.room_id + "/state/m.room.join_rules/",
                     room.alice_token, R"({"join_rule":"knock"})")
                    .response.status == 200U);

        WHEN("server B's send_knock for bob is accepted")
        {
            auto const knocked =
                accept_membership(runtime, FederationEndpoint::send_knock,
                                  membership_envelope(runtime, room.room_id, room.bob, "knock",
                                                      "$bob_knock:" + std::string{joiner_server}, 10U));
            REQUIRE(knocked.accepted);

            THEN("server C is sent the stored copy of the knock, and server B is sent nothing")
            {
                auto const sent = queued_pdus_for(runtime, bystander_server);
                REQUIRE(std::ranges::find(sent, canonical_form(knocked.signed_event_json)) != sent.end());
                auto const memberships = queued_memberships_for(runtime, bystander_server, room.bob);
                REQUIRE(std::ranges::find(memberships, "knock") != memberships.end());
                REQUIRE(queued_pdus_for(runtime, joiner_server).empty());
            }
        }
    }

    GIVEN("alice's invite-only room on this server, in which carol of server C is joined")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = make_fanout_room(runtime, "private_chat");

        WHEN("server B's send_join for bob, who was never invited, is refused")
        {
            auto const refused = accept_membership(runtime, FederationEndpoint::send_join,
                                                   membership_envelope(runtime, room.room_id, room.bob, "join",
                                                                       "$bob_join:" + std::string{joiner_server}, 10U));
            REQUIRE_FALSE(refused.accepted);

            THEN("no server is sent the event")
            {
                REQUIRE(queued_pdus_for(runtime, bystander_server).empty());
                REQUIRE(queued_pdus_for(runtime, joiner_server).empty());
            }
        }
    }
}
