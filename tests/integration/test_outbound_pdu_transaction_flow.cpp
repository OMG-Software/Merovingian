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
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/homeserver/client_server.hpp"

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
