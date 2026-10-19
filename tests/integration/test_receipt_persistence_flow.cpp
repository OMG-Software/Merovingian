// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Read receipts are the user's read-up-to position in a room: unread counts and the receipts a
// client is sent are both computed from them. They are kept in the database so that a server
// restart neither marks every room unread again nor loses what other members have read.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto sqlite_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();

    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() / ("merovingian-receipts-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto request(merovingian::homeserver::ClientServerRuntime& runtime, std::string method,
                           std::string target, std::string token, std::string body)
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {std::move(method), std::move(target), std::move(token), std::move(body)})
        .response;
}

[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view localpart)
    -> std::string
{
    REQUIRE(request(runtime, "POST", "/_matrix/client/v3/register", {},
                    merovingian::tests::registration_json(localpart, "CorrectHorse7!"))
                .status == 200U);
    auto const login =
        request(runtime, "POST", "/_matrix/client/v3/login", {},
                std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} +
                    std::string{localpart} + R"(:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto string_field(std::string const& body, std::string_view key) -> std::string
{
    auto const object = parse_object(body);
    auto const* value = string_member(object, key);
    REQUIRE(value != nullptr);
    return *value;
}

// The room's entry in rooms.join of an initial /sync by `token`.
[[nodiscard]] auto synced_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                               std::string const& room_id) -> merovingian::canonicaljson::Object
{
    auto const sync = request(runtime, "GET", "/_matrix/client/v3/sync", token, {});
    REQUIRE(sync.status == 200U);
    auto const body = parse_object(sync.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* join = object_member_as_object(*rooms, "join");
    REQUIRE(join != nullptr);
    auto const* room = object_member_as_object(*join, room_id);
    REQUIRE(room != nullptr);
    return *room;
}

[[nodiscard]] auto notification_count(merovingian::canonicaljson::Object const& room) -> std::int64_t
{
    auto const* unread = object_member_as_object(room, "unread_notifications");
    REQUIRE(unread != nullptr);
    auto const* count = int_member(*unread, "notification_count");
    REQUIRE(count != nullptr);
    return *count;
}

// The receipt `user_id` holds of `receipt_type` on `event_id` in the room's m.receipt
// ephemeral events, or nullptr.
[[nodiscard]] auto find_receipt(merovingian::canonicaljson::Object const& room, std::string const& event_id,
                                std::string_view receipt_type, std::string const& user_id)
    -> merovingian::canonicaljson::Object const*
{
    auto const* ephemeral = object_member_as_object(room, "ephemeral");
    auto const* events = ephemeral == nullptr ? nullptr : object_member_as_array(*ephemeral, "events");
    if (events == nullptr)
    {
        return nullptr;
    }
    for (auto const& value : *events)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
        if (type == nullptr || *type != "m.receipt")
        {
            continue;
        }
        auto const* content = object_member_as_object(*event, "content");
        auto const* by_type = content == nullptr ? nullptr : object_member_as_object(*content, event_id);
        auto const* users = by_type == nullptr ? nullptr : object_member_as_object(*by_type, receipt_type);
        auto const* receipt = users == nullptr ? nullptr : object_member_as_object(*users, user_id);
        if (receipt != nullptr)
        {
            return receipt;
        }
    }
    return nullptr;
}

} // namespace

SCENARIO("read receipts survive a server restart", "[receipt][receipt-persistence][restart][sqlite]")
{
    GIVEN("a SQLite-backed server where Alice has read every message Bob sent her")
    {
        auto const path = unique_sqlite_path();
        auto const config = sqlite_config(path);
        auto alice = std::string{};
        auto bob = std::string{};
        auto room_id = std::string{};
        auto root_id = std::string{};
        auto thread_reply_id = std::string{};
        auto latest_id = std::string{};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            alice = logged_in_token(started.runtime, "alice");
            bob = logged_in_token(started.runtime, "bob");
            room_id = string_field(
                request(started.runtime, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})")
                    .body,
                "room_id");
            REQUIRE(request(started.runtime, "POST", "/_matrix/client/v3/join/" + room_id, bob, "{}").status == 200U);
            root_id = string_field(request(started.runtime, "PUT",
                                           "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t1", bob,
                                           R"({"msgtype":"m.text","body":"root"})")
                                       .body,
                                   "event_id");
            thread_reply_id = string_field(
                request(started.runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t2", bob,
                        R"({"msgtype":"m.text","body":"reply","m.relates_to":{"rel_type":"m.thread","event_id":")" +
                            root_id + R"("}})")
                    .body,
                "event_id");
            latest_id = string_field(request(started.runtime, "PUT",
                                             "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t3", bob,
                                             R"({"msgtype":"m.text","body":"latest"})")
                                         .body,
                                     "event_id");

            REQUIRE(request(started.runtime, "POST",
                            "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/" + latest_id, alice,
                            R"({"thread_id":"main"})")
                        .status == 200U);
            REQUIRE(request(started.runtime, "POST",
                            "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read.private/" + thread_reply_id, alice,
                            R"({"thread_id":")" + root_id + R"("})")
                        .status == 200U);
            REQUIRE(notification_count(synced_room(started.runtime, alice, room_id)) == 0);
        }

        WHEN("the server restarts and Alice's client syncs from scratch")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto const alice_room = synced_room(restarted.runtime, alice, room_id);
            auto const bob_room = synced_room(restarted.runtime, bob, room_id);

            THEN("the room is still read")
            {
                REQUIRE(notification_count(alice_room) == 0);
            }
            THEN("Alice is sent both of her receipts with their thread IDs")
            {
                auto const* main_receipt = find_receipt(alice_room, latest_id, "m.read", "@alice:example.org");
                REQUIRE(main_receipt != nullptr);
                auto const* main_thread = string_member(*main_receipt, "thread_id");
                REQUIRE(main_thread != nullptr);
                REQUIRE(*main_thread == "main");
                auto const* thread_receipt =
                    find_receipt(alice_room, thread_reply_id, "m.read.private", "@alice:example.org");
                REQUIRE(thread_receipt != nullptr);
                auto const* thread_id = string_member(*thread_receipt, "thread_id");
                REQUIRE(thread_id != nullptr);
                REQUIRE(*thread_id == root_id);
            }
            THEN("Bob still sees Alice's public receipt and not her private one")
            {
                REQUIRE(find_receipt(bob_room, latest_id, "m.read", "@alice:example.org") != nullptr);
                REQUIRE(find_receipt(bob_room, thread_reply_id, "m.read.private", "@alice:example.org") == nullptr);
            }
        }

        WHEN("Alice moves her receipt and the server restarts")
        {
            {
                auto running = merovingian::homeserver::start_client_server(config);
                REQUIRE(running.started);
                REQUIRE(request(running.runtime, "POST",
                                "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/" + root_id, alice,
                                R"({"thread_id":"main"})")
                            .status == 200U);
            }
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto const alice_room = synced_room(restarted.runtime, alice, room_id);

            THEN("the receipt is where she last put it, not where it first was")
            {
                REQUIRE(find_receipt(alice_room, root_id, "m.read", "@alice:example.org") != nullptr);
                REQUIRE(find_receipt(alice_room, latest_id, "m.read", "@alice:example.org") == nullptr);
                REQUIRE(notification_count(alice_room) == 1);
            }
        }
        std::filesystem::remove(path);
    }
}
