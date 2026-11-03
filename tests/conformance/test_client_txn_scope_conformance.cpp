// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for client transaction IDs (client-server-api.md, "Transaction identifiers"): the
// scope of a transaction ID is one device and one endpoint, and a client-chosen ID is bounded.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto txn_config() -> merovingian::config::Config
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

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto member(Reply const& reply, std::string_view key) -> std::string
{
    auto const body = parse_object(reply.body);
    auto const* value = string_member(body, key);
    return value == nullptr ? std::string{} : *value;
}

auto register_user(ClientServerRuntime& rt, std::string const& localpart) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json(localpart, "CorrectHorse7!"))
                .status == 200U);
}

// A login that names its device: a second login with the same device ID is a token refresh of that device.
[[nodiscard]] auto login_device(ClientServerRuntime& rt, std::string const& localpart, std::string const& device)
    -> std::string
{
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                 R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + device + R"("})");
    REQUIRE(login.status == 200U);
    auto token = member(login, "access_token");
    REQUIRE_FALSE(token.empty());
    return token;
}

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, "{}");
    REQUIRE(created.status == 200U);
    auto room_id = member(created, "room_id");
    REQUIRE_FALSE(room_id.empty());
    return room_id;
}

[[nodiscard]] auto send_message(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                std::string const& txn) -> Reply
{
    return call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn, token,
                R"({"msgtype":"m.text","body":"hello"})");
}

[[nodiscard]] auto queued_for(ClientServerRuntime const& rt, std::string_view user, std::string_view device)
    -> std::ptrdiff_t
{
    return std::ranges::count_if(rt.homeserver.database.persistent_store.to_device_messages, [&](auto const& message) {
        return message.target_user_id == user && message.target_device_id == device;
    });
}

} // namespace

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#transaction-identifiers
SCENARIO("A transaction ID on /send is scoped to the device that used it", "[conformance][client-txn][run2][f52]")
{
    GIVEN("alice with two devices and a room")
    {
        auto started = merovingian::homeserver::start_client_server(txn_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        register_user(rt, "alice");
        auto const phone = login_device(rt, "alice", "PHONE");
        auto const laptop = login_device(rt, "alice", "LAPTOP");
        auto const room_id = create_room(rt, phone);

        WHEN("each device sends a message with the same transaction ID")
        {
            auto const from_phone = send_message(rt, phone, room_id, "1");
            auto const from_laptop = send_message(rt, laptop, room_id, "1");

            THEN("both requests create an event: the second is not a retransmission of the first")
            {
                REQUIRE(from_phone.status == 200U);
                REQUIRE(from_laptop.status == 200U);
                auto const first = member(from_phone, "event_id");
                auto const second = member(from_laptop, "event_id");
                REQUIRE_FALSE(first.empty());
                REQUIRE_FALSE(second.empty());
                REQUIRE(first != second);
            }
        }

        WHEN("a device sends again after a token refresh, with the same device ID and transaction ID")
        {
            auto const original = send_message(rt, phone, room_id, "2");
            auto const refreshed_token = login_device(rt, "alice", "PHONE");
            REQUIRE(refreshed_token != phone);
            auto const retransmitted = send_message(rt, refreshed_token, room_id, "2");

            THEN("it is the same request and gets the original event ID")
            {
                REQUIRE(original.status == 200U);
                REQUIRE(retransmitted.status == 200U);
                REQUIRE_FALSE(member(original, "event_id").empty());
                REQUIRE(member(retransmitted, "event_id") == member(original, "event_id"));
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#transaction-identifiers
SCENARIO("A transaction ID on /redact is scoped to the device that used it", "[conformance][client-txn][run2][f52]")
{
    GIVEN("alice with two devices and a message to redact")
    {
        auto started = merovingian::homeserver::start_client_server(txn_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        register_user(rt, "alice");
        auto const phone = login_device(rt, "alice", "PHONE");
        auto const laptop = login_device(rt, "alice", "LAPTOP");
        auto const room_id = create_room(rt, phone);
        auto const target = member(send_message(rt, phone, room_id, "target"), "event_id");
        REQUIRE_FALSE(target.empty());
        auto const redact_path = "/_matrix/client/v3/rooms/" + room_id + "/redact/" + target + "/1";

        WHEN("each device redacts it with the same transaction ID")
        {
            auto const from_phone = call(rt, "PUT", redact_path, phone, "{}");
            auto const from_laptop = call(rt, "PUT", redact_path, laptop, "{}");
            auto const phone_again = call(rt, "PUT", redact_path, phone, "{}");

            THEN("each device's request makes its own redaction, and a repeat from one device is replayed")
            {
                REQUIRE(from_phone.status == 200U);
                REQUIRE(from_laptop.status == 200U);
                REQUIRE_FALSE(member(from_phone, "event_id").empty());
                REQUIRE_FALSE(member(from_laptop, "event_id").empty());
                REQUIRE(member(from_phone, "event_id") != member(from_laptop, "event_id"));
                REQUIRE(member(phone_again, "event_id") == member(from_phone, "event_id"));
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3sendtoeventtypetxnid
SCENARIO("A transaction ID on /sendToDevice is scoped to the device that used it",
         "[conformance][client-txn][to-device][run2][f52]")
{
    GIVEN("alice with two devices and bob with one")
    {
        auto started = merovingian::homeserver::start_client_server(txn_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        register_user(rt, "alice");
        register_user(rt, "bob");
        auto const phone = login_device(rt, "alice", "PHONE");
        auto const laptop = login_device(rt, "alice", "LAPTOP");
        std::ignore = login_device(rt, "bob", "BOBDEV");
        auto const path = std::string{"/_matrix/client/v3/sendToDevice/m.test.message/1"};
        auto const body = std::string{R"({"messages":{"@bob:example.org":{"BOBDEV":{"from":"x"}}}})"};

        WHEN("each of alice's devices sends to bob with the same transaction ID")
        {
            REQUIRE(call(rt, "PUT", path, phone, body).status == 200U);
            REQUIRE(call(rt, "PUT", path, laptop, body).status == 200U);

            THEN("both messages are delivered")
            {
                REQUIRE(queued_for(rt, "@bob:example.org", "BOBDEV") == 2);
            }
        }

        WHEN("one device sends the same request twice")
        {
            REQUIRE(call(rt, "PUT", path, phone, body).status == 200U);
            REQUIRE(call(rt, "PUT", path, phone, body).status == 200U);

            THEN("the second is a retransmission and delivers nothing more")
            {
                REQUIRE(queued_for(rt, "@bob:example.org", "BOBDEV") == 1);
            }
        }
    }
}

// An identifier is at most 255 bytes (appendices.md, "Identifier Grammar"); the server keeps these two
// client-chosen parts as an idempotency key, so it bounds them (F-54, ADR-0381).
SCENARIO("A client transaction ID and event type over 255 bytes are refused on every transaction endpoint",
         "[conformance][client-txn][run2][f54]")
{
    GIVEN("alice with a room and a message")
    {
        auto started = merovingian::homeserver::start_client_server(txn_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        register_user(rt, "alice");
        auto const token = login_device(rt, "alice", "PHONE");
        auto const room_id = create_room(rt, token);
        auto const target = member(send_message(rt, token, room_id, "target"), "event_id");
        REQUIRE_FALSE(target.empty());
        auto const max_part = std::string(255U, 'a');
        auto const long_part = std::string(256U, 'a');
        auto const store_rows_before = rt.homeserver.database.persistent_store.client_txn_ids.size();

        WHEN("the transaction ID is 256 bytes")
        {
            auto const sent =
                call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + long_part, token,
                     R"({"msgtype":"m.text","body":"x"})");
            auto const redacted = call(
                rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/redact/" + target + "/" + long_part, token, "{}");
            auto const to_device = call(rt, "PUT", "/_matrix/client/v3/sendToDevice/m.test.message/" + long_part, token,
                                        R"({"messages":{}})");

            THEN("each endpoint answers 400 M_INVALID_PARAM and records nothing")
            {
                for (auto const* reply : {&sent, &redacted, &to_device})
                {
                    REQUIRE(reply->status == 400U);
                    REQUIRE(member(*reply, "errcode") == "M_INVALID_PARAM");
                }
                REQUIRE(rt.homeserver.database.persistent_store.client_txn_ids.size() == store_rows_before);
            }
        }

        WHEN("the event type is 256 bytes")
        {
            auto const sent = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/" + long_part + "/1",
                                   token, R"({"msgtype":"m.text","body":"x"})");
            auto const to_device =
                call(rt, "PUT", "/_matrix/client/v3/sendToDevice/" + long_part + "/1", token, R"({"messages":{}})");

            THEN("send and sendToDevice answer 400 M_INVALID_PARAM")
            {
                REQUIRE(sent.status == 400U);
                REQUIRE(member(sent, "errcode") == "M_INVALID_PARAM");
                REQUIRE(to_device.status == 400U);
                REQUIRE(member(to_device, "errcode") == "M_INVALID_PARAM");
            }
        }

        WHEN("the transaction ID and the event type are exactly 255 bytes")
        {
            auto const to_device = call(rt, "PUT", "/_matrix/client/v3/sendToDevice/" + max_part + "/" + max_part,
                                        token, R"({"messages":{}})");

            THEN("the request is accepted")
            {
                REQUIRE(to_device.status == 200U);
            }
        }
    }
}
