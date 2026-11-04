// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for PUT /rooms/{roomId}/state/m.room.encryption: `algorithm` is required and
// must be m.megolm.v1.aes-sha2.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto encryption_put_config() -> merovingian::config::Config
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

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json(localpart, "CorrectHorse7!"))
                .status == 200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                 R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_public_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto put_encryption(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                  std::string const& content) -> Reply
{
    return call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.encryption", token, content);
}

[[nodiscard]] auto get_encryption(ClientServerRuntime& rt, std::string const& token, std::string const& room_id)
    -> Reply
{
    return call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.encryption/", token);
}

[[nodiscard]] auto string_field(std::string const& body, std::string_view key) -> std::string
{
    auto const parsed = parse_object(body);
    auto const* value = string_member(parsed, key);
    return value == nullptr ? std::string{} : *value;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey} and m.room.encryption
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#mroomencryption
//
// m.room.encryption: `algorithm` is "**Required: **The encryption algorithm to be used to encrypt
// messages sent in the room. One of: `[m.megolm.v1.aes-sha2]`."
// Common error codes: "`M_BAD_JSON`: Request contained valid JSON, but it was malformed in some way,
// e.g. missing required keys, invalid values for keys."
// The PUT state endpoint answers 400 when "The sender's request is malformed".
SCENARIO("A state event for m.room.encryption without a valid algorithm is refused and changes nothing",
         "[conformance][client-server][encryption-put]")
{
    GIVEN("alice's room that already holds an m.room.encryption event")
    {
        auto started = merovingian::homeserver::start_client_server(encryption_put_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, alice);
        REQUIRE(
            put_encryption(rt, alice, room_id, R"({"algorithm":"m.megolm.v1.aes-sha2","rotation_period_ms":604800000})")
                .status == 200U);
        auto const before = get_encryption(rt, alice, room_id);
        REQUIRE(before.status == 200U);

        auto const refused = [&](std::string const& content) {
            auto const reply = put_encryption(rt, alice, room_id, content);
            // Spec: M_BAD_JSON, "missing required keys, invalid values for keys".
            CHECK(reply.status == 400U);
            CHECK(string_field(reply.body, "errcode") == "M_BAD_JSON");
            auto const after = get_encryption(rt, alice, room_id);
            // A refused PUT cannot turn encryption off or change it: the earlier event is still current.
            CHECK(after.status == 200U);
            CHECK(after.body == before.body);
        };

        WHEN("alice sends an empty content object")
        {
            THEN("it is 400 M_BAD_JSON and the earlier event is unchanged")
            {
                refused("{}");
            }
        }
        WHEN("alice sends an algorithm that is not a string")
        {
            THEN("it is 400 M_BAD_JSON and the earlier event is unchanged")
            {
                refused(R"({"algorithm":42})");
                refused(R"({"algorithm":null})");
                refused(R"({"algorithm":["m.megolm.v1.aes-sha2"]})");
            }
        }
        WHEN("alice sends an empty algorithm")
        {
            THEN("it is 400 M_BAD_JSON and the earlier event is unchanged")
            {
                refused(R"({"algorithm":""})");
            }
        }
        WHEN("alice sends an algorithm the spec does not list")
        {
            THEN("it is 400 M_BAD_JSON and the earlier event is unchanged")
            {
                refused(R"({"algorithm":"m.olm.v1.curve25519-aes-sha2"})");
                refused(R"({"algorithm":"M.MEGOLM.V1.AES-SHA2"})");
                refused(R"({"algorithm":"m.megolm.v1.aes-sha2 "})");
            }
        }
        WHEN("alice sends the listed algorithm")
        {
            auto const reply = put_encryption(rt, alice, room_id, R"({"algorithm":"m.megolm.v1.aes-sha2"})");

            THEN("it is 200 with an event_id")
            {
                REQUIRE(reply.status == 200U);
                CHECK_FALSE(string_field(reply.body, "event_id").empty());
            }
        }
        WHEN("alice sends the listed algorithm with rotation_period_ms and rotation_period_msgs")
        {
            auto const reply = put_encryption(
                rt, alice, room_id,
                R"({"algorithm":"m.megolm.v1.aes-sha2","rotation_period_ms":86400000,"rotation_period_msgs":50})");

            THEN("it is 200 and the extra fields are kept")
            {
                REQUIRE(reply.status == 200U);
                auto const after = get_encryption(rt, alice, room_id);
                REQUIRE(after.status == 200U);
                auto const content = parse_object(after.body);
                CHECK(object_member(content, "rotation_period_ms") != nullptr);
                CHECK(object_member(content, "rotation_period_msgs") != nullptr);
            }
        }
    }
}

// A sender without the power to send the event gets what the send path gives today, whether or not
// the body is valid: the algorithm check is judged only for a sender who may send the event.
SCENARIO("A sender without power over m.room.encryption is refused with 403 whatever the body",
         "[conformance][client-server][encryption-put]")
{
    GIVEN("alice's public room that bob has joined with no power to send state")
    {
        auto started = merovingian::homeserver::start_client_server(encryption_put_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_public_room(rt, alice);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, bob, "{}").status == 200U);

        WHEN("bob sends a valid body")
        {
            auto const reply = put_encryption(rt, bob, room_id, R"({"algorithm":"m.megolm.v1.aes-sha2"})");

            THEN("it is 403 M_FORBIDDEN")
            {
                CHECK(reply.status == 403U);
                CHECK(string_field(reply.body, "errcode") == "M_FORBIDDEN");
            }
        }
        WHEN("bob sends an invalid body")
        {
            auto const reply = put_encryption(rt, bob, room_id, "{}");

            THEN("it is the same 403 M_FORBIDDEN, not a 400")
            {
                CHECK(reply.status == 403U);
                CHECK(string_field(reply.body, "errcode") == "M_FORBIDDEN");
            }
        }
    }
}
