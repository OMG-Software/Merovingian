// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for CSAZ-9: events this server composes for its own clients are held to the
// spec's size limits, so a client cannot make this server sign a PDU every other server rejects.
//
// Spec: Matrix Client-Server API v1.19, "Size limits"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#size-limits
//
// Spec MUST: "The complete event MUST NOT be larger than 65536 bytes, when formatted with the
// federation event format, including any signatures, and encoded as Canonical JSON."
// Spec MUST: "`state_key` MUST NOT exceed 255 bytes." and "`type` MUST NOT exceed 255 bytes."
// Spec (Standard error response): `M_TOO_LARGE` "The request or entity was too large."

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto size_limit_config() -> merovingian::config::Config
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

[[nodiscard]] auto errcode_of(Reply const& reply) -> std::string
{
    auto const body = parse_object(reply.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
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

[[nodiscard]] auto user_id(std::string const& localpart) -> std::string
{
    return "@" + localpart + ":example.org";
}

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

// A message body of `length` bytes that starts with `marker`, so a read path can be searched for it.
[[nodiscard]] auto marked_text(std::string_view marker, std::size_t length) -> std::string
{
    auto text = std::string{marker};
    text.append(length - marker.size(), 'x');
    return text;
}

[[nodiscard]] auto timeline_contains(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                     std::string_view needle) -> bool
{
    auto const messages = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=100", token);
    REQUIRE(messages.status == 200U);
    return messages.body.find(needle) != std::string::npos;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}; "Size limits"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#size-limits
//
// The 65 536-byte limit applies to the complete signed event, so a request body under the limit can
// still compose an event over it once room_id, sender, prev_events, auth_events, hashes and
// signatures are added.
SCENARIO("A locally composed event over 65536 bytes is refused with M_TOO_LARGE and not stored",
         "[conformance][client-server][size-limits][csaz-9]")
{
    GIVEN("a user joined to a room they created")
    {
        auto started = merovingian::homeserver::start_client_server(size_limit_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);

        WHEN("they send a message whose request body is under 65536 bytes but whose signed event is over it")
        {
            auto const text = marked_text("csaz9-oversize-", 65'400U);
            auto const body = std::string{R"({"msgtype":"m.text","body":")"} + text + R"("})";
            REQUIRE(body.size() < 65'536U);
            auto const reply =
                call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/csaz9-big", token, body);

            THEN("the server answers 400 M_TOO_LARGE")
            {
                // Spec MUST: "The complete event MUST NOT be larger than 65536 bytes".
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
            }
            THEN("no event was stored in the room")
            {
                REQUIRE_FALSE(timeline_contains(rt, token, room_id, "csaz9-oversize-"));
            }
        }

        WHEN("they send a message comfortably under the limit")
        {
            auto const text = marked_text("csaz9-fits-", 60'000U);
            auto const body = std::string{R"({"msgtype":"m.text","body":")"} + text + R"("})";
            auto const reply =
                call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/csaz9-fits", token, body);

            THEN("it is accepted and stored")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(timeline_contains(rt, token, room_id, "csaz9-fits-"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}; "Size limits"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#size-limits
SCENARIO("A state event whose state_key exceeds 255 bytes is refused with M_TOO_LARGE",
         "[conformance][client-server][size-limits][csaz-9]")
{
    GIVEN("a room creator, who holds the state_default power level")
    {
        auto started = merovingian::homeserver::start_client_server(size_limit_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);

        WHEN("they put a state event with a 256-byte state_key")
        {
            auto const state_key = std::string(256U, 'k');
            auto const reply =
                call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/org.example.k/" + state_key, token,
                     R"({"v":1})");

            THEN("the server answers 400 M_TOO_LARGE and the state is not set")
            {
                // Spec MUST: "`state_key` MUST NOT exceed 255 bytes."
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
                REQUIRE(
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/org.example.k/" + state_key, token)
                        .status == 404U);
            }
        }

        WHEN("they put a state event with a 255-byte state_key")
        {
            auto const state_key = std::string(255U, 'k');
            auto const reply =
                call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/org.example.k/" + state_key, token,
                     R"({"v":1})");

            THEN("it is accepted and readable")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/org.example.k/" + state_key, token)
                        .status == 200U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}; "Size limits"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#size-limits
SCENARIO("An event whose type exceeds 255 bytes is refused with M_TOO_LARGE",
         "[conformance][client-server][size-limits][csaz-9]")
{
    GIVEN("a user joined to a room they created")
    {
        auto started = merovingian::homeserver::start_client_server(size_limit_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);

        WHEN("they send an event with a 256-byte type")
        {
            auto const type = "org.example." + std::string(256U - 12U, 't');
            REQUIRE(type.size() == 256U);
            auto const reply = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/" + type + "/csaz9-t",
                                    token, R"({"marker":"csaz9-longtype"})");

            THEN("the server answers 400 M_TOO_LARGE and nothing is stored")
            {
                // Spec MUST: "`type` MUST NOT exceed 255 bytes."
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
                REQUIRE_FALSE(timeline_contains(rt, token, room_id, "csaz9-longtype"));
            }
        }

        WHEN("they send an event with a 255-byte type")
        {
            auto const type = "org.example." + std::string(255U - 12U, 't');
            REQUIRE(type.size() == 255U);
            auto const reply = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/" + type + "/csaz9-u",
                                    token, R"({"marker":"csaz9-maxtype"})");

            THEN("it is accepted and stored")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(timeline_contains(rt, token, room_id, "csaz9-maxtype"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/rooms/{roomId}/kick; "Size limits"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#size-limits
//
// The membership endpoints compose an m.room.member event carrying the client's `reason`, so they
// are held to the same limit as /send.
SCENARIO("A kick whose reason makes the member event exceed 65536 bytes is refused with M_TOO_LARGE",
         "[conformance][client-server][size-limits][csaz-9]")
{
    GIVEN("a room creator and a second joined member")
    {
        auto started = merovingian::homeserver::start_client_server(size_limit_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}").status == 200U);

        WHEN("the creator kicks bob with a 66000-byte reason")
        {
            auto const reason = std::string(66'000U, 'r');
            auto const reply = call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/kick", alice,
                                    R"({"user_id":")" + user_id("bob") + R"(","reason":")" + reason + R"("})");

            THEN("the server answers 400 M_TOO_LARGE and bob is still joined")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
                auto const member = call(
                    rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.member/" + user_id("bob"), alice);
                REQUIRE(member.status == 200U);
                auto const content = parse_object(member.body);
                auto const* membership = string_member(content, "membership");
                REQUIRE(membership != nullptr);
                REQUIRE(*membership == "join");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/createRoom; "Size limits"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#size-limits
SCENARIO("createRoom with a topic too large for one event is refused with M_TOO_LARGE and creates no room",
         "[conformance][client-server][size-limits][csaz-9]")
{
    GIVEN("a registered user in no rooms")
    {
        auto started = merovingian::homeserver::start_client_server(size_limit_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");

        WHEN("they create a room with a 70000-byte topic")
        {
            auto const topic = std::string(70'000U, 'o');
            auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token,
                                    R"({"preset":"public_chat","topic":")" + topic + R"("})");

            THEN("the server answers 400 M_TOO_LARGE and the user has joined no room")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
                auto const joined = call(rt, "GET", "/_matrix/client/v3/joined_rooms", token);
                REQUIRE(joined.status == 200U);
                REQUIRE(joined.body.find("\"joined_rooms\":[]") != std::string::npos);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/createRoom; "Size limits"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#size-limits
//
// Every piece of client content createRoom turns into an event is held to the limits, and a refused
// request creates no room.
SCENARIO("createRoom refuses each kind of oversized client content before creating a room",
         "[conformance][client-server][size-limits][csaz-9]")
{
    GIVEN("a registered user in no rooms")
    {
        auto started = merovingian::homeserver::start_client_server(size_limit_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const big = std::string(70'000U, 'z');
        auto const long_key = std::string(256U, 'k');
        auto const long_type = "org.example." + std::string(256U - 12U, 't');

        auto const refused_without_room = [&](std::string const& body) {
            auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);
            REQUIRE(reply.status == 400U);
            REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
            auto const joined = call(rt, "GET", "/_matrix/client/v3/joined_rooms", token);
            REQUIRE(joined.body.find("\"joined_rooms\":[]") != std::string::npos);
        };

        WHEN("the name is too large")
        {
            THEN("it is refused")
            {
                refused_without_room(R"({"name":")" + big + R"("})");
            }
        }
        WHEN("creation_content is too large")
        {
            THEN("it is refused")
            {
                refused_without_room(R"({"creation_content":{"x":")" + big + R"("}})");
            }
        }
        WHEN("power_level_content_override is too large")
        {
            THEN("it is refused")
            {
                refused_without_room(R"({"power_level_content_override":{"x":")" + big + R"("}})");
            }
        }
        WHEN("an initial_state event is too large, or its type or state_key is over 255 bytes")
        {
            THEN("each is refused")
            {
                refused_without_room(R"({"initial_state":[{"type":"org.example.big","state_key":"","content":{"x":")" +
                                     big + R"("}}]})");
                refused_without_room(R"({"initial_state":[{"type":")" + long_type +
                                     R"(","state_key":"","content":{}}]})");
                refused_without_room(R"({"initial_state":[{"type":"org.example.k","state_key":")" + long_key +
                                     R"(","content":{}}]})");
            }
        }
        WHEN("an initial_state event's state_key is exactly 255 bytes")
        {
            auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token,
                                    R"({"initial_state":[{"type":"org.example.k","state_key":")" +
                                        std::string(255U, 'k') + R"(","content":{}}]})");

            THEN("the room is created")
            {
                REQUIRE(reply.status == 200U);
            }
        }
    }
}
