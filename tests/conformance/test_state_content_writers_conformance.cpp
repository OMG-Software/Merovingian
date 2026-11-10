// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"

// F-19 (security audit run 4): the content checks of m.room.canonical_alias and m.room.encryption apply to every local
// writer of those state events, not only PUT /state: the POST /rooms/{roomId}/send form that names a `state_key`, and
// createRoom `initial_state`.
//
// Spec: Matrix Client-Server API v1.19, "PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",
// "m.room.canonical_alias", "m.room.encryption" and "POST /_matrix/client/v3/createRoom".
// ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto make_config() -> merovingian::config::Config
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

[[nodiscard]] auto string_field(std::string const& body, std::string_view key) -> std::string
{
    auto const parsed = parse_object(body);
    auto const* value = string_member(parsed, key);
    return value == nullptr ? std::string{} : *value;
}

[[nodiscard]] auto create_public_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    REQUIRE(reply.status == 200U);
    return string_field(reply.body, "room_id");
}

[[nodiscard]] auto create_alias(ClientServerRuntime& rt, std::string const& token, std::string const& localpart,
                                std::string const& room_id) -> Reply
{
    return call(rt, "PUT", "/_matrix/client/v3/directory/room/%23" + localpart + "%3Aexample.org", token,
                R"({"room_id":")" + room_id + R"("})");
}

// POST /rooms/{roomId}/send with a body-typed event: the form that accepts a `state_key`.
[[nodiscard]] auto post_send(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                             std::string const& event_type, std::string const& state_key_member,
                             std::string const& content) -> Reply
{
    return call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token,
                R"({"type":")" + event_type + R"(",)" + state_key_member + R"("content":)" + content + "}");
}

[[nodiscard]] auto state_of(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                            std::string const& event_type) -> Reply
{
    return call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/" + event_type, token);
}

[[nodiscard]] auto create_room_with(ClientServerRuntime& rt, std::string const& token, std::string const& body) -> Reply
{
    return call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);
}

constexpr auto empty_key = R"("state_key":"",)";

} // namespace

// Spec: "If the event type being sent is `m.room.canonical_alias` servers SHOULD ensure that any added aliases being
// listed in the event are valid per their grammar/syntax and that they point to the room ID where the state event is
// to be sent." 400 `M_INVALID_PARAM` for syntax, `M_BAD_ALIAS` for an alias that does not point to the room.
SCENARIO("POST /send with a state_key judges m.room.canonical_alias as PUT /state does",
         "[conformance][client-server][canonical-alias][f19]")
{
    GIVEN("alice's room with the alias #here, and another room of hers with #elsewhere")
    {
        auto started = merovingian::homeserver::start_client_server(make_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, alice);
        auto const other_room_id = create_public_room(rt, alice);
        REQUIRE(create_alias(rt, alice, "here", room_id).status == 200U);
        REQUIRE(create_alias(rt, alice, "elsewhere", other_room_id).status == 200U);

        WHEN("she sends the event with a state_key and an alias that is not a room alias")
        {
            auto const reply =
                post_send(rt, alice, room_id, "m.room.canonical_alias", empty_key, R"({"alias":"not an alias"})");

            THEN("it is 400 M_INVALID_PARAM and nothing is stored")
            {
                // Spec SHOULD: added aliases are valid per their syntax.
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_INVALID_PARAM");
                REQUIRE(state_of(rt, alice, room_id, "m.room.canonical_alias").status == 404U);
            }
        }

        WHEN("she sends the event with an alias that points at her other room")
        {
            auto const reply = post_send(rt, alice, room_id, "m.room.canonical_alias", empty_key,
                                         R"({"alias":"#elsewhere:example.org"})");

            THEN("it is 400 M_BAD_ALIAS and nothing is stored")
            {
                // Spec SHOULD: added aliases point to the room the event is sent to.
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_BAD_ALIAS");
                REQUIRE(state_of(rt, alice, room_id, "m.room.canonical_alias").status == 404U);
            }
        }

        WHEN("she sends the event with an alias of this room")
        {
            auto const reply =
                post_send(rt, alice, room_id, "m.room.canonical_alias", empty_key, R"({"alias":"#here:example.org"})");

            THEN("it is accepted and stored")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(state_of(rt, alice, room_id, "m.room.canonical_alias").status == 200U);
            }
        }

        WHEN("she sends a message event of that type, with no state_key, and a bad alias")
        {
            auto const reply =
                post_send(rt, alice, room_id, "m.room.canonical_alias", "", R"({"alias":"not an alias"})");

            THEN("it is not judged as a state event")
            {
                // Only a state event is a canonical alias; a message of the type has no state to corrupt.
                REQUIRE(reply.status == 200U);
                REQUIRE(state_of(rt, alice, room_id, "m.room.canonical_alias").status == 404U);
            }
        }

        WHEN("a member without the power to send the event sends a bad alias")
        {
            auto const bob = register_and_login(rt, "bob");
            REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, bob, "{}").status == 200U);
            auto const reply =
                post_send(rt, bob, room_id, "m.room.canonical_alias", empty_key, R"({"alias":"not an alias"})");

            THEN("the answer is the 403 of the authorization rules, not a content error")
            {
                REQUIRE(reply.status == 403U);
            }
        }

        WHEN("PUT /state sends an alias that points at the other room")
        {
            auto const reply = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.canonical_alias",
                                    alice, R"({"alias":"#elsewhere:example.org"})");

            THEN("the status and errcode are as before")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_BAD_ALIAS");
            }
        }
    }
}

// Spec (m.room.encryption): `algorithm` is required and "One of: [m.megolm.v1.aes-sha2]".
SCENARIO("POST /send with a state_key judges m.room.encryption as PUT /state does",
         "[conformance][client-server][encryption][f19]")
{
    GIVEN("alice's room")
    {
        auto started = merovingian::homeserver::start_client_server(make_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, alice);

        WHEN("she sends the event with a state_key and an unknown algorithm")
        {
            auto const reply =
                post_send(rt, alice, room_id, "m.room.encryption", empty_key, R"({"algorithm":"x.unknown"})");

            THEN("it is 400 M_BAD_JSON and the room is not encrypted")
            {
                // Spec MUST: the algorithm is one of m.megolm.v1.aes-sha2.
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_BAD_JSON");
                REQUIRE(state_of(rt, alice, room_id, "m.room.encryption").status == 404U);
            }
        }

        WHEN("she sends the event with no algorithm")
        {
            auto const reply = post_send(rt, alice, room_id, "m.room.encryption", empty_key, "{}");

            THEN("it is 400 M_BAD_JSON")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_BAD_JSON");
            }
        }

        WHEN("she sends the event with m.megolm.v1.aes-sha2")
        {
            auto const reply = post_send(rt, alice, room_id, "m.room.encryption", empty_key,
                                         R"({"algorithm":"m.megolm.v1.aes-sha2"})");

            THEN("it is accepted and the room is encrypted")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(string_field(state_of(rt, alice, room_id, "m.room.encryption").body, "algorithm") ==
                        "m.megolm.v1.aes-sha2");
            }
        }
    }
}

// Spec (createRoom): "Events listed in `initial_state`, in the order that they are listed", an event for
// `room_alias_name` that "will become the canonical alias for the room", and 400 for an invalid request.
SCENARIO("createRoom initial_state is judged by the same content checks", "[conformance][client-server][f19]")
{
    GIVEN("alice, who holds the alias #taken for a room of hers")
    {
        auto started = merovingian::homeserver::start_client_server(make_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const existing = create_public_room(rt, alice);
        REQUIRE(create_alias(rt, alice, "taken", existing).status == 200U);
        auto const joined_rooms = [&] {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/joined_rooms", alice);
            REQUIRE(reply.status == 200U);
            return reply.body;
        };
        auto const rooms_before = joined_rooms();

        WHEN("initial_state holds an m.room.encryption with an unknown algorithm")
        {
            auto const reply = create_room_with(
                rt, alice,
                R"({"initial_state":[{"type":"m.room.encryption","state_key":"","content":{"algorithm":"x.unknown"}}]})");

            THEN("it is 400 M_INVALID_ROOM_STATE and no room is stored")
            {
                // Spec MUST: 400 M_INVALID_ROOM_STATE, "The initial state implied by the parameters to the request is
                // invalid". Decided by the encryption policy (ADR-0445), which the content check leaves alone: an
                // entry that is not m.megolm.v1.aes-sha2 is how a client asks for an unencrypted room.
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_INVALID_ROOM_STATE");
                REQUIRE(joined_rooms() == rooms_before);
            }
        }

        WHEN("initial_state holds a valid m.room.encryption")
        {
            auto const reply = create_room_with(
                rt, alice,
                R"({"initial_state":[{"type":"m.room.encryption","state_key":"","content":{"algorithm":"m.megolm.v1.aes-sha2"}}]})");

            THEN("the room is created encrypted")
            {
                // Clients create encrypted rooms this way.
                REQUIRE(reply.status == 200U);
                auto const state = state_of(rt, alice, string_field(reply.body, "room_id"), "m.room.encryption");
                REQUIRE(state.status == 200U);
                REQUIRE(string_field(state.body, "algorithm") == "m.megolm.v1.aes-sha2");
            }
        }

        WHEN("initial_state holds an m.room.encryption under another state key with an unknown algorithm")
        {
            auto const reply = create_room_with(
                rt, alice,
                R"({"initial_state":[{"type":"m.room.encryption","state_key":"other","content":{"algorithm":"x"}}]})");

            THEN("it is not judged")
            {
                REQUIRE(reply.status == 200U);
            }
        }

        WHEN("initial_state holds a canonical alias that is not a room alias")
        {
            auto const reply = create_room_with(
                rt, alice,
                R"({"initial_state":[{"type":"m.room.canonical_alias","state_key":"","content":{"alias":"nope"}}]})");

            THEN("it is 400 M_INVALID_ROOM_STATE and no room is stored")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_INVALID_ROOM_STATE");
                REQUIRE(joined_rooms() == rooms_before);
            }
        }

        WHEN("initial_state holds a canonical alias that points at another room")
        {
            auto const reply = create_room_with(
                rt, alice,
                R"({"initial_state":[{"type":"m.room.canonical_alias","state_key":"","content":{"alias":"#taken:example.org"}}]})");

            THEN("it is 400 M_INVALID_ROOM_STATE")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_INVALID_ROOM_STATE");
            }
        }

        WHEN("initial_state holds a local canonical alias that nobody has created")
        {
            auto const reply = create_room_with(
                rt, alice,
                R"({"initial_state":[{"type":"m.room.canonical_alias","state_key":"","content":{"alias":"#ghost:example.org"}}]})");

            THEN("it is 400 M_INVALID_ROOM_STATE")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_INVALID_ROOM_STATE");
            }
        }

        WHEN("initial_state names the alias the same request creates with room_alias_name")
        {
            auto const reply = create_room_with(
                rt, alice,
                R"({"room_alias_name":"fresh","initial_state":[{"type":"m.room.canonical_alias","state_key":"","content":{"alias":"#fresh:example.org","alt_aliases":["#fresh:example.org"]}}]})");

            THEN("the room is created with that canonical alias")
            {
                // The room and alias do not exist when the state is judged; the alias is the one being created.
                REQUIRE(reply.status == 200U);
                auto const state = state_of(rt, alice, string_field(reply.body, "room_id"), "m.room.canonical_alias");
                REQUIRE(state.status == 200U);
                REQUIRE(string_field(state.body, "alias") == "#fresh:example.org");
            }
        }

        WHEN("initial_state names an alias on another server")
        {
            auto const reply = create_room_with(
                rt, alice,
                R"({"initial_state":[{"type":"m.room.canonical_alias","state_key":"","content":{"alias":"#x:remote.example"}}]})");

            THEN("only its syntax is judged")
            {
                REQUIRE(reply.status == 200U);
            }
        }
    }
}
