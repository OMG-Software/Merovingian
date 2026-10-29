// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for the room endpoints Complement run 10 found out of step with the spec:
// kick, GET /event, m.room.canonical_alias validation, createRoom's `topic` and `room_version`.

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
#include <variant>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto run10_config() -> merovingian::config::Config
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

[[nodiscard]] auto user_id(std::string const& localpart) -> std::string
{
    return "@" + localpart + ":example.org";
}

[[nodiscard]] auto create_room_with(ClientServerRuntime& rt, std::string const& token, std::string const& body) -> Reply
{
    return call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);
}

[[nodiscard]] auto create_public_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const reply = create_room_with(rt, token, R"({"preset":"public_chat"})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto string_field(std::string const& body, std::string_view key) -> std::string
{
    auto const parsed = parse_object(body);
    auto const* value = string_member(parsed, key);
    return value == nullptr ? std::string{} : *value;
}

[[nodiscard]] auto joined_members(ClientServerRuntime& rt, std::string const& token, std::string const& room_id)
    -> std::string
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/joined_members", token);
    REQUIRE(reply.status == 200U);
    return reply.body;
}

[[nodiscard]] auto kick(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                        std::string const& target) -> Reply
{
    return call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/kick", token,
                R"({"user_id":")" + target + R"(","reason":"bye"})");
}

[[nodiscard]] auto alias_target(std::string const& localpart) -> std::string
{
    return "/_matrix/client/v3/directory/room/%23" + localpart + "%3Aexample.org";
}

[[nodiscard]] auto create_alias(ClientServerRuntime& rt, std::string const& token, std::string const& localpart,
                                std::string const& room_id) -> Reply
{
    return call(rt, "PUT", alias_target(localpart), token, R"({"room_id":")" + room_id + R"("})");
}

[[nodiscard]] auto put_canonical_alias(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                       std::string const& content) -> Reply
{
    return call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.canonical_alias", token, content);
}

[[nodiscard]] auto topic_state(ClientServerRuntime& rt, std::string const& token, std::string const& room_id)
    -> merovingian::canonicaljson::Object
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic/", token);
    REQUIRE(reply.status == 200U);
    return parse_object(reply.body);
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/rooms/{roomId}/kick
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidkick
//
// 403: "Example reasons for rejections are: ... The kickee is not currently in the room."
// A user who left, or who never joined, is not currently in the room.
SCENARIO("A kick of a user who is not in the room is refused with 403", "[conformance][client-server][kick][run10]")
{
    GIVEN("alice's public room, bob who joined and left, and carol who never joined")
    {
        auto started = merovingian::homeserver::start_client_server(run10_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        std::ignore = register_and_login(rt, "carol");
        auto const room_id = create_public_room(rt, alice);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}").status == 200U);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", bob, "{}").status == 200U);

        WHEN("alice kicks bob, who has left")
        {
            auto const reply = kick(rt, alice, room_id, user_id("bob"));

            THEN("it is 403 M_FORBIDDEN")
            {
                // Spec: "The kickee is not currently in the room."
                REQUIRE(reply.status == 403U);
                REQUIRE(string_field(reply.body, "errcode") == "M_FORBIDDEN");
            }
        }

        WHEN("alice kicks carol, who never joined")
        {
            auto const reply = kick(rt, alice, room_id, user_id("carol"));

            THEN("it is 403 M_FORBIDDEN and carol gains no membership event")
            {
                REQUIRE(reply.status == 403U);
                REQUIRE(string_field(reply.body, "errcode") == "M_FORBIDDEN");
                auto const members = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members", alice);
                REQUIRE(members.status == 200U);
                REQUIRE(members.body.find(user_id("carol")) == std::string::npos);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/rooms/{roomId}/kick
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidkick
//
// 200: "The user has been kicked from the room." A joined user, and an invited user (whose
// membership is `invite`, a state from which `leave` is a valid transition), can be kicked.
SCENARIO("A kick of a joined or invited user succeeds", "[conformance][client-server][kick][run10]")
{
    GIVEN("alice's public room, bob who joined and carol who was invited")
    {
        auto started = merovingian::homeserver::start_client_server(run10_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        std::ignore = register_and_login(rt, "carol");
        auto const room_id = create_public_room(rt, alice);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}").status == 200U);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                     R"({"user_id":"@carol:example.org"})")
                    .status == 200U);

        WHEN("alice kicks bob and then carol")
        {
            auto const kicked_bob = kick(rt, alice, room_id, user_id("bob"));
            auto const kicked_carol = kick(rt, alice, room_id, user_id("carol"));

            THEN("both are 200 and bob is no longer joined")
            {
                // Spec: "200 The user has been kicked from the room."
                REQUIRE(kicked_bob.status == 200U);
                REQUIRE(kicked_carol.status == 200U);
                REQUIRE(joined_members(rt, alice, room_id).find(user_id("bob")) == std::string::npos);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomideventeventid
//
// The only error response the endpoint defines is "404 The event was not found or you do not
// have permission to read this event.", so a user without access cannot tell the event exists.
SCENARIO("GET /event for a user with no access is 404, never 403", "[conformance][client-server][event][run10]")
{
    GIVEN("alice's invite-only room with a message, and mallory who is not in it")
    {
        auto started = merovingian::homeserver::start_client_server(run10_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const mallory = register_and_login(rt, "mallory");
        auto const created = create_room_with(rt, alice, R"({"preset":"private_chat"})");
        REQUIRE(created.status == 200U);
        auto const room_id = string_field(created.body, "room_id");
        auto const sent = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t1", alice,
                               R"({"msgtype":"m.text","body":"run10-secret"})");
        REQUIRE(sent.status == 200U);
        auto const event_id = string_field(sent.body, "event_id");

        WHEN("mallory fetches the event, and an event ID that does not exist")
        {
            auto const real = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id, mallory);
            auto const missing =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/$does_not_exist", mallory);

            THEN("both are the same 404 M_NOT_FOUND and nothing of the event leaks")
            {
                // Spec: "404 The event was not found or you do not have permission to read this event."
                REQUIRE(real.status == 404U);
                REQUIRE(string_field(real.body, "errcode") == "M_NOT_FOUND");
                REQUIRE(real.body.find("run10-secret") == std::string::npos);
                REQUIRE(missing.status == 404U);
                REQUIRE(string_field(missing.body, "errcode") == "M_NOT_FOUND");
                REQUIRE(string_field(missing.body, "error") == string_field(real.body, "error"));
            }
        }

        WHEN("alice, who is joined, fetches the event")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id, alice);

            THEN("it is served")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(reply.body.find("run10-secret") != std::string::npos);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3roomsroomidstateeventtypestatekey
//
// "If the event type being sent is `m.room.canonical_alias` servers SHOULD ensure that any new
// aliases being listed in the event are valid per their grammar/syntax and that they point to the
// room ID where the state event is to be sent to. Servers do not validate aliases which are being
// removed or are already present in the state event."
// 400: "`M_INVALID_PARAM`: One or more aliases ... have invalid syntax. `M_BAD_ALIAS`: One or more
// aliases ... do not point to the room ID for which the state event is to be sent to."
SCENARIO("A canonical alias event is validated against the alias directory",
         "[conformance][client-server][canonical-alias][run10]")
{
    GIVEN("alice's room with the alias #here, and another room of hers with the alias #elsewhere")
    {
        auto started = merovingian::homeserver::start_client_server(run10_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, alice);
        auto const other_room_id = create_public_room(rt, alice);
        REQUIRE(create_alias(rt, alice, "here", room_id).status == 200U);
        REQUIRE(create_alias(rt, alice, "elsewhere", other_room_id).status == 200U);

        WHEN("alice sets `alias` to text that is not a room alias")
        {
            auto const reply = put_canonical_alias(rt, alice, room_id, R"({"alias":"not an alias"})");

            THEN("it is 400 M_INVALID_PARAM")
            {
                // Spec: "M_INVALID_PARAM: One or more aliases ... have invalid syntax."
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_INVALID_PARAM");
            }
        }

        WHEN("alice lists a syntactically invalid entry in `alt_aliases`")
        {
            auto const reply =
                put_canonical_alias(rt, alice, room_id, R"({"alt_aliases":["#here:example.org","oops"]})");

            THEN("it is 400 M_INVALID_PARAM")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_INVALID_PARAM");
            }
        }

        WHEN("alice sets `alias` to a well-formed local alias that was never created")
        {
            auto const reply = put_canonical_alias(rt, alice, room_id, R"({"alias":"#never:example.org"})");

            THEN("it is 400 M_BAD_ALIAS")
            {
                // Spec: "M_BAD_ALIAS: ... do not point to the room ID".
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_BAD_ALIAS");
            }
        }

        WHEN("alice sets `alias` to an alias that points at her other room")
        {
            auto const reply = put_canonical_alias(rt, alice, room_id, R"({"alias":"#elsewhere:example.org"})");

            THEN("it is 400 M_BAD_ALIAS")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_BAD_ALIAS");
            }
        }

        WHEN("alice lists an alias of the other room in `alt_aliases`")
        {
            auto const reply = put_canonical_alias(
                rt, alice, room_id, R"({"alias":"#here:example.org","alt_aliases":["#elsewhere:example.org"]})");

            THEN("it is 400 M_BAD_ALIAS")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_BAD_ALIAS");
            }
        }

        WHEN("alice deletes #here and then names it as the canonical alias")
        {
            REQUIRE(call(rt, "DELETE", alias_target("here"), alice).status == 200U);
            auto const reply = put_canonical_alias(rt, alice, room_id, R"({"alias":"#here:example.org"})");

            THEN("it is 400 M_BAD_ALIAS")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_BAD_ALIAS");
            }
        }

        WHEN("alice sets `alias` to #here and `alt_aliases` to an alias of this room")
        {
            REQUIRE(create_alias(rt, alice, "also", room_id).status == 200U);
            auto const reply = put_canonical_alias(
                rt, alice, room_id, R"({"alias":"#here:example.org","alt_aliases":["#also:example.org"]})");

            THEN("it is accepted")
            {
                REQUIRE(reply.status == 200U);
            }
        }

        WHEN("alice clears the canonical alias with an empty content")
        {
            auto const reply = put_canonical_alias(rt, alice, room_id, "{}");

            THEN("it is accepted")
            {
                REQUIRE(reply.status == 200U);
            }
        }

        WHEN("an alias already in the state event is deleted and the event is sent again unchanged")
        {
            REQUIRE(put_canonical_alias(rt, alice, room_id, R"({"alias":"#here:example.org"})").status == 200U);
            REQUIRE(call(rt, "DELETE", alias_target("here"), alice).status == 200U);
            auto const reply =
                put_canonical_alias(rt, alice, room_id, R"({"alias":"#here:example.org","alt_aliases":[]})");

            THEN("it is accepted, because aliases already present are not validated")
            {
                // Spec: "Servers do not validate aliases which are being removed or are already
                // present in the state event."
                REQUIRE(reply.status == 200U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/createRoom, `m.room.topic`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3createroom
//
// `topic`: "an `m.room.topic` event with a `text/plain` mimetype will be sent into the room to
// indicate the topic for the room. This overwrites any `m.room.topic` event in `initial_state`."
// `m.room.topic` content: `topic` is the plain text topic and "SHOULD duplicate the content of the
// `text/plain` representation in `m.topic`"; `m.topic` is `{"m.text": [{"body", "mimetype"}]}`.
SCENARIO("createRoom's topic is written as a text/plain m.topic representation",
         "[conformance][client-server][topic][run10]")
{
    GIVEN("alice")
    {
        auto started = merovingian::homeserver::start_client_server(run10_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");

        WHEN("she creates a room with a topic")
        {
            auto const created = create_room_with(rt, alice, R"({"preset":"public_chat","topic":"Run 10 topic"})");
            REQUIRE(created.status == 200U);
            auto const content = topic_state(rt, alice, string_field(created.body, "room_id"));

            THEN("the content has `topic` and a text/plain entry in `m.topic`.`m.text`")
            {
                auto const* plain = string_member(content, "topic");
                REQUIRE(plain != nullptr);
                REQUIRE(*plain == "Run 10 topic");
                auto const* block = object_member_as_object(content, "m.topic");
                REQUIRE(block != nullptr);
                auto const* representations = object_member_as_array(*block, "m.text");
                REQUIRE(representations != nullptr);
                REQUIRE(representations->size() == 1U);
                auto const* representation =
                    std::get_if<merovingian::canonicaljson::Object>(&(*representations)[0].storage());
                REQUIRE(representation != nullptr);
                REQUIRE(*string_member(*representation, "body") == "Run 10 topic");
                REQUIRE(*string_member(*representation, "mimetype") == "text/plain");
            }
        }

        WHEN("she creates a room whose initial_state sets a different topic as well as a `topic`")
        {
            auto const created = create_room_with(
                rt, alice,
                R"({"preset":"public_chat","topic":"The real topic","initial_state":[{"type":"m.room.topic","state_key":"","content":{"topic":"Overwritten"}}]})");
            REQUIRE(created.status == 200U);
            auto const content = topic_state(rt, alice, string_field(created.body, "room_id"));

            THEN("the `topic` parameter wins, with its m.topic representation")
            {
                // Spec: "This overwrites any `m.room.topic` event in `initial_state`."
                REQUIRE(*string_member(content, "topic") == "The real topic");
                auto const* block = object_member_as_object(content, "m.topic");
                REQUIRE(block != nullptr);
                auto const* representations = object_member_as_array(*block, "m.text");
                REQUIRE(representations != nullptr);
                REQUIRE_FALSE(representations->empty());
                auto const* representation =
                    std::get_if<merovingian::canonicaljson::Object>(&(*representations)[0].storage());
                REQUIRE(representation != nullptr);
                REQUIRE(*string_member(*representation, "body") == "The real topic");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/createRoom
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3createroom
//
// `room_version` is a `string`. A body whose `room_version` is another JSON type is malformed.
SCENARIO("createRoom refuses a room_version that is not a string", "[conformance][client-server][run10]")
{
    GIVEN("alice")
    {
        auto started = merovingian::homeserver::start_client_server(run10_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");

        for (auto const* value : {"1", "12", "true", "null", "[\"12\"]", "{}"})
        {
            WHEN(std::string{"she creates a room with room_version "} + value)
            {
                auto const reply = create_room_with(rt, alice, std::string{R"({"room_version":)"} + value + "}");

                THEN("it is 400 M_BAD_JSON and no room is created")
                {
                    // Spec: `room_version` is a `string`.
                    REQUIRE(reply.status == 400U);
                    REQUIRE(string_field(reply.body, "errcode") == "M_BAD_JSON");
                    auto const joined = call(rt, "GET", "/_matrix/client/v3/joined_rooms", alice);
                    REQUIRE(joined.status == 200U);
                    auto const parsed = parse_object(joined.body);
                    auto const* rooms = object_member_as_array(parsed, "joined_rooms");
                    REQUIRE(rooms != nullptr);
                    REQUIRE(rooms->empty());
                }
            }
        }

        WHEN("she creates a room with room_version \"10\"")
        {
            auto const reply = create_room_with(rt, alice, R"({"room_version":"10"})");

            THEN("it is accepted")
            {
                REQUIRE(reply.status == 200U);
            }
        }
    }
}
