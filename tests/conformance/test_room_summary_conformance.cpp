// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for GET /_matrix/client/v1/room_summary/{roomIdOrAlias} (added in v1.15).

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/query_params.hpp"
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

[[nodiscard]] auto summary_config() -> merovingian::config::Config
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

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token, std::string const& body)
    -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);
    REQUIRE(reply.status == 200U);
    return string_field(reply.body, "room_id");
}

[[nodiscard]] auto summary_of(ClientServerRuntime& rt, std::string const& token, std::string const& id_or_alias)
    -> Reply
{
    return call(rt, "GET",
                "/_matrix/client/v1/room_summary/" + merovingian::core::percent_encode_path_component(id_or_alias),
                token);
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/room_summary/{roomIdOrAlias}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1room_summaryroomidoralias
//
// 200 "A summary of the room": `room_id`, `num_joined_members`, `world_readable` and
// `guest_can_join` are required; `name`, `topic`, `canonical_alias`, `join_rule`, `room_type`,
// `room_version` and `membership` describe the room and the caller.
SCENARIO("A room summary describes a public room by its ID or its alias",
         "[conformance][client-server][room-summary][run10]")
{
    GIVEN("alice's public room with a name, topic and alias, and bob who is not in it")
    {
        auto started = merovingian::homeserver::start_client_server(summary_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(
            rt, alice,
            R"({"preset":"public_chat","name":"Summary room","topic":"Summary topic","room_alias_name":"summary","creation_content":{"type":"m.space"}})");

        WHEN("bob asks for the summary by room ID")
        {
            auto const reply = summary_of(rt, bob, room_id);

            THEN("it carries the required and descriptive fields and no membership")
            {
                REQUIRE(reply.status == 200U);
                auto const body = parse_object(reply.body);
                // Spec: `room_id`, `num_joined_members`, `world_readable`, `guest_can_join` required.
                REQUIRE(*string_member(body, "room_id") == room_id);
                REQUIRE(*int_member(body, "num_joined_members") == 1);
                REQUIRE(bool_member(body, "world_readable") != nullptr);
                REQUIRE_FALSE(*bool_member(body, "world_readable"));
                REQUIRE(bool_member(body, "guest_can_join") != nullptr);
                REQUIRE(*string_member(body, "name") == "Summary room");
                REQUIRE(*string_member(body, "topic") == "Summary topic");
                REQUIRE(*string_member(body, "canonical_alias") == "#summary:example.org");
                REQUIRE(*string_member(body, "join_rule") == "public");
                REQUIRE(*string_member(body, "room_type") == "m.space");
                REQUIRE(string_member(body, "room_version") != nullptr);
                // Spec: `membership` is "The membership state of the user if the user is joined".
                REQUIRE(string_member(body, "membership") == nullptr);
                // `children_state` belongs to the hierarchy's chunk, not to RoomSummary.
                REQUIRE(object_member(body, "children_state") == nullptr);
            }
        }

        WHEN("bob asks for the summary by room alias")
        {
            auto const reply = summary_of(rt, bob, "#summary:example.org");

            THEN("it is the same room's summary")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(string_field(reply.body, "room_id") == room_id);
            }
        }

        WHEN("bob joins and asks again")
        {
            REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}").status == 200U);
            auto const reply = summary_of(rt, bob, room_id);

            THEN("`membership` is join and the joined count rises")
            {
                REQUIRE(reply.status == 200U);
                auto const body = parse_object(reply.body);
                REQUIRE(*string_member(body, "membership") == "join");
                REQUIRE(*int_member(body, "num_joined_members") == 2);
            }
        }

        WHEN("bob asks for a room that does not exist and an alias that does not exist")
        {
            auto const room = summary_of(rt, bob, "!nosuchroom:example.org");
            auto const alias = summary_of(rt, bob, "#nosuchalias:example.org");

            THEN("both are 404 M_NOT_FOUND")
            {
                // Spec: "404 The room could not be found."
                REQUIRE(room.status == 404U);
                REQUIRE(string_field(room.body, "errcode") == "M_NOT_FOUND");
                REQUIRE(alias.status == 404U);
                REQUIRE(string_field(alias.body, "errcode") == "M_NOT_FOUND");
            }
        }

        WHEN("a caller with an unknown access token asks")
        {
            auto const reply = summary_of(rt, "not-a-token", room_id);

            THEN("it is 401 M_UNKNOWN_TOKEN")
            {
                REQUIRE(reply.status == 401U);
                REQUIRE(string_field(reply.body, "errcode") == "M_UNKNOWN_TOKEN");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/room_summary/{roomIdOrAlias}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1room_summaryroomidoralias
//
// "Servers MAY allow unauthenticated access to this API if at least one of the following
// conditions holds true: The room has a join rule of `public`, `knock` or `knock_restricted`. The
// room has a `world_readable` history visibility." `membership` is "Absent if the API was called
// unauthenticated." The endpoint defines 404 for a room that "could not be found".
SCENARIO("A room summary can be read without authentication only for a public, knock or world-readable room",
         "[conformance][client-server][room-summary][run10]")
{
    GIVEN("a public room, a knock room, an invite-only room, and an invite-only world-readable room")
    {
        auto started = merovingian::homeserver::start_client_server(summary_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const public_room = create_room(rt, alice, R"({"preset":"public_chat"})");
        auto const knock_room = create_room(
            rt, alice,
            R"({"preset":"private_chat","initial_state":[{"type":"m.room.join_rules","state_key":"","content":{"join_rule":"knock"}}]})");
        auto const private_room = create_room(rt, alice, R"({"preset":"private_chat"})");
        auto const readable_room = create_room(
            rt, alice,
            R"({"preset":"private_chat","initial_state":[{"type":"m.room.history_visibility","state_key":"","content":{"history_visibility":"world_readable"}}]})");

        WHEN("an unauthenticated caller asks for each")
        {
            auto const pub = summary_of(rt, {}, public_room);
            auto const knock = summary_of(rt, {}, knock_room);
            auto const readable = summary_of(rt, {}, readable_room);
            auto const priv = summary_of(rt, {}, private_room);
            auto const missing = summary_of(rt, {}, "!nosuchroom:example.org");

            THEN("the public, knock and world-readable rooms are served, without `membership`")
            {
                REQUIRE(pub.status == 200U);
                REQUIRE(knock.status == 200U);
                REQUIRE(readable.status == 200U);
                REQUIRE(string_member(parse_object(pub.body), "membership") == nullptr);
                REQUIRE(*bool_member(parse_object(readable.body), "world_readable"));
            }

            THEN("the invite-only room and a room that does not exist are refused identically")
            {
                // Spec: "Requires authentication: Yes"; a room outside the MAY conditions needs a
                // token, whether or not it exists, so the answer does not reveal the room.
                REQUIRE(priv.status == 401U);
                REQUIRE(string_field(priv.body, "errcode") == "M_MISSING_TOKEN");
                REQUIRE(missing.status == priv.status);
                REQUIRE(string_field(missing.body, "errcode") == string_field(priv.body, "errcode"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/room_summary/{roomIdOrAlias}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1room_summaryroomidoralias
//
// An authenticated caller is shown a room they are joined to or invited to, one they could join
// (public, knock, knock_restricted, or restricted with a joined allow-room), or a world-readable
// one; any other room "could not be found" (404). `allowed_room_ids`: "If the room is a restricted
// room, these are the room IDs which are specified by the join rules."
SCENARIO("A room summary of a private or restricted room is shown only to those who may see it",
         "[conformance][client-server][room-summary][run10]")
{
    GIVEN("alice's invite-only room with bob invited, a space with carol joined, and a room restricted to that space")
    {
        auto started = merovingian::homeserver::start_client_server(summary_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const dave = register_and_login(rt, "dave");
        auto const private_room = create_room(rt, alice, R"({"preset":"private_chat"})");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + private_room + "/invite", alice,
                     R"({"user_id":"@bob:example.org"})")
                    .status == 200U);
        auto const space = create_room(rt, alice, R"({"preset":"public_chat","creation_content":{"type":"m.space"}})");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + space + "/join", carol, "{}").status == 200U);
        auto const restricted = create_room(
            rt, alice,
            R"({"preset":"private_chat","initial_state":[{"type":"m.room.join_rules","state_key":"","content":{"join_rule":"restricted","allow":[{"type":"m.room_membership","room_id":")" +
                space + R"("}]}}]})");

        WHEN("alice, bob (invited) and dave (a stranger) ask for the private room")
        {
            auto const joined = summary_of(rt, alice, private_room);
            auto const invited = summary_of(rt, bob, private_room);
            auto const stranger = summary_of(rt, dave, private_room);

            THEN("alice and bob see it with their membership, and dave gets 404 M_NOT_FOUND")
            {
                REQUIRE(joined.status == 200U);
                REQUIRE(string_field(joined.body, "membership") == "join");
                REQUIRE(invited.status == 200U);
                REQUIRE(string_field(invited.body, "membership") == "invite");
                // Spec: "404 The room could not be found."
                REQUIRE(stranger.status == 404U);
                REQUIRE(string_field(stranger.body, "errcode") == "M_NOT_FOUND");
            }
        }

        WHEN("carol (joined to the allowed space) and dave ask for the restricted room")
        {
            auto const member_of_space = summary_of(rt, carol, restricted);
            auto const stranger = summary_of(rt, dave, restricted);

            THEN("carol sees it with `allowed_room_ids`, and dave gets 404")
            {
                REQUIRE(member_of_space.status == 200U);
                auto const body = parse_object(member_of_space.body);
                REQUIRE(*string_member(body, "join_rule") == "restricted");
                auto const* allowed = object_member_as_array(body, "allowed_room_ids");
                REQUIRE(allowed != nullptr);
                REQUIRE(allowed->size() == 1U);
                REQUIRE(*std::get_if<std::string>(&(*allowed)[0].storage()) == space);
                REQUIRE(stranger.status == 404U);
            }
        }
    }
}
