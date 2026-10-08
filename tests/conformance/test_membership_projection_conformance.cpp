// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for CSAZ-6: a membership change sent as a state event takes effect exactly as
// one sent through the membership APIs does.
//
// Spec: Matrix Client-Server API v1.19, `m.room.member`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#mroommember
//
// Spec: "Adjusts the membership state for a user in a room. It is preferable to use the membership
// APIs (`/rooms/<room id>/invite` etc) when performing membership actions rather than adjusting the
// state directly as there are a restricted set of valid transformations." Adjusting the state
// directly is therefore valid, and an accepted m.room.member event is the user's membership,
// whichever endpoint sent it.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto projection_config() -> merovingian::config::Config
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

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token, std::string const& preset)
    -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":")" + preset + R"("})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto put_member_state(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                    std::string const& target, std::string const& membership) -> Reply
{
    return call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.member/" + target, token,
                R"({"membership":")" + membership + R"("})");
}

[[nodiscard]] auto joined_members_body(ClientServerRuntime& rt, std::string const& token, std::string const& room_id)
    -> std::string
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/joined_members", token);
    REQUIRE(reply.status == 200U);
    return reply.body;
}

[[nodiscard]] auto send_text(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                             std::string const& txn) -> Reply
{
    return call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn, token,
                R"({"msgtype":"m.text","body":"hello"})");
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/state/m.room.member/{stateKey}; `m.room.member`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#mroommember
//
// `ban` - "The user has been banned from the room, and is no longer allowed to join it until they
// are un-banned".
SCENARIO("A ban sent through the state API removes the user from the room", "[conformance][client-server][csaz-6]")
{
    GIVEN("alice's public room, with bob joined")
    {
        auto started = merovingian::homeserver::start_client_server(projection_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice, "public_chat");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}").status == 200U);
        REQUIRE(joined_members_body(rt, alice, room_id).find(user_id("bob")) != std::string::npos);
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/before-ban", alice,
                     R"({"msgtype":"m.text","body":"csaz6-before-ban"})")
                    .status == 200U);

        WHEN("alice bans bob with PUT /state/m.room.member/@bob")
        {
            REQUIRE(put_member_state(rt, alice, room_id, user_id("bob"), "ban").status == 200U);

            THEN("bob is no longer a joined member")
            {
                REQUIRE(joined_members_body(rt, alice, room_id).find(user_id("bob")) == std::string::npos);
            }
            THEN("bob still sees what he could see before the ban, and nothing sent after it")
            {
                // Spec (Room History Visibility): "After a user has left a room, they may see any
                // events which they were allowed to see before they left the room, but no events
                // received after they left." A ban ends bob's join just as a leave does (ADR-0084).
                REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/after-ban", alice,
                             R"({"msgtype":"m.text","body":"csaz6-after-ban"})")
                            .status == 200U);
                auto const messages =
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=50", bob);
                REQUIRE(messages.status == 200U);
                REQUIRE(messages.body.find("csaz6-after-ban") == std::string::npos);
                // Spec: rule 2, "If the user's `membership` was `join`, allow", judged at the event.
                REQUIRE(messages.body.find("csaz6-before-ban") != std::string::npos);
            }
            THEN("bob can no longer send to the room")
            {
                REQUIRE(send_text(rt, bob, room_id, "after-ban").status == 403U);
            }
            THEN("bob is not listed in his joined rooms")
            {
                auto const joined = call(rt, "GET", "/_matrix/client/v3/joined_rooms", bob);
                REQUIRE(joined.status == 200U);
                REQUIRE(joined.body.find(room_id) == std::string::npos);
            }
            THEN("bob cannot rejoin")
            {
                // Spec: a banned user "is no longer allowed to join it until they are un-banned".
                REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}").status == 403U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/state/m.room.member/{stateKey}; `m.room.member`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#mroommember
//
// `leave` - "The user was once joined to the room, but has since left (possibly by choice, or
// possibly by being kicked)."
SCENARIO("A kick sent through the state API removes the user from the room", "[conformance][client-server][csaz-6]")
{
    GIVEN("alice's public room, with bob joined")
    {
        auto started = merovingian::homeserver::start_client_server(projection_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice, "public_chat");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}").status == 200U);

        WHEN("alice kicks bob with PUT /state/m.room.member/@bob")
        {
            REQUIRE(put_member_state(rt, alice, room_id, user_id("bob"), "leave").status == 200U);

            THEN("bob is no longer a joined member and cannot send")
            {
                REQUIRE(joined_members_body(rt, alice, room_id).find(user_id("bob")) == std::string::npos);
                REQUIRE(send_text(rt, bob, room_id, "after-kick").status == 403U);
            }
            THEN("bob can join again, since a kick is not a ban")
            {
                REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}").status == 200U);
                REQUIRE(joined_members_body(rt, alice, room_id).find(user_id("bob")) != std::string::npos);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/state/m.room.member/{stateKey}; `m.room.member`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#mroommember
//
// `invite` - "The user has been invited to join a room, but has not yet joined it."
SCENARIO("An invite sent through the state API is an invite the invitee can see and accept",
         "[conformance][client-server][csaz-6]")
{
    GIVEN("alice's invite-only room and a user carol who is not in it")
    {
        auto started = merovingian::homeserver::start_client_server(projection_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice, "private_chat");

        WHEN("alice invites carol with PUT /state/m.room.member/@carol")
        {
            REQUIRE(put_member_state(rt, alice, room_id, user_id("carol"), "invite").status == 200U);

            THEN("carol's sync lists the room under invites")
            {
                auto const sync = call(rt, "GET", "/_matrix/client/v3/sync?timeout=0", carol);
                REQUIRE(sync.status == 200U);
                auto const body = parse_object(sync.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* invite = object_member_as_object(*rooms, "invite");
                REQUIRE(invite != nullptr);
                REQUIRE(object_member(*invite, room_id) != nullptr);
            }
            THEN("carol can join")
            {
                REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", carol, "{}").status == 200U);
                REQUIRE(joined_members_body(rt, alice, room_id).find(user_id("carol")) != std::string::npos);
            }
        }
    }
}
