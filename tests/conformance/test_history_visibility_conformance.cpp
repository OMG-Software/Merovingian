// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for CSAZ-2 (read gates on initialSync, /members, /state) and CSAZ-3
// (m.room.history_visibility enforcement on every client read path).
//
// Spec: Matrix Client-Server API v1.19, "Room History Visibility" and the
// GET /rooms/{roomId}/{members,state,state/{eventType}/{stateKey},messages,event/{eventId},
// context/{eventId},initialSync} endpoints.
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#room-history-visibility
//
// Every scenario drives the real client-server dispatcher. The history-visibility rules
// are applied to the state of the room AT the event, so each scenario sets the visibility
// at the point in the story the spec rule is about.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto visibility_config() -> merovingian::config::Config
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

[[nodiscard]] auto visibility_state(std::string_view visibility) -> std::string
{
    return R"({"type":"m.room.history_visibility","state_key":"","content":{"history_visibility":")" +
           std::string{visibility} + R"("}})";
}

// Creates a room from the public_chat preset (private_chat rooms are encrypted, and /search
// skips encrypted rooms); `initial_state` is a comma-separated list of state event objects, or
// empty. Users join by invitation in every scenario, so the join rule does not matter.
[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token,
                               std::string const& initial_state = {}) -> std::string
{
    auto const body = initial_state.empty()
                          ? std::string{R"({"preset":"public_chat"})"}
                          : std::string{R"({"preset":"public_chat","initial_state":[)"} + initial_state + "]}";
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto create_room_with_visibility(ClientServerRuntime& rt, std::string const& token,
                                               std::string_view visibility) -> std::string
{
    return create_room(rt, token, visibility_state(visibility));
}

auto set_visibility(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                    std::string_view visibility) -> void
{
    REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.history_visibility", token,
                 std::string{R"({"history_visibility":")"} + std::string{visibility} + R"("})")
                .status == 200U);
}

auto set_room_name(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                   std::string_view name) -> void
{
    REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.name", token,
                 std::string{R"({"name":")"} + std::string{name} + R"("})")
                .status == 200U);
}

[[nodiscard]] auto send_text(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                             std::string_view text) -> std::string
{
    static auto counter = std::uint64_t{0U};
    auto const reply =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/hv" + std::to_string(++counter),
             token, std::string{R"({"msgtype":"m.text","body":")"} + std::string{text} + R"("})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* event_id = string_member(parsed, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

[[nodiscard]] auto send_thread_reply(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                     std::string const& root_event_id, std::string_view text) -> std::string
{
    static auto counter = std::uint64_t{0U};
    auto const reply =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/hvt" + std::to_string(++counter),
             token,
             std::string{R"({"msgtype":"m.text","body":")"} + std::string{text} +
                 R"(","m.relates_to":{"rel_type":"m.thread","event_id":")" + root_event_id + R"("}})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* event_id = string_member(parsed, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

auto invite(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
            std::string const& localpart) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", token,
                 R"({"user_id":")" + user_id(localpart) + R"("})")
                .status == 200U);
}

auto join(ClientServerRuntime& rt, std::string const& token, std::string const& room_id) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", token, "{}").status == 200U);
}

auto invite_and_join(ClientServerRuntime& rt, std::string const& inviter_token, std::string const& room_id,
                     std::string const& localpart, std::string const& invitee_token) -> void
{
    invite(rt, inviter_token, room_id, localpart);
    join(rt, invitee_token, room_id);
}

auto leave(ClientServerRuntime& rt, std::string const& token, std::string const& room_id) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", token, "{}").status == 200U);
}

auto ban(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
         std::string const& localpart) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", token,
                 R"({"user_id":")" + user_id(localpart) + R"(","reason":"test"})")
                .status == 200U);
}

[[nodiscard]] auto event_ids_in(std::string const& body, std::string_view array_name) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    auto const parsed = parse_object(body);
    auto const* array = object_member_as_array(parsed, array_name);
    if (array == nullptr)
    {
        return ids;
    }
    for (auto const& value : *array)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        auto const* id = event == nullptr ? nullptr : string_member(*event, "event_id");
        if (id != nullptr)
        {
            ids.push_back(*id);
        }
    }
    return ids;
}

[[nodiscard]] auto serialize_object(merovingian::canonicaljson::Object const& object) -> std::string
{
    auto const serialized = merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{object});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto contains(std::vector<std::string> const& ids, std::string const& id) -> bool
{
    return std::ranges::find(ids, id) != ids.end();
}

// Event IDs of one type in an event array, with the state_key of each.
[[nodiscard]] auto events_of_type(std::string const& body, std::string_view array_name,
                                  std::string_view type) -> std::vector<std::pair<std::string, std::string>>
{
    auto out = std::vector<std::pair<std::string, std::string>>{};
    auto const parsed = parse_object(body);
    auto const* array = object_member_as_array(parsed, array_name);
    if (array == nullptr)
    {
        return out;
    }
    for (auto const& value : *array)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        if (event == nullptr)
        {
            continue;
        }
        auto const* event_type = string_member(*event, "type");
        auto const* state_key = string_member(*event, "state_key");
        auto const* id = string_member(*event, "event_id");
        if (event_type != nullptr && *event_type == type && id != nullptr)
        {
            out.emplace_back(*id, state_key == nullptr ? std::string{} : *state_key);
        }
    }
    return out;
}

[[nodiscard]] auto member_events_by_user(std::string const& body, std::string_view array_name)
    -> std::vector<std::pair<std::string, std::string>>
{
    // (state_key, membership) for every m.room.member event in the array.
    auto out = std::vector<std::pair<std::string, std::string>>{};
    auto const parsed = parse_object(body);
    auto const* array = object_member_as_array(parsed, array_name);
    if (array == nullptr)
    {
        return out;
    }
    for (auto const& value : *array)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        if (event == nullptr)
        {
            continue;
        }
        auto const* type = string_member(*event, "type");
        auto const* state_key = string_member(*event, "state_key");
        auto const* content = object_member_as_object(*event, "content");
        auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
        if (type != nullptr && *type == "m.room.member" && state_key != nullptr && membership != nullptr)
        {
            out.emplace_back(*state_key, *membership);
        }
    }
    return out;
}

[[nodiscard]] auto membership_of(std::vector<std::pair<std::string, std::string>> const& members,
                                 std::string const& user) -> std::optional<std::string>
{
    auto const it = std::ranges::find_if(members, [&](auto const& entry) {
        return entry.first == user;
    });
    return it == members.end() ? std::nullopt : std::optional<std::string>{it->second};
}

[[nodiscard]] auto messages(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                            std::string const& query = "?dir=b&limit=100") -> Reply
{
    return call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages" + query, token);
}

[[nodiscard]] auto string_field(std::string const& body, std::string_view key) -> std::string
{
    auto const parsed = parse_object(body);
    auto const* value = string_member(parsed, key);
    return value == nullptr ? std::string{} : *value;
}

[[nodiscard]] auto search_count(ClientServerRuntime& rt, std::string const& token,
                                std::string const& term) -> std::int64_t
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/search", token,
                            std::string{R"({"search_categories":{"room_events":{"search_term":")"} + term + R"("}}})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* categories = object_member_as_object(parsed, "search_categories");
    REQUIRE(categories != nullptr);
    auto const* room_events = object_member_as_object(*categories, "room_events");
    REQUIRE(room_events != nullptr);
    auto const* count = int_member(*room_events, "count");
    REQUIRE(count != nullptr);
    return *count;
}

[[nodiscard]] auto sync_timeline_ids(ClientServerRuntime& rt, std::string const& token,
                                     std::string const& room_id) -> std::vector<std::string>
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/sync", token);
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* rooms = object_member_as_object(parsed, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* joined = object_member_as_object(*rooms, "join");
    REQUIRE(joined != nullptr);
    auto const* room = object_member_as_object(*joined, room_id);
    if (room == nullptr)
    {
        return {};
    }
    auto const* timeline = object_member_as_object(*room, "timeline");
    REQUIRE(timeline != nullptr);
    auto ids = std::vector<std::string>{};
    auto const* events = object_member_as_array(*timeline, "events");
    REQUIRE(events != nullptr);
    for (auto const& value : *events)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        auto const* id = event == nullptr ? nullptr : string_member(*event, "event_id");
        if (id != nullptr)
        {
            ids.push_back(*id);
        }
    }
    return ids;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// CSAZ-2: who may read a room's state and roster
// ─────────────────────────────────────────────────────────────────────────────

// Spec: GET /rooms/{roomId}/initialSync, /members, /joined_members, /state, /state/{type}/{key}:
// "403 You aren't a member of the room and weren't previously a member of the room."
// Room History Visibility: "In all cases except world_readable, a user needs to join a room
// to view events in that room." A knock, an invite and a declined invite are not membership.
SCENARIO("A user who knocked or was invited but never joined cannot read the room",
         "[history-visibility][csaz-2][security][conformance]")
{
    GIVEN(
        "a knock room with a message, mallory who knocked, carol who was invited and declined, and dave who is invited")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const mallory = register_and_login(rt, "mallory");
        auto const carol = register_and_login(rt, "carol");
        auto const dave = register_and_login(rt, "dave");
        auto const room_id =
            create_room(rt, alice, R"({"type":"m.room.join_rules","state_key":"","content":{"join_rule":"knock"}})");
        std::ignore = send_text(rt, alice, room_id, "secret-knock-room-history");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/knock/" + room_id, mallory, "{}").status == 200U);
        invite(rt, alice, room_id, "carol");
        leave(rt, carol, room_id);
        invite(rt, alice, room_id, "dave");

        for (auto const* who : {"mallory", "carol", "dave"})
        {
            auto const& token = std::string{who} == "mallory" ? mallory : (std::string{who} == "carol" ? carol : dave);
            WHEN(std::string{who} + " calls initialSync, /members, /joined_members, /state and /state/{type}/{key}")
            {
                auto const initial = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/initialSync", token);
                auto const members = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members", token);
                auto const joined = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/joined_members", token);
                auto const state = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token);
                auto const one =
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.join_rules/", token);

                THEN("every one is refused with 403 M_FORBIDDEN and nothing about the room leaks")
                {
                    for (auto const* reply : {&initial, &members, &joined, &state, &one})
                    {
                        REQUIRE(reply->status == 403U);
                        REQUIRE(string_field(reply->body, "errcode") == "M_FORBIDDEN");
                        REQUIRE(reply->body.find("secret-knock-room-history") == std::string::npos);
                        REQUIRE(reply->body.find("@alice:example.org") == std::string::npos);
                    }
                }
            }
        }
    }
}

// Spec: /members 200 "If you have left the room then this will be the members of the room when
// you left."; initialSync `state` "If the user has left the room this will be the state of the
// room when they left it."; Room History Visibility: "After a user has left a room, they may
// see any events which they were allowed to see before they left the room, but no events
// received after they left."
SCENARIO("A banned user reads the room only as it was when they were banned",
         "[history-visibility][csaz-2][security][conformance]")
{
    GIVEN("a room where bob was joined, then banned, and the room then moved on without him")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice);
        set_room_name(rt, alice, room_id, "Before the ban");
        invite_and_join(rt, alice, room_id, "bob", bob);
        auto const before = send_text(rt, alice, room_id, "said-before-the-ban");
        ban(rt, alice, room_id, "bob");
        auto const after = send_text(rt, alice, room_id, "said-after-the-ban");
        invite_and_join(rt, alice, room_id, "carol", carol);
        set_room_name(rt, alice, room_id, "After the ban");

        WHEN("bob calls initialSync")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/initialSync", bob);

            THEN("the message sent after the ban is absent and the state is as of the ban")
            {
                REQUIRE(reply.status == 200U);
                auto const parsed = parse_object(reply.body);
                auto const* chunk_holder = object_member_as_object(parsed, "messages");
                REQUIRE(chunk_holder != nullptr);
                auto const ids = event_ids_in(serialize_object(*chunk_holder), "chunk");
                REQUIRE(contains(ids, before));
                REQUIRE_FALSE(contains(ids, after));
                REQUIRE(reply.body.find("said-after-the-ban") == std::string::npos);
                REQUIRE(reply.body.find("After the ban") == std::string::npos);
                REQUIRE(reply.body.find("Before the ban") != std::string::npos);
                auto const members = member_events_by_user(reply.body, "state");
                REQUIRE(membership_of(members, user_id("carol")) == std::nullopt);
                REQUIRE(membership_of(members, user_id("bob")) == std::optional<std::string>{"ban"});
            }
        }

        WHEN("bob calls /messages")
        {
            auto const reply = messages(rt, bob, room_id);

            THEN("the message sent before the ban is returned and the message sent after is not")
            {
                REQUIRE(reply.status == 200U);
                auto const ids = event_ids_in(reply.body, "chunk");
                REQUIRE(contains(ids, before));
                REQUIRE_FALSE(contains(ids, after));
                REQUIRE(reply.body.find("said-after-the-ban") == std::string::npos);
                REQUIRE(reply.body.find("After the ban") == std::string::npos);
                auto const joins = member_events_by_user(reply.body, "chunk");
                REQUIRE(membership_of(joins, user_id("carol")) == std::nullopt);
            }
        }

        WHEN("bob calls /members")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members", bob);

            THEN("the roster is as of his ban, without anyone who joined later")
            {
                REQUIRE(reply.status == 200U);
                auto const members = member_events_by_user(reply.body, "chunk");
                REQUIRE(membership_of(members, user_id("alice")) == std::optional<std::string>{"join"});
                REQUIRE(membership_of(members, user_id("bob")) == std::optional<std::string>{"ban"});
                REQUIRE(membership_of(members, user_id("carol")) == std::nullopt);
            }
        }

        WHEN("bob calls /state and /state/m.room.name")
        {
            auto const all = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state", bob);
            auto const name = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.name/", bob);

            THEN("both describe the room as it was when he was banned")
            {
                REQUIRE(all.status == 200U);
                REQUIRE(all.body.find("Before the ban") != std::string::npos);
                REQUIRE(all.body.find("After the ban") == std::string::npos);
                REQUIRE(all.body.find(user_id("carol")) == std::string::npos);
                REQUIRE(name.status == 200U);
                REQUIRE(string_field(name.body, "name") == "Before the ban");
            }
        }

        WHEN("bob calls /joined_members")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/joined_members", bob);

            THEN("it is refused, because the spec returns only the joined members to a joined user")
            {
                REQUIRE(reply.status == 403U);
            }
        }

        WHEN("alice, who is joined, calls initialSync and /members")
        {
            auto const initial = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/initialSync", alice);
            auto const members = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members", alice);

            THEN("she sees the current room")
            {
                REQUIRE(initial.status == 200U);
                REQUIRE(initial.body.find("said-after-the-ban") != std::string::npos);
                REQUIRE(initial.body.find("After the ban") != std::string::npos);
                REQUIRE(members.status == 200U);
                auto const roster = member_events_by_user(members.body, "chunk");
                REQUIRE(membership_of(roster, user_id("carol")) == std::optional<std::string>{"join"});
            }
        }
    }
}

// Spec: same as above. A user who left of their own accord is bounded the same way.
SCENARIO("A user who left reads the room only as it was when they left",
         "[history-visibility][csaz-2][security][conformance]")
{
    GIVEN("a room where bob joined and left, and alice kept talking")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice);
        invite_and_join(rt, alice, room_id, "bob", bob);
        auto const before = send_text(rt, alice, room_id, "bob-was-here-for-this");
        leave(rt, bob, room_id);
        auto const after = send_text(rt, alice, room_id, "bob-was-gone-for-this");
        invite_and_join(rt, alice, room_id, "carol", carol);

        WHEN("bob calls /members with `at` far beyond his departure")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members?at=999999", bob);

            THEN("the answer is capped at the moment he left")
            {
                REQUIRE(reply.status == 200U);
                auto const members = member_events_by_user(reply.body, "chunk");
                REQUIRE(membership_of(members, user_id("bob")) == std::optional<std::string>{"leave"});
                REQUIRE(membership_of(members, user_id("carol")) == std::nullopt);
            }
        }

        WHEN("bob calls /messages and initialSync")
        {
            auto const page = messages(rt, bob, room_id);
            auto const initial = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/initialSync", bob);

            THEN("he sees what he saw while joined and nothing received after")
            {
                REQUIRE(page.status == 200U);
                auto const ids = event_ids_in(page.body, "chunk");
                REQUIRE(contains(ids, before));
                REQUIRE_FALSE(contains(ids, after));
                REQUIRE(initial.status == 200U);
                REQUIRE(initial.body.find("bob-was-gone-for-this") == std::string::npos);
            }
        }
    }
}

// Spec: POST /rooms/{roomId}/forget: "the user will no longer be able to retrieve history for
// that room." A forgotten room is one the user is no longer a member of and cannot read.
SCENARIO("A user who forgot a room can no longer read it", "[history-visibility][csaz-2][conformance]")
{
    GIVEN("a room bob joined, left and then forgot")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice);
        invite_and_join(rt, alice, room_id, "bob", bob);
        std::ignore = send_text(rt, alice, room_id, "said-while-bob-was-here");
        leave(rt, bob, room_id);

        WHEN("bob reads the room before and after forgetting it")
        {
            auto const before = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members", bob);
            REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/forget", bob, "{}").status == 200U);
            auto const after = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members", bob);
            auto const after_initial = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/initialSync", bob);
            auto const after_messages = messages(rt, bob, room_id);

            THEN("he could read it before, and every read is refused after")
            {
                REQUIRE(before.status == 200U);
                REQUIRE(after.status == 403U);
                REQUIRE(after_initial.status == 403U);
                REQUIRE(after_messages.status == 403U);
            }
        }
    }
}

// Spec: /members `at`: "The point in time (pagination token) to return members for in the
// room." Defaults to the current state.
SCENARIO("GET /members honours the at token", "[history-visibility][csaz-2][conformance]")
{
    GIVEN("a room where bob joined after a known point in the timeline")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice);
        std::ignore = send_text(rt, alice, room_id, "marker");
        auto const latest = messages(rt, alice, room_id, "?dir=b&limit=1");
        REQUIRE(latest.status == 200U);
        auto const token_at_marker = string_field(latest.body, "start");
        REQUIRE_FALSE(token_at_marker.empty());
        invite_and_join(rt, alice, room_id, "bob", bob);

        WHEN("alice asks for the members at the earlier token and at the current state")
        {
            auto const earlier =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members?at=" + token_at_marker, alice);
            auto const current = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members", alice);

            THEN("bob is absent at the earlier point and present now")
            {
                REQUIRE(earlier.status == 200U);
                REQUIRE(current.status == 200U);
                auto const then_members = member_events_by_user(earlier.body, "chunk");
                auto const now_members = member_events_by_user(current.body, "chunk");
                REQUIRE(membership_of(then_members, user_id("alice")) == std::optional<std::string>{"join"});
                REQUIRE(membership_of(then_members, user_id("bob")) == std::nullopt);
                REQUIRE(membership_of(now_members, user_id("bob")) == std::optional<std::string>{"join"});
            }
        }

        WHEN("alice gives an at token that is not a token")
        {
            auto const reply =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members?at=not-a-token", alice);

            THEN("the request is refused as a bad parameter")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(string_field(reply.body, "errcode") == "M_INVALID_PARAM");
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSAZ-3: m.room.history_visibility on every read path
// ─────────────────────────────────────────────────────────────────────────────

// Spec (Room History Visibility, server behaviour), rules 2, 3 and 5: with `joined`, events
// sent before the user joined are not visible to them.
SCENARIO("With joined history visibility a newcomer cannot read events sent before they joined",
         "[history-visibility][csaz-3][security][conformance]")
{
    GIVEN("a joined-visibility room with a message and a thread reply sent before bob joined")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room_with_visibility(rt, alice, "joined");
        auto const m1 = send_text(rt, alice, room_id, "vaultcombination7351");
        auto const reply1 = send_thread_reply(rt, alice, room_id, m1, "vault-thread-reply");
        invite_and_join(rt, alice, room_id, "bob", bob);
        auto const m2 = send_text(rt, alice, room_id, "afterbobjoined");

        WHEN("bob reads the room through /messages")
        {
            auto const reply = messages(rt, bob, room_id);

            THEN("M1 and its reply are absent and M2 is present")
            {
                REQUIRE(reply.status == 200U);
                auto const ids = event_ids_in(reply.body, "chunk");
                REQUIRE_FALSE(contains(ids, m1));
                REQUIRE_FALSE(contains(ids, reply1));
                REQUIRE(contains(ids, m2));
                REQUIRE(reply.body.find("vaultcombination7351") == std::string::npos);
            }
        }

        WHEN("bob requests M1 through /event and /context, and M2 through both")
        {
            auto const event = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + m1, bob);
            auto const context = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/context/" + m1, bob);
            auto const visible_event = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + m2, bob);
            auto const visible_context =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/context/" + m2 + "?limit=100", bob);

            THEN("M1 is refused with 404 M_NOT_FOUND and M2 is served without leaking M1")
            {
                REQUIRE(event.status == 404U);
                REQUIRE(string_field(event.body, "errcode") == "M_NOT_FOUND");
                REQUIRE(context.status == 404U);
                REQUIRE(string_field(context.body, "errcode") == "M_NOT_FOUND");
                REQUIRE(visible_event.status == 200U);
                REQUIRE(visible_context.status == 200U);
                auto const before_ids = event_ids_in(visible_context.body, "events_before");
                REQUIRE_FALSE(contains(before_ids, m1));
                REQUIRE_FALSE(contains(before_ids, reply1));
                REQUIRE(visible_context.body.find("vaultcombination7351") == std::string::npos);
            }
        }

        WHEN("bob searches for the text of M1 and of M2")
        {
            THEN("only M2 is found")
            {
                REQUIRE(search_count(rt, bob, "vaultcombination7351") == 0);
                REQUIRE(search_count(rt, bob, "afterbobjoined") == 1);
            }
        }

        WHEN("bob asks for the relations and the threads of M1")
        {
            auto const relations = call(rt, "GET", "/_matrix/client/v1/rooms/" + room_id + "/relations/" + m1, bob);
            auto const threads = call(rt, "GET", "/_matrix/client/v1/rooms/" + room_id + "/threads", bob);

            THEN("the parent is not found and no thread is listed")
            {
                REQUIRE(relations.status == 404U);
                REQUIRE(threads.status == 200U);
                REQUIRE(event_ids_in(threads.body, "chunk").empty());
                REQUIRE(threads.body.find("vault-thread-reply") == std::string::npos);
            }
        }

        WHEN("bob syncs")
        {
            auto const timeline = sync_timeline_ids(rt, bob, room_id);

            THEN("the join snapshot's timeline starts at what he may see")
            {
                REQUIRE_FALSE(contains(timeline, m1));
                REQUIRE_FALSE(contains(timeline, reply1));
                REQUIRE(contains(timeline, m2));
            }
        }

        WHEN("alice, who was joined throughout, reads the same room")
        {
            auto const ids = event_ids_in(messages(rt, alice, room_id).body, "chunk");

            THEN("she sees every message")
            {
                REQUIRE(contains(ids, m1));
                REQUIRE(contains(ids, reply1));
                REQUIRE(contains(ids, m2));
            }
        }
    }
}

// Spec: rule 3, "If history_visibility was set to shared, and the user joined the room at any
// point after the event was sent, allow." The default (no event, or a value not understood)
// is `shared`.
SCENARIO("With shared history visibility a newcomer reads everything sent before they joined",
         "[history-visibility][csaz-3][conformance]")
{
    GIVEN("a shared-visibility room with messages sent before bob joined")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room_with_visibility(rt, alice, "shared");
        auto const m1 = send_text(rt, alice, room_id, "sharedhistoryword");
        auto const reply1 = send_thread_reply(rt, alice, room_id, m1, "shared-thread-reply");
        invite_and_join(rt, alice, room_id, "bob", bob);

        WHEN("bob reads the room through every path")
        {
            auto const page = messages(rt, bob, room_id);
            auto const event = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + m1, bob);
            auto const context = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/context/" + m1, bob);
            auto const relations = call(rt, "GET", "/_matrix/client/v1/rooms/" + room_id + "/relations/" + m1, bob);
            auto const timeline = sync_timeline_ids(rt, bob, room_id);

            THEN("M1 is present on all of them")
            {
                REQUIRE(contains(event_ids_in(page.body, "chunk"), m1));
                REQUIRE(event.status == 200U);
                REQUIRE(context.status == 200U);
                REQUIRE(relations.status == 200U);
                REQUIRE(contains(event_ids_in(relations.body, "chunk"), reply1));
                REQUIRE(contains(timeline, m1));
                REQUIRE(search_count(rt, bob, "sharedhistoryword") == 1);
            }
        }
    }
}

// Spec: rule 4 and the `invited` description: "Events are accessible to newly joined members
// from the point they were invited onwards."
SCENARIO("With invited history visibility a newcomer reads from their invite onwards",
         "[history-visibility][csaz-3][conformance]")
{
    GIVEN("an invited-visibility room with a message before bob's invite and one between invite and join")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room_with_visibility(rt, alice, "invited");
        auto const before_invite = send_text(rt, alice, room_id, "before-the-invite");
        invite(rt, alice, room_id, "bob");
        auto const after_invite = send_text(rt, alice, room_id, "after-the-invite");
        join(rt, bob, room_id);
        auto const after_join = send_text(rt, alice, room_id, "after-the-join");

        WHEN("bob reads /messages")
        {
            auto const ids = event_ids_in(messages(rt, bob, room_id).body, "chunk");

            THEN("events from the invite onwards are visible and earlier ones are not")
            {
                REQUIRE_FALSE(contains(ids, before_invite));
                REQUIRE(contains(ids, after_invite));
                REQUIRE(contains(ids, after_join));
            }
        }

        WHEN("bob requests the earlier and the later event")
        {
            auto const early = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + before_invite, bob);
            auto const late = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + after_invite, bob);

            THEN("the earlier one is 404 and the later one is served")
            {
                REQUIRE(early.status == 404U);
                REQUIRE(late.status == 200U);
            }
        }
    }
}

// Spec: "All events while this is the m.room.history_visibility value may be shared ... with
// any authenticated user, regardless of whether they have ever joined the room", and the rules
// apply "with the state of the m.room.history_visibility event when the event in question is
// added to the DAG".
SCENARIO("World-readable history is readable without joining, and only while it was world-readable",
         "[history-visibility][csaz-3][conformance]")
{
    GIVEN("a room that was world-readable for one message and is then made joined-only for another")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const mallory = register_and_login(rt, "mallory");
        auto const room_id = create_room_with_visibility(rt, alice, "world_readable");
        auto const open_message = send_text(rt, alice, room_id, "said-in-public");

        WHEN("mallory, who never joined, reads the room")
        {
            auto const page = messages(rt, mallory, room_id);
            auto const event =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + open_message, mallory);
            auto const context =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/context/" + open_message, mallory);
            auto const initial = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/initialSync", mallory);

            THEN("/messages, /event, /context and initialSync serve the public history")
            {
                REQUIRE(page.status == 200U);
                REQUIRE(contains(event_ids_in(page.body, "chunk"), open_message));
                REQUIRE(event.status == 200U);
                REQUIRE(context.status == 200U);
                REQUIRE(initial.status == 200U);
            }
        }

        WHEN("mallory asks for the roster and the state, which the spec gives only to members")
        {
            auto const members = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members", mallory);
            auto const state = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state", mallory);

            THEN("both are 403")
            {
                REQUIRE(members.status == 403U);
                REQUIRE(state.status == 403U);
            }
        }

        WHEN("alice makes the room joined-only, says something private, and bob then joins")
        {
            set_visibility(rt, alice, room_id, "joined");
            auto const private_message = send_text(rt, alice, room_id, "said-in-private");
            invite_and_join(rt, alice, room_id, "bob", bob);

            THEN("bob sees the public message (rule 1 at its point) but not the private one")
            {
                auto const ids = event_ids_in(messages(rt, bob, room_id).body, "chunk");
                REQUIRE(contains(ids, open_message));
                REQUIRE_FALSE(contains(ids, private_message));
            }

            THEN("mallory, now that the room is no longer world-readable, is refused")
            {
                REQUIRE(messages(rt, mallory, room_id).status == 403U);
                REQUIRE(
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + open_message, mallory).status ==
                    403U);
            }
        }
    }
}

// Spec: "For m.room.history_visibility events themselves, the user should be allowed to see
// the event if the history_visibility before or after the event would allow them to see it."
SCENARIO("A history_visibility event is visible if the visibility before or after it allows",
         "[history-visibility][csaz-3][conformance]")
{
    GIVEN("a shared room that alice then makes joined-only, before bob joins")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room_with_visibility(rt, alice, "shared");
        set_visibility(rt, alice, room_id, "joined");
        auto const hidden = send_text(rt, alice, room_id, "joined-only-message");
        invite_and_join(rt, alice, room_id, "bob", bob);

        WHEN("bob reads /messages")
        {
            auto const reply = messages(rt, bob, room_id);

            THEN("the event that switched shared to joined is visible but the message sent under joined is not")
            {
                auto const ids = event_ids_in(reply.body, "chunk");
                auto const visibility_events = events_of_type(reply.body, "chunk", "m.room.history_visibility");
                REQUIRE(visibility_events.size() >= 1U);
                REQUIRE_FALSE(contains(ids, hidden));
            }
        }
    }
}

// Spec: "for the user's own m.room.member events, the user should be allowed to see the event
// if their membership before or after the event would allow them to see it. (For example, a
// user can always see m.room.member events which set their membership to join, or which change
// their membership from join to any other value, even if history_visibility is joined.)"
SCENARIO("A user always sees their own membership events that start or end their join",
         "[history-visibility][csaz-3][conformance]")
{
    GIVEN("a joined-only room that bob joined and then left")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room_with_visibility(rt, alice, "joined");
        invite_and_join(rt, alice, room_id, "bob", bob);
        leave(rt, bob, room_id);

        WHEN("bob reads /messages")
        {
            auto const reply = messages(rt, bob, room_id);

            THEN("his join and his leave are both in the chunk")
            {
                REQUIRE(reply.status == 200U);
                auto const members = events_of_type(reply.body, "chunk", "m.room.member");
                auto memberships = std::vector<std::string>{};
                auto const parsed = parse_object(reply.body);
                auto const* chunk = object_member_as_array(parsed, "chunk");
                REQUIRE(chunk != nullptr);
                for (auto const& value : *chunk)
                {
                    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                    auto const* state_key = event == nullptr ? nullptr : string_member(*event, "state_key");
                    auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
                    auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
                    if (state_key != nullptr && *state_key == user_id("bob") && membership != nullptr)
                    {
                        memberships.push_back(*membership);
                    }
                }
                REQUIRE(std::ranges::find(memberships, "join") != memberships.end());
                REQUIRE(std::ranges::find(memberships, "leave") != memberships.end());
                REQUIRE_FALSE(members.empty());
            }
        }
    }
}

// Spec: /messages `end`: "If no further events are available (either because we have reached
// the start of the timeline, or because the user does not have permission to see any more
// events), this property is omitted"; and "an empty chunk does not necessarily imply that no
// more events are available".
SCENARIO("A /messages page of invisible events still returns a token that advances",
         "[history-visibility][csaz-3][conformance]")
{
    GIVEN("a joined-only room whose history before bob's join is invisible to him")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        // A page examines at most this many events before it hands back a token, so a run of
        // hidden events longer than that gives an empty page whose `end` still moves on.
        rt.limits.max_messages_events_examined = 3U;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room_with_visibility(rt, alice, "joined");
        for (auto index = 0; index < 6; ++index)
        {
            std::ignore = send_text(rt, alice, room_id, "hidden-" + std::to_string(index));
        }
        invite_and_join(rt, alice, room_id, "bob", bob);
        std::ignore = send_text(rt, alice, room_id, "visible-after-join");

        WHEN("bob pages backwards one event at a time until the server stops returning a token")
        {
            auto from = std::string{};
            auto pages = 0;
            auto saw_empty_page_with_token = false;
            auto every_token_advanced = true;
            auto seen_hidden = false;
            for (; pages < 60; ++pages)
            {
                auto const query = from.empty() ? std::string{"?dir=b&limit=1"} : "?dir=b&limit=1&from=" + from;
                auto const reply = messages(rt, bob, room_id, query);
                REQUIRE(reply.status == 200U);
                seen_hidden = seen_hidden || reply.body.find("hidden-") != std::string::npos;
                auto const parsed = parse_object(reply.body);
                auto const* chunk = object_member_as_array(parsed, "chunk");
                REQUIRE(chunk != nullptr);
                auto const end = string_field(reply.body, "end");
                if (chunk->empty() && !end.empty())
                {
                    saw_empty_page_with_token = true;
                }
                if (end.empty())
                {
                    break;
                }
                if (!from.empty() && std::stoull(end) >= std::stoull(from))
                {
                    every_token_advanced = false;
                }
                from = end;
            }

            THEN("every token moves strictly backwards, the walk terminates, and no hidden message is returned")
            {
                REQUIRE(pages < 60);
                REQUIRE(every_token_advanced);
                REQUIRE_FALSE(seen_hidden);
            }

            THEN("a page whose events were all filtered out is an empty chunk with a token to continue from")
            {
                REQUIRE(saw_empty_page_with_token);
            }
        }
    }
}

// Spec: GET /context `state`: "The state of the room at the last event returned." For a user
// who has left, that point is one they were allowed to see.
SCENARIO("GET /context never returns state from after a departed user's leave",
         "[history-visibility][csaz-3][security][conformance]")
{
    GIVEN("a room where bob joined, saw a message, left, and the room was then renamed")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice);
        set_room_name(rt, alice, room_id, "Name while bob was here");
        invite_and_join(rt, alice, room_id, "bob", bob);
        auto const seen = send_text(rt, alice, room_id, "bob-saw-this");
        leave(rt, bob, room_id);
        auto const unseen = send_text(rt, alice, room_id, "bob-never-saw-this");
        set_room_name(rt, alice, room_id, "Name after bob left");

        WHEN("bob asks for the context of the message he saw")
        {
            auto const context =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/context/" + seen + "?limit=100", bob);

            THEN("later events and later state are not included")
            {
                REQUIRE(context.status == 200U);
                REQUIRE_FALSE(contains(event_ids_in(context.body, "events_after"), unseen));
                REQUIRE(context.body.find("bob-never-saw-this") == std::string::npos);
                REQUIRE(context.body.find("Name after bob left") == std::string::npos);
                REQUIRE(context.body.find("Name while bob was here") != std::string::npos);
            }
        }

        WHEN("bob asks for the event he never saw")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + unseen, bob);

            THEN("it is 404 M_NOT_FOUND")
            {
                REQUIRE(reply.status == 404U);
                REQUIRE(string_field(reply.body, "errcode") == "M_NOT_FOUND");
            }
        }
    }
}

// Spec: rule 2, "If the user's membership was join, allow." History stored before state groups
// existed (ADR-0064) has no recorded state, so the visibility at the time cannot be proved. Only
// rule 2, judged from the user's own membership timeline, applies: a user who was joined when the
// event was sent sees it under every visibility; anyone else does not, even when the room is
// `shared` now.
SCENARIO("History stored without a state group is visible only to users who were joined when it was sent",
         "[history-visibility][csaz-3][conformance][security]")
{
    GIVEN("a shared room whose events have lost their state groups, as rows written before ADR-0064 have")
    {
        auto started = merovingian::homeserver::start_client_server(visibility_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const dave = register_and_login(rt, "dave");
        auto const room_id = create_room_with_visibility(rt, alice, "shared");
        invite_and_join(rt, alice, room_id, "bob", bob);
        invite_and_join(rt, alice, room_id, "dave", dave);
        auto const while_joined = send_text(rt, alice, room_id, "sent-while-bob-and-dave-were-joined");
        leave(rt, dave, room_id);
        auto const after_dave_left = send_text(rt, alice, room_id, "sent-after-dave-left");
        invite_and_join(rt, alice, room_id, "carol", carol);
        rt.homeserver.database.persistent_store.event_state_groups.clear();

        WHEN("bob, who was joined throughout, reads /messages, /event and /sync")
        {
            auto const ids = event_ids_in(messages(rt, bob, room_id).body, "chunk");
            auto const event = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + while_joined, bob);
            auto const timeline = sync_timeline_ids(rt, bob, room_id);

            THEN("he sees both messages")
            {
                REQUIRE(contains(ids, while_joined));
                REQUIRE(contains(ids, after_dave_left));
                REQUIRE(event.status == 200U);
                REQUIRE(contains(timeline, while_joined));
            }
        }

        WHEN("carol, who joined afterwards, reads the room")
        {
            auto const ids = event_ids_in(messages(rt, carol, room_id).body, "chunk");
            auto const event = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + while_joined, carol);

            THEN("she sees neither, although the room is shared")
            {
                REQUIRE_FALSE(contains(ids, while_joined));
                REQUIRE_FALSE(contains(ids, after_dave_left));
                REQUIRE(event.status == 404U);
            }
        }

        WHEN("dave, who left before the second message, reads the room")
        {
            auto const ids = event_ids_in(messages(rt, dave, room_id).body, "chunk");

            THEN("he sees the message sent while he was joined and not the one after he left")
            {
                REQUIRE(contains(ids, while_joined));
                REQUIRE_FALSE(contains(ids, after_dave_left));
            }
        }
    }
}
