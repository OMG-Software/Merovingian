// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// What a left room's lazy-loaded `state` may read (ADR-0450). These are this server's choices, not spec rules: the spec
// says a user who left sees "the members of the room when you left" only for GET /members, and lazy-loading permits
// redundant members. The spec-mandated rules are in tests/conformance/test_lazy_load_members_conformance.cpp.
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

constexpr auto k_lazy_state = std::string_view{R"({"room":{"state":{"lazy_load_members":true}}})"};
constexpr auto k_left_lazy = std::string_view{R"({"room":{"include_leave":true,"state":{"lazy_load_members":true}}})"};

[[nodiscard]] auto lazy_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        in_memory_database_config(),
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

[[nodiscard]] auto user_id(std::string_view localpart) -> std::string
{
    return "@" + std::string{localpart} + ":example.org";
}

[[nodiscard]] auto register_user(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    auto const registered =
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.status == 200U);
    return *string_member(parse_object(registered.body), "access_token");
}

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    REQUIRE(created.status == 200U);
    return *string_member(parse_object(created.body), "room_id");
}

auto join_room(ClientServerRuntime& rt, std::string const& token, std::string const& room_id) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", token, "{}").status == 200U);
}

auto leave_room(ClientServerRuntime& rt, std::string const& token, std::string const& room_id) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", token, "{}").status == 200U);
}

auto say(ClientServerRuntime& rt, std::string const& token, std::string const& room_id, std::string const& text) -> void
{
    static auto counter = std::uint64_t{0U};
    auto const sent =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/lf" + std::to_string(++counter),
             token, R"({"msgtype":"m.text","body":")" + text + R"("})");
    REQUIRE(sent.status == 200U);
}

// Gives `member`, who must have joined, the power to ban, then has them ban `target`.
auto promote_and_ban(ClientServerRuntime& rt, std::string const& admin, std::string const& member_token,
                     std::string const& member, std::string const& target, std::string const& room_id) -> void
{
    auto const levels = std::string{R"({"users":{")"} + member + R"(":100}})";
    REQUIRE(
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.power_levels/", admin, levels).status ==
        200U);
    auto const ban = std::string{R"({"user_id":")"} + target + R"("})";
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", member_token, ban).status == 200U);
}

struct Synced final
{
    merovingian::canonicaljson::Object body{};
    std::string next_batch{};
};

[[nodiscard]] auto sync(ClientServerRuntime& rt, std::string const& token, std::string_view filter,
                        std::string const& since = {}) -> Synced
{
    auto target =
        std::string{"/_matrix/client/v3/sync?filter="} + merovingian::core::percent_encode_path_component(filter);
    if (!since.empty())
    {
        target += "&since=" + merovingian::core::percent_encode_path_component(since);
    }
    auto const reply = call(rt, "GET", target, token);
    REQUIRE(reply.status == 200U);
    auto body = parse_object(reply.body);
    auto next = *string_member(body, "next_batch");
    return {std::move(body), std::move(next)};
}

// The state_key of every m.room.member event in rooms.leave.<room_id>.state. The room must be in rooms.leave.
[[nodiscard]] auto left_state_members(Synced const& synced, std::string const& room_id) -> std::multiset<std::string>
{
    auto keys = std::multiset<std::string>{};
    auto const* rooms = object_member_as_object(synced.body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* left = object_member_as_object(*rooms, "leave");
    REQUIRE(left != nullptr);
    auto const* room = object_member_as_object(*left, room_id);
    REQUIRE(room != nullptr);
    auto const* state = object_member_as_object(*room, "state");
    auto const* events = state == nullptr ? nullptr : object_member_as_array(*state, "events");
    if (events == nullptr)
    {
        return keys;
    }
    for (auto const& entry : *events)
    {
        auto const& event = std::get<merovingian::canonicaljson::Object>(entry.storage());
        auto const* type = string_member(event, "type");
        auto const* key = string_member(event, "state_key");
        if (type != nullptr && *type == "m.room.member" && key != nullptr)
        {
            keys.insert(*key);
        }
    }
    return keys;
}

} // namespace

SCENARIO("A left room's limited lazy state names nobody who joined after the user left",
         "[integration][sync][lazy-sync][left-room-read]")
{
    GIVEN("dave, up to date, leaves; then carol joins and alice bans dave")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice);
        join_room(rt, bob, room);
        join_room(rt, dave, room);
        auto const initial = sync(rt, dave, k_lazy_state);
        say(rt, bob, room, "before dave left");
        leave_room(rt, dave, room);
        join_room(rt, carol, room);
        auto const ban_body = std::string{R"({"user_id":")"} + user_id("dave") + R"("})";
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room + "/ban", alice, ban_body).status == 200U);

        WHEN("dave's incremental sync has room for only the ban in its timeline")
        {
            auto const synced = sync(rt, dave,
                                     R"({"room":{"include_leave":true,"timeline":{"limit":1},)"
                                     R"("state":{"lazy_load_members":true}}})",
                                     initial.next_batch);

            THEN("carol, who joined after dave left, is not named")
            {
                REQUIRE_FALSE(left_state_members(synced, room).contains(user_id("carol")));
            }
        }
    }
}

SCENARIO("A left room's unlimited lazy state does not read past the leave for the sender of a later ban",
         "[integration][sync][lazy-sync][left-room-read]")
{
    GIVEN("dave has synced his leave; then carol joins, is promoted and bans dave")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const carol = register_user(rt, "carol");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice);
        join_room(rt, dave, room);
        std::ignore = sync(rt, dave, k_lazy_state);
        leave_room(rt, dave, room);
        auto const after_leave = sync(rt, dave, k_left_lazy);
        join_room(rt, carol, room);
        promote_and_ban(rt, alice, carol, user_id("carol"), user_id("dave"), room);

        WHEN("dave's next incremental sync carries only the ban, unlimited")
        {
            auto const synced = sync(rt, dave, k_left_lazy, after_leave.next_batch);

            THEN("carol's member event, from after dave left, is not in state")
            {
                REQUIRE_FALSE(left_state_members(synced, room).contains(user_id("carol")));
            }
        }
    }
}

SCENARIO("A left room's lazy state does not read past the leave when the state groups are lost",
         "[integration][sync][lazy-sync][left-room-read]")
{
    GIVEN("dave, up to date, leaves; carol joins, is promoted and bans dave; the state groups are lost")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const carol = register_user(rt, "carol");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice);
        join_room(rt, dave, room);
        auto const initial = sync(rt, dave, k_left_lazy);
        leave_room(rt, dave, room);
        join_room(rt, carol, room);
        promote_and_ban(rt, alice, carol, user_id("carol"), user_id("dave"), room);
        rt.homeserver.database.persistent_store.event_state_groups.clear();

        WHEN("dave's incremental sync's unlimited timeline runs from his leave to the ban")
        {
            auto const synced = sync(rt, dave, k_left_lazy, initial.next_batch);

            THEN("the lookup's fallback to the current member event does not name carol")
            {
                REQUIRE_FALSE(left_state_members(synced, room).contains(user_id("carol")));
            }
        }
    }
}

SCENARIO("A left room's lazy members survive state that cannot be rebuilt at the timeline's start",
         "[integration][sync][lazy-sync][left-room-read]")
{
    GIVEN("dave, up to date; then carol joins, bob speaks, dave leaves, and the recorded state groups are lost")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice);
        join_room(rt, bob, room);
        join_room(rt, dave, room);
        auto const initial = sync(rt, dave, k_lazy_state);
        say(rt, bob, room, "b1");
        join_room(rt, carol, room);
        say(rt, bob, room, "b2");
        say(rt, bob, room, "b3");
        leave_room(rt, dave, room);
        rt.homeserver.database.persistent_store.event_state_groups.clear();

        WHEN("dave's incremental sync has a limited timeline that leaves out the member events")
        {
            auto const synced = sync(rt, dave,
                                     R"({"room":{"include_leave":true,"timeline":{"limit":2,)"
                                     R"("not_types":["m.room.member"]},"state":{"lazy_load_members":true}}})",
                                     initial.next_batch);

            THEN("the timeline's sender and the member who changed in the gap are still sent")
            {
                auto const keys = left_state_members(synced, room);
                REQUIRE(keys.contains(user_id("bob")));
                REQUIRE(keys.contains(user_id("carol")));
            }
        }
    }
}
