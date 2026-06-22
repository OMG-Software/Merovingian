// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Error, boundary, and anomaly tests for room_service functions not covered
// by test_homeserver_vertical_slice.cpp or test_client_server.cpp.
//
// Coverage:
//   - ban_user: unauthenticated rejected; non-existent room rejected; creator
//     can ban a member; non-privileged member cannot ban
//   - kick_user: unauthenticated rejected; creator can kick a member;
//     non-privileged member cannot kick
//   - unban_user: unauthenticated rejected; creator can unban after a ban
//   - forget_room: unauthenticated rejected; forget while still joined rejected;
//     forget succeeds after leaving
//   - knock_room: unauthenticated rejected; non-existent room rejected

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

#include <sodium.h>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

struct TwoUserRoom
{
    std::string alice_token{};
    std::string alice_id{};
    std::string bob_token{};
    std::string bob_id{};
    std::string room_id{};
};

// Registers alice (room creator) and bob (invited + joined member).
[[nodiscard]] auto make_two_user_room(merovingian::homeserver::HomeserverRuntime& runtime) -> TwoUserRoom
{
    auto const alice_reg = merovingian::homeserver::register_local_user(
        runtime, "alice", "CorrectHorse7!", merovingian::tests::registration_token);
    REQUIRE(alice_reg.ok);
    auto const alice_login = merovingian::homeserver::login_local_user(
        runtime, alice_reg.value, "CorrectHorse7!", "ALICE_DEV");
    REQUIRE(alice_login.ok);

    auto const bob_reg = merovingian::homeserver::register_local_user(
        runtime, "bob", "CorrectHorse7!", merovingian::tests::registration_token);
    REQUIRE(bob_reg.ok);
    auto const bob_login = merovingian::homeserver::login_local_user(
        runtime, bob_reg.value, "CorrectHorse7!", "BOB_DEV");
    REQUIRE(bob_login.ok);

    auto const room = merovingian::homeserver::create_room(runtime, alice_login.value);
    REQUIRE(room.ok);

    auto const invite = merovingian::homeserver::invite_user(
        runtime, alice_login.value, room.value, bob_reg.value);
    REQUIRE(invite.ok);

    auto const join = merovingian::homeserver::join_room(runtime, bob_login.value, room.value);
    REQUIRE(join.ok);

    return {alice_login.value, alice_reg.value, bob_login.value, bob_reg.value, room.value};
}

} // namespace

// --- ban_user --------------------------------------------------------------------

SCENARIO("ban_user rejects an unauthenticated caller",
         "[homeserver][rooms][ban][error]")
{
    GIVEN("a started runtime with alice and bob in a room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        WHEN("ban is attempted with an unknown access token")
        {
            auto const result = merovingian::homeserver::ban_user(
                runtime, "syt_unknown_token", ctx.room_id, ctx.bob_id);

            THEN("ban is rejected — unauthenticated callers cannot modify room membership")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("ban_user rejects a ban in a room that does not exist",
         "[homeserver][rooms][ban][error]")
{
    GIVEN("a started runtime with a registered user but no room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(
            runtime, "alice", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(
            runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("ban is attempted in a room that does not exist")
        {
            auto const result = merovingian::homeserver::ban_user(
                runtime, login.value, "!ghost:example.org", "@bob:example.org");

            THEN("ban is rejected — the room does not exist")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("ban_user allows the room creator to ban a member",
         "[homeserver][rooms][ban]")
{
    GIVEN("a started runtime with alice (room creator) and bob (member)")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        WHEN("alice bans bob from the room")
        {
            auto const result = merovingian::homeserver::ban_user(
                runtime, ctx.alice_token, ctx.room_id, ctx.bob_id, "test ban");

            THEN("the ban succeeds — room creator has sufficient power level")
            {
                REQUIRE(result.ok);
            }
        }
    }
}

SCENARIO("ban_user prevents a non-privileged member from banning another member",
         "[homeserver][rooms][ban][error][security]")
{
    GIVEN("a started runtime where bob is a regular member without ban power")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        WHEN("bob attempts to ban alice (the room creator)")
        {
            auto const result = merovingian::homeserver::ban_user(
                runtime, ctx.bob_token, ctx.room_id, ctx.alice_id, "attempted ban");

            THEN("ban is rejected — bob lacks the required power level")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

// --- kick_user -------------------------------------------------------------------

SCENARIO("kick_user rejects an unauthenticated caller",
         "[homeserver][rooms][kick][error]")
{
    GIVEN("a started runtime with alice and bob in a room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        WHEN("kick is attempted with an unknown access token")
        {
            auto const result = merovingian::homeserver::kick_user(
                runtime, "syt_unknown_token", ctx.room_id, ctx.bob_id);

            THEN("kick is rejected — unauthenticated callers cannot modify room membership")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("kick_user allows the room creator to kick a member",
         "[homeserver][rooms][kick]")
{
    GIVEN("a started runtime with alice (room creator) and bob (member)")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        WHEN("alice kicks bob from the room")
        {
            auto const result = merovingian::homeserver::kick_user(
                runtime, ctx.alice_token, ctx.room_id, ctx.bob_id, "test kick");

            THEN("the kick succeeds — room creator has sufficient power level")
            {
                REQUIRE(result.ok);
            }
        }
    }
}

SCENARIO("kick_user prevents a non-privileged member from kicking another member",
         "[homeserver][rooms][kick][error][security]")
{
    GIVEN("a started runtime where bob is a regular member without kick power")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        WHEN("bob attempts to kick alice (the room creator)")
        {
            auto const result = merovingian::homeserver::kick_user(
                runtime, ctx.bob_token, ctx.room_id, ctx.alice_id, "attempted kick");

            THEN("kick is rejected — bob lacks the required power level")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

// --- unban_user ------------------------------------------------------------------

SCENARIO("unban_user rejects an unauthenticated caller",
         "[homeserver][rooms][unban][error]")
{
    GIVEN("a started runtime with alice and bob in a room where bob is banned")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);
        auto const ban = merovingian::homeserver::ban_user(
            runtime, ctx.alice_token, ctx.room_id, ctx.bob_id);
        REQUIRE(ban.ok);

        WHEN("unban is attempted with an unknown access token")
        {
            auto const result = merovingian::homeserver::unban_user(
                runtime, "syt_unknown_token", ctx.room_id, ctx.bob_id);

            THEN("unban is rejected — unauthenticated callers cannot modify room membership")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("unban_user allows the room creator to lift a ban",
         "[homeserver][rooms][unban]")
{
    GIVEN("a started runtime with alice as room creator and bob banned")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        auto const ban = merovingian::homeserver::ban_user(
            runtime, ctx.alice_token, ctx.room_id, ctx.bob_id);
        REQUIRE(ban.ok);

        WHEN("alice unbans bob")
        {
            auto const result = merovingian::homeserver::unban_user(
                runtime, ctx.alice_token, ctx.room_id, ctx.bob_id);

            THEN("unban succeeds — the ban state is reversed")
            {
                REQUIRE(result.ok);
            }
        }
    }
}

// --- forget_room -----------------------------------------------------------------

SCENARIO("forget_room rejects an unauthenticated caller",
         "[homeserver][rooms][forget][error]")
{
    GIVEN("a started runtime with a room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(
            runtime, "alice", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(
            runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);

        WHEN("forget is attempted with an unknown access token")
        {
            auto const result = merovingian::homeserver::forget_room(
                runtime, "syt_unknown_token", room.value);

            THEN("forget is rejected — unauthenticated callers cannot forget rooms")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("forget_room rejects forgetting a room the user is still joined to",
         "[homeserver][rooms][forget][error]")
{
    // Spec: Matrix Client-Server API v1.18
    // A joined user cannot forget a room they are still a member of.
    // URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidforget
    GIVEN("a started runtime with alice still joined to a room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(
            runtime, "alice", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(
            runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);

        WHEN("alice tries to forget the room without leaving first")
        {
            auto const result = merovingian::homeserver::forget_room(runtime, login.value, room.value);

            THEN("forget is rejected — a joined member cannot forget a room")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("forget_room succeeds after the user has left the room",
         "[homeserver][rooms][forget]")
{
    GIVEN("a started runtime with alice and bob where both have left the room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        auto const bob_leave = merovingian::homeserver::leave_room(
            runtime, ctx.bob_token, ctx.room_id);
        REQUIRE(bob_leave.ok);
        auto const alice_leave = merovingian::homeserver::leave_room(
            runtime, ctx.alice_token, ctx.room_id);
        REQUIRE(alice_leave.ok);

        WHEN("alice forgets the room after leaving")
        {
            auto const result = merovingian::homeserver::forget_room(
                runtime, ctx.alice_token, ctx.room_id);

            THEN("forget succeeds — non-members may forget the room")
            {
                REQUIRE(result.ok);
            }
        }
    }
}

// --- knock_room ------------------------------------------------------------------

SCENARIO("knock_room rejects an unauthenticated caller",
         "[homeserver][rooms][knock][error]")
{
    GIVEN("a started runtime with a room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(
            runtime, "alice", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(
            runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);

        WHEN("knock is attempted with an unknown access token")
        {
            auto const result = merovingian::homeserver::knock_room(
                runtime, "syt_unknown_token", room.value);

            THEN("knock is rejected — unauthenticated callers cannot knock")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("knock_room rejects a knock on a room that does not exist",
         "[homeserver][rooms][knock][error]")
{
    GIVEN("a started runtime with a registered user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(
            runtime, "alice", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(
            runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("a knock is attempted on a room_id that does not exist")
        {
            auto const result = merovingian::homeserver::knock_room(
                runtime, login.value, "!doesnotexist:example.org");

            THEN("knock is rejected — room not found")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}
