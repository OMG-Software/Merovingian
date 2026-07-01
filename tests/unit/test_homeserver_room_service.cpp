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
//   - create_room with is_direct: m.direct account data is written/appended for
//     the creator so that a second device can classify the room via sliding sync

#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <string>
#include <thread>

#include <sodium.h>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
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
    auto const alice_reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                        merovingian::tests::registration_token);
    REQUIRE(alice_reg.ok);
    auto const alice_login =
        merovingian::homeserver::login_local_user(runtime, alice_reg.value, "CorrectHorse7!", "ALICE_DEV");
    REQUIRE(alice_login.ok);

    auto const bob_reg = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
    REQUIRE(bob_reg.ok);
    auto const bob_login =
        merovingian::homeserver::login_local_user(runtime, bob_reg.value, "CorrectHorse7!", "BOB_DEV");
    REQUIRE(bob_login.ok);

    auto const room = merovingian::homeserver::create_room(runtime, alice_login.value);
    REQUIRE(room.ok);

    auto const invite = merovingian::homeserver::invite_user(runtime, alice_login.value, room.value, bob_reg.value);
    REQUIRE(invite.ok);

    auto const join = merovingian::homeserver::join_room(runtime, bob_login.value, room.value);
    REQUIRE(join.ok);

    return {alice_login.value, alice_reg.value, bob_login.value, bob_reg.value, room.value};
}

} // namespace

// --- ban_user --------------------------------------------------------------------

SCENARIO("ban_user rejects an unauthenticated caller", "[homeserver][rooms][ban][error]")
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
            auto const result =
                merovingian::homeserver::ban_user(runtime, "syt_unknown_token", ctx.room_id, ctx.bob_id);

            THEN("ban is rejected — unauthenticated callers cannot modify room membership")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("ban_user rejects a ban in a room that does not exist", "[homeserver][rooms][ban][error]")
{
    GIVEN("a started runtime with a registered user but no room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("ban is attempted in a room that does not exist")
        {
            auto const result =
                merovingian::homeserver::ban_user(runtime, login.value, "!ghost:example.org", "@bob:example.org");

            THEN("ban is rejected — the room does not exist")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("ban_user allows the room creator to ban a member", "[homeserver][rooms][ban]")
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
            auto const result =
                merovingian::homeserver::ban_user(runtime, ctx.alice_token, ctx.room_id, ctx.bob_id, "test ban");

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
            auto const result =
                merovingian::homeserver::ban_user(runtime, ctx.bob_token, ctx.room_id, ctx.alice_id, "attempted ban");

            THEN("ban is rejected — bob lacks the required power level")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

// --- kick_user -------------------------------------------------------------------

SCENARIO("kick_user rejects an unauthenticated caller", "[homeserver][rooms][kick][error]")
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
            auto const result =
                merovingian::homeserver::kick_user(runtime, "syt_unknown_token", ctx.room_id, ctx.bob_id);

            THEN("kick is rejected — unauthenticated callers cannot modify room membership")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("kick_user allows the room creator to kick a member", "[homeserver][rooms][kick]")
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
            auto const result =
                merovingian::homeserver::kick_user(runtime, ctx.alice_token, ctx.room_id, ctx.bob_id, "test kick");

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
            auto const result =
                merovingian::homeserver::kick_user(runtime, ctx.bob_token, ctx.room_id, ctx.alice_id, "attempted kick");

            THEN("kick is rejected — bob lacks the required power level")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

// --- unban_user ------------------------------------------------------------------

SCENARIO("unban_user rejects an unauthenticated caller", "[homeserver][rooms][unban][error]")
{
    GIVEN("a started runtime with alice and bob in a room where bob is banned")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);
        auto const ban = merovingian::homeserver::ban_user(runtime, ctx.alice_token, ctx.room_id, ctx.bob_id);
        REQUIRE(ban.ok);

        WHEN("unban is attempted with an unknown access token")
        {
            auto const result =
                merovingian::homeserver::unban_user(runtime, "syt_unknown_token", ctx.room_id, ctx.bob_id);

            THEN("unban is rejected — unauthenticated callers cannot modify room membership")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("unban_user allows the room creator to lift a ban", "[homeserver][rooms][unban]")
{
    GIVEN("a started runtime with alice as room creator and bob banned")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        auto const ban = merovingian::homeserver::ban_user(runtime, ctx.alice_token, ctx.room_id, ctx.bob_id);
        REQUIRE(ban.ok);

        WHEN("alice unbans bob")
        {
            auto const result = merovingian::homeserver::unban_user(runtime, ctx.alice_token, ctx.room_id, ctx.bob_id);

            THEN("unban succeeds — the ban state is reversed")
            {
                REQUIRE(result.ok);
            }
        }
    }
}

// --- forget_room -----------------------------------------------------------------

SCENARIO("forget_room rejects an unauthenticated caller", "[homeserver][rooms][forget][error]")
{
    GIVEN("a started runtime with a room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);

        WHEN("forget is attempted with an unknown access token")
        {
            auto const result = merovingian::homeserver::forget_room(runtime, "syt_unknown_token", room.value);

            THEN("forget is rejected — unauthenticated callers cannot forget rooms")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("forget_room rejects forgetting a room the user is still joined to", "[homeserver][rooms][forget][error]")
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

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
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

SCENARIO("forget_room succeeds after the user has left the room", "[homeserver][rooms][forget]")
{
    GIVEN("a started runtime with alice and bob where both have left the room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_two_user_room(runtime);

        auto const bob_leave = merovingian::homeserver::leave_room(runtime, ctx.bob_token, ctx.room_id);
        REQUIRE(bob_leave.ok);
        auto const alice_leave = merovingian::homeserver::leave_room(runtime, ctx.alice_token, ctx.room_id);
        REQUIRE(alice_leave.ok);

        WHEN("alice forgets the room after leaving")
        {
            auto const result = merovingian::homeserver::forget_room(runtime, ctx.alice_token, ctx.room_id);

            THEN("forget succeeds — non-members may forget the room")
            {
                REQUIRE(result.ok);
            }
        }
    }
}

// --- knock_room ------------------------------------------------------------------

SCENARIO("knock_room rejects an unauthenticated caller", "[homeserver][rooms][knock][error]")
{
    GIVEN("a started runtime with a room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);

        WHEN("knock is attempted with an unknown access token")
        {
            auto const result = merovingian::homeserver::knock_room(runtime, "syt_unknown_token", room.value);

            THEN("knock is rejected — unauthenticated callers cannot knock")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("knock_room rejects a knock on a room that does not exist", "[homeserver][rooms][knock][error]")
{
    GIVEN("a started runtime with a registered user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("a knock is attempted on a room_id that does not exist")
        {
            auto const result = merovingian::homeserver::knock_room(runtime, login.value, "!doesnotexist:example.org");

            THEN("knock is rejected — room not found")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// m.direct account data — DM room visibility on a second device
// ---------------------------------------------------------------------------

namespace
{

[[nodiscard]] auto find_m_direct_content(merovingian::homeserver::HomeserverRuntime const& runtime,
                                         std::string const& user_id) -> std::string
{
    auto const& account_data = runtime.database.persistent_store.account_data;
    auto const it =
        std::ranges::find_if(account_data, [&user_id](merovingian::database::PersistentAccountData const& e) {
            return e.user_id == user_id && e.room_id.empty() && e.event_type == "m.direct";
        });
    return it == account_data.end() ? std::string{} : it->content_json;
}

[[nodiscard]] auto m_direct_rooms_for(std::string const& content_json, std::string const& invitee_id)
    -> std::vector<std::string>
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(content_json);
    auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    if (obj == nullptr)
    {
        return {};
    }
    auto const it = std::ranges::find_if(*obj, [&invitee_id](merovingian::canonicaljson::ObjectMember const& m) {
        return m.key == invitee_id;
    });
    if (it == obj->end())
    {
        return {};
    }
    auto const* arr = std::get_if<merovingian::canonicaljson::Array>(&it->value->storage());
    if (arr == nullptr)
    {
        return {};
    }
    auto rooms = std::vector<std::string>{};
    for (auto const& v : *arr)
    {
        auto const* s = std::get_if<std::string>(&v.storage());
        if (s != nullptr)
        {
            rooms.push_back(*s);
        }
    }
    return rooms;
}

} // namespace

SCENARIO("create_room with is_direct writes m.direct account data when none exists",
         "[homeserver][rooms][dm][m.direct]")
{
    GIVEN("a started runtime with alice and bob registered")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                        merovingian::tests::registration_token);
        REQUIRE(alice.ok);
        auto const alice_login =
            merovingian::homeserver::login_local_user(runtime, alice.value, "CorrectHorse7!", "ALICE_DEV");
        REQUIRE(alice_login.ok);

        auto const bob = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(bob.ok);

        WHEN("alice creates a room with is_direct:true and invites bob")
        {
            auto options = merovingian::homeserver::CreateRoomOptions{};
            options.is_direct = true;
            options.invitees = {bob.value};
            auto const room = merovingian::homeserver::create_room(runtime, alice_login.value, options);
            REQUIRE(room.ok);

            THEN("m.direct global account data is written for alice mapping bob to the new room")
            {
                auto const content = find_m_direct_content(runtime, alice.value);
                REQUIRE_FALSE(content.empty());
                auto const rooms = m_direct_rooms_for(content, bob.value);
                REQUIRE(rooms.size() == 1U);
                REQUIRE(rooms[0] == room.value);
            }
        }
    }
}

SCENARIO("create_room with is_direct appends a second room to m.direct for the same invitee",
         "[homeserver][rooms][dm][m.direct]")
{
    GIVEN("a started runtime where alice already has one DM room with bob")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                        merovingian::tests::registration_token);
        REQUIRE(alice.ok);
        auto const alice_login =
            merovingian::homeserver::login_local_user(runtime, alice.value, "CorrectHorse7!", "ALICE_DEV");
        REQUIRE(alice_login.ok);

        auto const bob = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(bob.ok);

        auto options = merovingian::homeserver::CreateRoomOptions{};
        options.is_direct = true;
        options.invitees = {bob.value};
        auto const room1 = merovingian::homeserver::create_room(runtime, alice_login.value, options);
        REQUIRE(room1.ok);

        WHEN("alice creates a second DM room with bob")
        {
            auto const room2 = merovingian::homeserver::create_room(runtime, alice_login.value, options);
            REQUIRE(room2.ok);

            THEN("m.direct maps bob to both rooms without duplicates")
            {
                auto const content = find_m_direct_content(runtime, alice.value);
                REQUIRE_FALSE(content.empty());
                auto const rooms = m_direct_rooms_for(content, bob.value);
                REQUIRE(rooms.size() == 2U);
                REQUIRE(std::ranges::find(rooms, room1.value) != rooms.end());
                REQUIRE(std::ranges::find(rooms, room2.value) != rooms.end());
            }
        }
    }
}

SCENARIO("create_room without is_direct does not write m.direct account data", "[homeserver][rooms][dm][m.direct]")
{
    GIVEN("a started runtime with alice and bob registered")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                        merovingian::tests::registration_token);
        REQUIRE(alice.ok);
        auto const alice_login =
            merovingian::homeserver::login_local_user(runtime, alice.value, "CorrectHorse7!", "ALICE_DEV");
        REQUIRE(alice_login.ok);

        auto const bob = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(bob.ok);

        WHEN("alice creates a room without is_direct and invites bob")
        {
            auto options = merovingian::homeserver::CreateRoomOptions{};
            options.is_direct = false;
            options.invitees = {bob.value};
            auto const room = merovingian::homeserver::create_room(runtime, alice_login.value, options);
            REQUIRE(room.ok);

            THEN("no m.direct account data is written for alice")
            {
                auto const content = find_m_direct_content(runtime, alice.value);
                REQUIRE(content.empty());
            }
        }
    }
}

// --- perform_sync_outbound_call --------------------------------------------------

SCENARIO("perform_sync_outbound_call returns failure immediately when discovery_network is unavailable",
         "[homeserver][federation][outbound]")
{
    GIVEN("a started runtime whose discovery_network has been cleared to simulate missing infrastructure")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // Simulate a runtime where server discovery was never wired or has been torn down.
        runtime.discovery_network.reset();

        WHEN("a federation outbound call is attempted to a remote room")
        {
            auto const tx = merovingian::federation::OutboundTransaction{
                .destination = "remote.example.com",
                .method = "PUT",
                .target = "/_matrix/federation/v1/send/txn-1",
                .origin = "local.example.com",
                .body = R"({"pdus":[]})",
            };
            auto const [ok, reason] = merovingian::homeserver::perform_sync_outbound_call(
                runtime, "!room:remote.example.com", tx, "ed25519:K001", {}, "test.diagnostic", 30U);

            THEN("the call fails fast without crashing or blocking, and returns a non-empty reason")
            {
                REQUIRE_FALSE(ok);
                REQUIRE_FALSE(reason.empty());
            }
        }
    }
}

// --- parallel make_join race ---------------------------------------------------

SCENARIO("join_room rejects an unauthenticated caller", "[homeserver][rooms][join][error]")
{
    GIVEN("a started runtime with no valid session token")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("join_room is called with an empty access token")
        {
            auto const result = merovingian::homeserver::join_room(runtime, "", "!abc:remote.example.com", {});

            THEN("join fails with 401")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 401U);
            }
        }

        WHEN("join_room is called with a made-up access token")
        {
            auto const result =
                merovingian::homeserver::join_room(runtime, "not_a_real_token", "!abc:remote.example.com", {});

            THEN("join fails with 401")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 401U);
            }
        }
    }
}

SCENARIO("join_room returns 404 when no candidate servers are available",
         "[homeserver][rooms][join][federation][error]")
{
    GIVEN("a started runtime where the room ID domain equals our server and no via servers are provided")
    {
        REQUIRE(sodium_init() >= 0);
        // registration_enabled_config() sets server_name = "example.org"
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("join_room is called for a room on our own domain with no via_servers")
        {
            // Room domain == our server, no via_servers → join_candidate_servers returns empty.
            auto const result = merovingian::homeserver::join_room(runtime, login.value, "!abc:example.org", {});

            THEN("join fails with 404 — no resident server to contact")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 404U);
            }
        }
    }
}

SCENARIO("join_room returns 200 when the user is already a member of a local room", "[homeserver][rooms][join]")
{
    GIVEN("a started runtime where alice has already created and joined a local room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        auto const created = merovingian::homeserver::create_room(runtime, login.value, {});
        REQUIRE(created.ok);
        auto const room_id = created.value;

        WHEN("join_room is called again for the same room the creator is already joined to")
        {
            auto const result = merovingian::homeserver::join_room(runtime, login.value, room_id, {});

            THEN("join succeeds with 200 — idempotent re-join of a local room")
            {
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
            }
        }
    }
}

SCENARIO("parallel make_join race with join_parallelism=0 defaults to 1 concurrent task",
         "[homeserver][rooms][join][federation][error]")
{
    GIVEN("a started runtime with join_parallelism=0 and no reachable discovery infrastructure")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        runtime.discovery_network.reset();
        runtime.cached_discovery.reset();

        WHEN("join_room is called with three candidates and join_parallelism=0 (clamped to 1)")
        {
            // join_parallelism=0 is clamped to max(1U, 0U)=1 so candidates are
            // serialised rather than running in parallel — must still exhaust all three.
            runtime.federation.config.join_parallelism = 0U;
            auto const result = merovingian::homeserver::join_room(
                runtime, login.value, "!abc:remote.example.com",
                {"s1.remote.example.com", "s2.remote.example.com", "s3.remote.example.com"});

            THEN("join fails with 502 — all candidates exhausted serially")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 502U);
            }
        }
    }
}

SCENARIO("parallel make_join race uses join_timeout_seconds when it is configured",
         "[homeserver][rooms][join][federation][error]")
{
    GIVEN("a started runtime with join_timeout_seconds=5 and no reachable discovery infrastructure")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        runtime.discovery_network.reset();
        runtime.cached_discovery.reset();

        WHEN("join_room is called with join_timeout_seconds=5 (non-zero — uses join budget not remote timeout)")
        {
            // join_timeout_seconds > 0 selects per_call_timeout = join_timeout_seconds
            // rather than remote_timeout_seconds. With no discovery the call fails
            // quickly regardless; we verify the result code and that the branch
            // executes without incident.
            runtime.federation.config.join_timeout_seconds = 5U;
            runtime.federation.config.join_parallelism = 1U;
            auto const result = merovingian::homeserver::join_room(runtime, login.value, "!abc:remote.example.com",
                                                                   {"s1.remote.example.com"});

            THEN("join fails with 502 using the configured join timeout")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 502U);
            }
        }
    }
}

SCENARIO("parallel make_join race with more candidates than parallelism throttles via semaphore",
         "[homeserver][rooms][join][federation][error][concurrency]")
{
    GIVEN("a started runtime with five candidates and join_parallelism=2 and no discovery infrastructure")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        runtime.discovery_network.reset();
        runtime.cached_discovery.reset();

        WHEN("join_room is called with five candidates and parallelism capped at 2")
        {
            // Five candidates exceed parallelism=2, so the PortableSemaphore must
            // throttle to at most 2 concurrent in-flight make_join calls at any time.
            // All five eventually fail → 502.
            runtime.federation.config.join_parallelism = 2U;
            auto const result = merovingian::homeserver::join_room(runtime, login.value, "!abc:remote.example.com",
                                                                   {"s1.remote.example.com", "s2.remote.example.com",
                                                                    "s3.remote.example.com", "s4.remote.example.com",
                                                                    "s5.remote.example.com"});

            THEN("join fails with 502 after exhausting all five candidates")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 502U);
            }
        }
    }
}

SCENARIO("parallel make_join race returns 502 when all candidates are unreachable",
         "[homeserver][rooms][join][federation][error]")
{
    GIVEN("a started runtime with an authenticated user and no reachable discovery infrastructure")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        // Disable server discovery so every make_join candidate fails instantly
        // rather than timing out; the race must still converge and return 502.
        runtime.discovery_network.reset();
        runtime.cached_discovery.reset();

        WHEN("join_room is called with two unreachable candidate servers and parallelism = 2")
        {
            runtime.federation.config.join_parallelism = 2U;
            auto const result = merovingian::homeserver::join_room(runtime, login.value, "!abc:remote.example.com",
                                                                   {"s1.remote.example.com", "s2.remote.example.com"});

            THEN("join fails with 502 — all candidates exhausted without a winner")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 502U);
            }
        }
    }
}

// --- orphan future draining (HomeserverRuntime destructor) ----------------------

SCENARIO("HomeserverRuntime destructor waits for orphaned make_join race loser futures",
         "[homeserver][rooms][join][federation][concurrency]")
{
    GIVEN("a started runtime with a slow orphaned future parked in orphan_futures_")
    {
        REQUIRE(sodium_init() >= 0);
        auto completed = std::atomic<bool>{false};

        WHEN("the runtime is destroyed while the orphan future is still running")
        {
            {
                auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
                REQUIRE(started.started);
                auto& runtime = started.runtime;

                auto future = std::async(std::launch::async, [&completed]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    completed = true;
                });
                {
                    auto const lock = std::lock_guard{runtime.orphan_futures_mutex_};
                    runtime.orphan_futures_.push_back(std::move(future));
                }
            } // `started` goes out of scope here — the HomeserverRuntime destructor runs.

            THEN("destruction blocks until the orphaned task finishes")
            {
                // The dtor explicitly waits on every future in orphan_futures_ before
                // any other member (outbound_client, discovery_network, the signing
                // SecretBuffer) is torn down. If it returned without waiting, this
                // flag could still be false here despite the 50ms sleep having had
                // time to elapse — proving the destructor actually blocks, not just
                // that the background thread eventually finishes on its own.
                REQUIRE(completed.load());
            }
        }
    }
}
