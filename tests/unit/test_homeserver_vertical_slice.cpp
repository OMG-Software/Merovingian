// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/homeserver/vertical_slice.hpp>
#include <merovingian/observability/observability.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Homeserver runtime starts from validated config with listeners database and hardening", "[homeserver][vertical]")
{
    GIVEN("the default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the runtime is started")
        {
            auto const started = merovingian::homeserver::start_runtime(config);

            THEN("the runtime has listeners, validated schema, hardening summaries, and startup audit")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.started);
                REQUIRE(started.runtime.listeners.count() == 2U);
                REQUIRE(started.runtime.database.opened);
                REQUIRE(started.runtime.database.schema_validated);
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "users"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "rooms"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "events"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "audit_log"));
                REQUIRE(started.runtime.hardening.count() > 0U);
                REQUIRE(merovingian::homeserver::audit_event_count(started.runtime) == 1U);
            }
        }
    }
}

SCENARIO("Homeserver admin health exposes safe runtime status", "[homeserver][vertical][observability]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);

        WHEN("admin health is requested")
        {
            auto const health = merovingian::homeserver::admin_health(started.runtime);
            auto const summary = merovingian::homeserver::admin_health_summary(started.runtime);

            THEN("health is safe and does not expose credentials or event contents")
            {
                REQUIRE(health.status == merovingian::observability::HealthStatus::ok);
                REQUIRE(summary.find("runtime:ok") != std::string::npos);
                REQUIRE(summary.find("database:ok") != std::string::npos);
                REQUIRE(summary.find("password") == std::string::npos);
                REQUIRE(summary.find("access_token") == std::string::npos);
                REQUIRE(summary.find("m.room.message") == std::string::npos);
            }
        }
    }
}

SCENARIO("Homeserver local auth creates logs in sessions and revokes tokens", "[homeserver][vertical][auth]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers, logs in, authenticates, and logs out")
        {
            auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!");
            auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
            auto const authenticated = merovingian::homeserver::authenticated_user(runtime, login.value);
            auto const logout = merovingian::homeserver::logout_local_user(runtime, login.value);
            auto const after_logout = merovingian::homeserver::authenticated_user(runtime, login.value);

            THEN("the token works only before logout and audit events are appended")
            {
                REQUIRE(user.ok);
                REQUIRE(user.value == "@alice:example.org");
                REQUIRE(login.ok);
                REQUIRE(authenticated.has_value());
                REQUIRE(*authenticated == user.value);
                REQUIRE(logout.ok);
                REQUIRE_FALSE(after_logout.has_value());
                REQUIRE(merovingian::homeserver::audit_event_count(runtime) >= 4U);
            }
        }
    }
}

SCENARIO("Homeserver local room flow creates joins sends and fetches state", "[homeserver][vertical][rooms]")
{
    GIVEN("a logged-in local user")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!");
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("the user creates, joins, sends, and fetches state")
        {
            auto const room = merovingian::homeserver::create_room(runtime, login.value);
            auto const join = merovingian::homeserver::join_room(runtime, login.value, room.value);
            auto const event = merovingian::homeserver::send_event(runtime, login.value, room.value, R"({"type":"m.room.message"})");
            auto const state = merovingian::homeserver::fetch_room_state(runtime, login.value, room.value);

            THEN("the local room path succeeds and state includes member and event counts")
            {
                REQUIRE(room.ok);
                REQUIRE(room.value == "!room1:example.org");
                REQUIRE(join.ok);
                REQUIRE(event.ok);
                REQUIRE(state.ok);
                REQUIRE(state.value.find("room_id=!room1:example.org") != std::string::npos);
                REQUIRE(state.value.find("members=1") != std::string::npos);
                REQUIRE(state.value.find("events=1") != std::string::npos);
            }
        }
    }
}

SCENARIO("Homeserver rejects unauthenticated room operations", "[homeserver][vertical][security]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);

        WHEN("room operations use an unknown token")
        {
            auto const create = merovingian::homeserver::create_room(started.runtime, "bad-token");
            auto const join = merovingian::homeserver::join_room(started.runtime, "bad-token", "!room1:example.org");
            auto const send = merovingian::homeserver::send_event(started.runtime, "bad-token", "!room1:example.org", "{}");
            auto const state = merovingian::homeserver::fetch_room_state(started.runtime, "bad-token", "!room1:example.org");

            THEN("all protected room operations fail closed")
            {
                REQUIRE_FALSE(create.ok);
                REQUIRE(create.reason == "unauthenticated");
                REQUIRE_FALSE(join.ok);
                REQUIRE(join.reason == "unauthenticated");
                REQUIRE_FALSE(send.ok);
                REQUIRE(send.reason == "unauthenticated");
                REQUIRE_FALSE(state.ok);
                REQUIRE(state.reason == "unauthenticated");
            }
        }
    }
}
