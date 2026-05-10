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
            auto const route = merovingian::homeserver::handle_local_http_request(
                started.runtime,
                {"GET", "/_merovingian/admin/health", {}, {}}
            );

            THEN("health is safe and does not expose credentials or event contents")
            {
                REQUIRE(health.status == merovingian::observability::HealthStatus::ok);
                REQUIRE(summary.find("runtime:ok") != std::string::npos);
                REQUIRE(summary.find("database:ok") != std::string::npos);
                REQUIRE(route.status == 200U);
                REQUIRE(route.body.find("runtime:ok") != std::string::npos);
                REQUIRE(route.body.find("password") == std::string::npos);
                REQUIRE(route.body.find("access_token") == std::string::npos);
                REQUIRE(route.body.find("m.room.message") == std::string::npos);
            }
        }
    }
}

SCENARIO("Homeserver local auth route creates logs in sessions and revokes tokens", "[homeserver][vertical][auth]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers, logs in, authenticates, and logs out through local routes")
        {
            auto const user = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"}
            );
            auto const login = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"}
            );
            auto const authenticated = merovingian::homeserver::authenticated_user(runtime, login.body);
            auto const logout = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/client/v3/logout", login.body, {}}
            );
            auto const after_logout = merovingian::homeserver::authenticated_user(runtime, login.body);

            THEN("the token works only before logout and audit events are appended")
            {
                REQUIRE(user.status == 200U);
                REQUIRE(user.body == "@alice:example.org");
                REQUIRE(login.status == 200U);
                REQUIRE(authenticated.has_value());
                REQUIRE(*authenticated == user.body);
                REQUIRE(logout.status == 200U);
                REQUIRE_FALSE(after_logout.has_value());
                REQUIRE(merovingian::homeserver::audit_event_count(runtime) >= 4U);
            }
        }
    }
}

SCENARIO("Homeserver local room route flow creates joins sends and fetches state", "[homeserver][vertical][rooms]")
{
    GIVEN("a logged-in local user")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime,
            {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"}
        );
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"}
        );
        REQUIRE(login.status == 200U);

        WHEN("the user creates, joins, sends, and fetches state")
        {
            auto const room = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/client/v3/createRoom", login.body, {}}
            );
            auto const join = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room.body + "/join", login.body, {}}
            );
            auto const event = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room.body + "/send", login.body, R"({"type":"m.room.message"})"}
            );
            auto const state = merovingian::homeserver::handle_local_http_request(
                runtime,
                {"GET", "/_matrix/client/v3/rooms/" + room.body + "/state", login.body, {}}
            );

            THEN("the local room path succeeds and state includes member and event counts")
            {
                REQUIRE(room.status == 200U);
                REQUIRE(room.body == "!room1:example.org");
                REQUIRE(join.status == 200U);
                REQUIRE(event.status == 200U);
                REQUIRE(state.status == 200U);
                REQUIRE(state.body.find("room_id=!room1:example.org") != std::string::npos);
                REQUIRE(state.body.find("members=1") != std::string::npos);
                REQUIRE(state.body.find("events=1") != std::string::npos);
            }
        }
    }
}

SCENARIO("Homeserver rejects unauthenticated room route operations", "[homeserver][vertical][security]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);

        WHEN("room routes use an unknown token")
        {
            auto const create = merovingian::homeserver::handle_local_http_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/createRoom", "bad-token", {}}
            );
            auto const join = merovingian::homeserver::handle_local_http_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/!room1:example.org/join", "bad-token", {}}
            );
            auto const send = merovingian::homeserver::handle_local_http_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/!room1:example.org/send", "bad-token", "{}"}
            );
            auto const state = merovingian::homeserver::handle_local_http_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/rooms/!room1:example.org/state", "bad-token", {}}
            );

            THEN("all protected room route operations fail closed")
            {
                REQUIRE(create.status == 401U);
                REQUIRE(create.body == "unauthenticated");
                REQUIRE(join.status == 401U);
                REQUIRE(join.body == "unauthenticated");
                REQUIRE(send.status == 401U);
                REQUIRE(send.body == "unauthenticated");
                REQUIRE(state.status == 401U);
                REQUIRE(state.body == "unauthenticated");
            }
        }
    }
}

SCENARIO("Homeserver local route dispatcher rejects unknown routes", "[homeserver][vertical][routing]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);

        WHEN("an unknown route is requested")
        {
            auto const route = merovingian::homeserver::handle_local_http_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/unknown", {}, {}}
            );

            THEN("the request is rejected")
            {
                REQUIRE(route.status == 404U);
                REQUIRE(route.body == "route not found");
            }
        }
    }
}
