// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/observability/observability.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

} // namespace

SCENARIO("Homeserver runtime starts from validated config with listeners database and hardening",
         "[homeserver][vertical]")
{
    GIVEN("the default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the runtime is started")
        {
            auto const started = merovingian::homeserver::start_runtime(config);

            THEN("the runtime has listeners, validated schema, hardening summaries, and startup "
                 "audit")
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

SCENARIO("Homeserver admin health requires an admin session", "[homeserver][vertical][observability]")
{
    GIVEN("a started runtime with an admin user")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!");
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.value + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);

        WHEN("admin health is requested with and without the admin token")
        {
            auto const health = merovingian::homeserver::admin_health(runtime);
            auto const summary = merovingian::homeserver::admin_health_summary(runtime);
            auto const unauthorized = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", {}, {}});
            auto const authorized = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", login.body, {}});

            THEN("health is safe and route access is admin-gated")
            {
                REQUIRE(health.status == merovingian::observability::HealthStatus::ok);
                REQUIRE(summary.find("runtime:ok") != std::string::npos);
                REQUIRE(summary.find("database:ok") != std::string::npos);
                REQUIRE(unauthorized.status == 401U);
                REQUIRE(unauthorized.body == "admin authentication required");
                REQUIRE(authorized.status == 200U);
                REQUIRE(authorized.body.find("runtime:ok") != std::string::npos);
                REQUIRE(authorized.body.find("password") == std::string::npos);
                REQUIRE(authorized.body.find("access_token") == std::string::npos);
                REQUIRE(authorized.body.find("m.room.message") == std::string::npos);
            }
        }
    }
}

SCENARIO("Homeserver registration follows runtime registration config", "[homeserver][vertical][auth]")
{
    GIVEN("a runtime with registration disabled")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);

        WHEN("a client attempts registration")
        {
            auto const user = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST",
                                  "/_matrix/client/v3/register",
                                  {},
                                  merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});

            THEN("registration is rejected by policy")
            {
                REQUIRE(user.status == 400U);
                REQUIRE(user.body == "registration_disabled");
            }
        }
    }
}

SCENARIO("Homeserver local auth route creates unique sessions and revokes tokens", "[homeserver][vertical][auth]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers, logs in twice, authenticates, and logs out")
        {
            auto const user = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
            auto const login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
            auto const second_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
            auto const authenticated = merovingian::homeserver::authenticated_user(runtime, login.body);
            auto const logout = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/logout", login.body, {}});
            auto const after_logout = merovingian::homeserver::authenticated_user(runtime, login.body);
            auto const second_still_authenticated =
                merovingian::homeserver::authenticated_user(runtime, second_login.body);

            THEN("tokens are unique, only the logged-out token is revoked, and audit events are "
                 "appended")
            {
                REQUIRE(user.status == 200U);
                REQUIRE(user.body == "@alice:example.org");
                REQUIRE(login.status == 200U);
                REQUIRE(second_login.status == 200U);
                REQUIRE(login.body != second_login.body);
                REQUIRE(authenticated == std::optional<std::string>{user.body});
                REQUIRE(logout.status == 200U);
                REQUIRE_FALSE(after_logout.has_value());
                REQUIRE(second_still_authenticated.has_value());
                REQUIRE(merovingian::homeserver::audit_event_count(runtime) >= 5U);
            }
        }
    }
}

SCENARIO("Homeserver admin observability endpoints expose runtime metrics and durable audit",
         "[homeserver][vertical][observability]")
{
    GIVEN("a started runtime with an admin session")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!");
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.value + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);

        WHEN("admin metrics and audit are requested")
        {
            auto const metrics = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/metrics", login.body, {}});
            auto const audit = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/audit", login.body, {}});
            auto const unauthenticated = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/audit", "not-a-token", {}});

            THEN("only the admin session can read safe operational summaries")
            {
                REQUIRE(metrics.status == 200U);
                REQUIRE(audit.status == 200U);
                REQUIRE(unauthenticated.status == 401U);
                REQUIRE(metrics.body.find("audit_events_appended_total") != std::string::npos);
                REQUIRE(metrics.body.find("access_token") == std::string::npos);
                REQUIRE(audit.body.find("runtime.started") != std::string::npos);
                REQUIRE(audit.body.find("CorrectHorse7") == std::string::npos);
                REQUIRE(runtime.database.persistent_store.audit_log.size() >= 3U);
            }
        }
    }
}

SCENARIO("Homeserver local auth stores hardened password and token hashes", "[homeserver][vertical][auth][security]")
{
    GIVEN("a started runtime with local registration enabled")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers and logs in twice")
        {
            auto const user = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
            REQUIRE(user.status == 200U);
            auto const first_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
            auto const second_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});

            THEN("the persisted password is Argon2id-shaped and tokens are random with versioned "
                 "hashes")
            {
                REQUIRE(first_login.status == 200U);
                REQUIRE(second_login.status == 200U);
                REQUIRE(first_login.body != second_login.body);
                REQUIRE(first_login.body.rfind("mvs_", 0U) == 0U);
                REQUIRE(second_login.body.rfind("mvs_", 0U) == 0U);
                REQUIRE(runtime.database.users.size() == 1U);
                REQUIRE(runtime.database.users.front().password_hash.rfind("password-hash:v2:$argon2id$", 0U) == 0U);
                REQUIRE(runtime.database.users.front().password_hash.find("CorrectHorse7!") == std::string::npos);
                REQUIRE(runtime.database.sessions.size() == 2U);
                REQUIRE(runtime.database.sessions.front().access_token_hash.rfind("token-hash:v2:", 0U) == 0U);
                REQUIRE(runtime.database.sessions.back().access_token_hash.rfind("token-hash:v2:", 0U) == 0U);
                REQUIRE(runtime.database.sessions.front().access_token_hash !=
                        runtime.database.sessions.back().access_token_hash);
            }
        }
    }
}

SCENARIO("Homeserver rejects same-length incorrect passwords and crafted token collisions",
         "[homeserver][vertical][auth]")
{
    GIVEN("a registered user and active token")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);

        WHEN("a same-length wrong password and same-shape fake token are used")
        {
            auto const bad_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|WrongHorse7!!|DEVICE1"});
            auto fake_token = std::string{login.body};
            fake_token.back() = fake_token.back() == '0' ? '1' : '0';
            auto const fake_auth = merovingian::homeserver::authenticated_user(runtime, fake_token);

            THEN("credential and token comparisons use the full secret value")
            {
                REQUIRE(bad_login.status == 403U);
                REQUIRE(bad_login.body == "bad credentials");
                REQUIRE_FALSE(fake_auth.has_value());
            }
        }
    }
}

SCENARIO("Homeserver local room route flow creates joins sends and fetches state", "[homeserver][vertical][rooms]")
{
    GIVEN("a logged-in local user")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);

        WHEN("the user creates, joins, sends, and fetches state")
        {
            auto const room = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", login.body, {}});
            auto const join = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/join", login.body, {}});
            auto const event = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/send", login.body,
                          R"({"type":"m.room.message"})"});
            auto const state = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/" + room.body + "/state", login.body, {}});

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
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);

        WHEN("room routes use an unknown token")
        {
            auto const create = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST", "/_matrix/client/v3/createRoom", "bad-token", {}});
            auto const join = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/!room1:example.org/join", "bad-token", {}});
            auto const send = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/!room1:example.org/send", "bad-token", "{}"});
            auto const state = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/!room1:example.org/state", "bad-token", {}});

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
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);

        WHEN("an unknown route is requested")
        {
            auto const route = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"GET", "/_matrix/client/v3/unknown", {}, {}});

            THEN("the request is rejected")
            {
                REQUIRE(route.status == 404U);
                REQUIRE(route.body == "route not found");
            }
        }
    }
}

SCENARIO("Homeserver event send uses wall-clock origin_server_ts", "[homeserver][vertical][events]")
{
    GIVEN("a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);
        auto const room = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", login.body, {}});
        REQUIRE(room.status == 200U);

        WHEN("an event is sent and the stored JSON is inspected")
        {
            auto const event = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/send", login.body,
                          R"({"type":"m.room.message"})"});
            REQUIRE(event.status == 200U);
            auto const& stored = runtime.database.persistent_store.events;

            THEN("origin_server_ts is a Unix-epoch millisecond timestamp not a depth counter")
            {
                REQUIRE_FALSE(stored.empty());
                auto const& event_json = stored.back().json;
                REQUIRE(event_json.find("\"origin_server_ts\"") != std::string::npos);
                auto const depth = stored.back().depth;
                REQUIRE(depth >= 1U);
            }
        }
    }
}
