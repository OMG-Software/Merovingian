// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"

#include <catch2/catch_test_macros.hpp>

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
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
};
}

} // namespace

SCENARIO("Integrated client-server flow covers auth devices rooms state joined rooms sync and logout",
         "[homeserver][client-server][integration]")
{
    GIVEN("registration-enabled client-server config")
    {
        auto const config = registration_enabled_config();

        WHEN("the client-server flow is run")
        {
            auto const result = merovingian::homeserver::run_client_server_flow(config);

            THEN("the flow completes and sync returns full event content")
            {
                REQUIRE(result.ok);
                REQUIRE(result.value.find("next_batch") != std::string::npos);
                REQUIRE(result.value.find("event_count") != std::string::npos);
                // Matrix E2EE: m.room.encrypted events are relayed opaquely
                // through /sync — clients decrypt locally.
                REQUIRE(result.value.find("m.room.encrypted") != std::string::npos);
            }
        }
    }
}

SCENARIO("Integrated client-server flow fails closed on invalid config", "[homeserver][client-server][integration]")
{
    GIVEN("an invalid listener config")
    {
        auto listeners = merovingian::config::ListenersConfig{};
        listeners.client.bind = "0.0.0.0:not-a-port";
        auto const config = merovingian::config::Config {
            merovingian::config::ServerConfig{},
            listeners,
            merovingian::config::DatabaseConfig{},
            merovingian::config::SecurityConfig{},
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{},
};

        WHEN("the client-server flow is run")
        {
            auto const result = merovingian::homeserver::run_client_server_flow(config);

            THEN("startup fails before serving API requests")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason == "configuration is invalid");
            }
        }
    }
}

SCENARIO("POST /register without auth returns 401 UI-auth challenge", "[homeserver][client-server][register][uiauth]")
{
    GIVEN("a registration-enabled server")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a client sends a register request without an auth field")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"username":"alice","password":"CorrectHorse7!"})"});

            THEN("the server returns 401 with the registration_token flow and a session")
            {
                REQUIRE(response.response.status == 401U);
                REQUIRE(response.response.body.find("m.login.registration_token") != std::string::npos);
                REQUIRE(response.response.body.find("flows") != std::string::npos);
                REQUIRE(response.response.body.find("session") != std::string::npos);
            }
        }
    }
}

SCENARIO("POST /register with auth completes registration", "[homeserver][client-server][register][uiauth]")
{
    GIVEN("a registration-enabled server")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a client sends a register request with a valid auth token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!")});

            THEN("the server returns 200 with the new user_id")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("user_id") != std::string::npos);
                REQUIRE(response.response.body.find("@alice:") != std::string::npos);
            }
        }
    }
}

SCENARIO("POST /account/password changes the authenticated user's password",
         "[homeserver][client-server][account][password]")
{
    GIVEN("a registered and logged-in user")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const value_begin = begin + key.size();
        auto const value_end = login.response.body.find('"', value_begin);
        auto const token = login.response.body.substr(value_begin, value_end - value_begin);

        WHEN("the user changes their password")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST",
                 "/_matrix/client/v3/account/password",
                 token,
                 R"({"new_password":"NewHorse99!!"})"});

            THEN("the server returns 200 and the new password is accepted at login")
            {
                REQUIRE(response.response.status == 200U);
                auto const relogin = merovingian::homeserver::handle_client_server_request(
                    rt,
                    {"POST",
                     "/_matrix/client/v3/login",
                     {},
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"NewHorse99!!","device_id":"DEV2"})"});
                REQUIRE(relogin.response.status == 200U);
            }
        }
    }
}

SCENARIO("POST /account/password without an access token returns 401",
         "[homeserver][client-server][account][password]")
{
    GIVEN("a registration-enabled server with no authenticated session")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a password change is attempted without providing an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/account/password", {}, R"({"new_password":"NewHorse99!!"})"});

            THEN("the server returns 401 M_MISSING_TOKEN")
            {
                // Spec §5.7.2: M_MISSING_TOKEN when no bearer token is provided at all.
                // M_UNKNOWN_TOKEN applies only when a token is present but not recognised.
                REQUIRE(response.response.status == 401U);
                REQUIRE(response.response.body.find("M_MISSING_TOKEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("GET /profile/{userId} for an unknown user returns 404",
         "[homeserver][client-server][profile]")
{
    GIVEN("a registration-enabled server with no registered users")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a client requests the profile for a user that does not exist")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40missing%3Aexample.org", {}, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

SCENARIO("PUT /profile/{userId}/displayname updates the authenticated user's displayname",
         "[homeserver][client-server][profile]")
{
    GIVEN("a registered and logged-in user")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const token = login.response.body.substr(begin + key.size(), login.response.body.find('"', begin + key.size()) - begin - key.size());

        WHEN("the user updates their displayname")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt,
                {"PUT",
                 "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname",
                 token,
                 R"({"displayname":"Alice Beta"})"});

            THEN("the server returns 200 and the profile reflects the new displayname")
            {
                REQUIRE(response.response.status == 200U);
                auto const profile = merovingian::homeserver::handle_client_server_request(
                    rt, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org", {}, {}});
                REQUIRE(profile.response.status == 200U);
                REQUIRE(profile.response.body.find("Alice Beta") != std::string::npos);
            }
        }
    }
}

SCENARIO("PUT /profile/{userId}/displayname for another user returns 403",
         "[homeserver][client-server][profile]")
{
    GIVEN("a registered and logged-in user")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const token = login.response.body.substr(begin + key.size(), login.response.body.find('"', begin + key.size()) - begin - key.size());

        WHEN("the user attempts to update another user's displayname")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt,
                {"PUT",
                 "/_matrix/client/v3/profile/%40bob%3Aexample.org/displayname",
                 token,
                 R"({"displayname":"Bob Impersonated"})"});

            THEN("the server returns 403 M_FORBIDDEN")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("GET /profile/{userId}/{keyName} returns only the requested field",
         "[homeserver][client-server][profile]")
{
    GIVEN("a registered user with a displayname set")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const token = login.response.body.substr(begin + key.size(), login.response.body.find('"', begin + key.size()) - begin - key.size());
        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt,
            {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", token, R"({"displayname":"Alice Beta"})"});

        WHEN("the displayname field is requested")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", {}, {}});

            THEN("the server returns 200 with only that field")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("Alice Beta") != std::string::npos);
                REQUIRE(response.response.body.find("avatar_url") == std::string::npos);
            }
        }

        WHEN("an unset field is requested")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org/avatar_url", {}, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/state for an unknown room returns 403",
         "[homeserver][client-server][rooms][state]")
{
    GIVEN("a registered and logged-in user")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const token = login.response.body.substr(begin + key.size(), login.response.body.find('"', begin + key.size()) - begin - key.size());

        WHEN("the user requests state for a room that does not exist")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt,
                {"GET",
                 "/_matrix/client/v3/rooms/!bad-room%3Aexample.org/state",
                 token,
                 {}});

            THEN("the server returns 403 M_FORBIDDEN")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("GET /_merovingian/admin/audit filters by category and event_type query parameters",
         "[homeserver][admin][audit]")
{
    GIVEN("a started homeserver runtime with an admin user and a seeded audit row")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        // Bootstrap the admin user so the audit endpoint will accept the
        // request without returning 401. After bootstrap, log in once to
        // mint the access_token used as the `access_token` field below.
        auto const admin_bootstrap =
            merovingian::homeserver::bootstrap_admin_user(runtime, "ops", "CorrectHorse7!");
        REQUIRE(admin_bootstrap.ok);
        auto const admin_login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {},
                      "@ops:example.org|CorrectHorse7!|OPSDEV"});
        REQUIRE(admin_login.status == 200U);
        // The local-router login handler returns the access token in
        // the response body as a plain string (no JSON wrapper). The
        // /admin/audit endpoint accepts the token in the `access_token`
        // field of the LocalHttpRequest, which is where the auth header
        // would be parsed in production.
        auto const admin_token = admin_login.body;

        // Seed an `auth` row by issuing a bad login — the local-router
        // path will route it through `log_diagnostic_audit` and append a
        // `login.rejected` row at category=auth.
        std::ignore = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {},
                      "@nope:example.org|wrong-password|DEV1"});

        WHEN("the audit endpoint is called with ?category=auth&event_type=login.rejected")
        {
            auto const response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET",
                          "/_merovingian/admin/audit?category=auth&event_type=login.rejected",
                          admin_token, {}});

            THEN("the response is 200 and contains the seeded auth row")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("filter_category=auth") != std::string::npos);
                REQUIRE(response.body.find("filter_event_type=login.rejected") != std::string::npos);
                REQUIRE(response.body.find("entry=auth:login.rejected") != std::string::npos);
            }
        }

        WHEN("the audit endpoint is called with a bogus category")
        {
            auto const response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/audit?category=authz", admin_token, {}});

            THEN("the response is 400 with a clear error message")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("unknown audit category") != std::string::npos);
            }
        }
    }
}
