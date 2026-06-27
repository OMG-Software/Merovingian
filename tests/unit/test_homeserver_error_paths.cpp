// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for homeserver authentication and HTTP-dispatch error paths.
// Happy paths live in test_homeserver_vertical_slice.cpp. This file targets
// the failure and anomaly cases:
//
//   - Login with wrong password returns !ok
//   - Login for an unknown user returns !ok
//   - Registering a duplicate username returns !ok
//   - Logout with an unknown/invalid access token returns !ok
//   - verify_local_user_password with a wrong password returns false
//   - handle_local_http_request for an unrecognised route returns 4xx
//   - handle_local_http_request for an auth-required route without a token
//     returns 401 M_MISSING_TOKEN
//   - handle_federation_http_request for a non-federation path returns 4xx

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
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
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

} // namespace

// --- Login failure paths -----------------------------------------------------

SCENARIO("login_local_user rejects a correct user_id with a wrong password", "[homeserver][auth][login][error]")
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

        WHEN("the user logs in with a wrong password")
        {
            auto const result =
                merovingian::homeserver::login_local_user(runtime, reg.value, "WrongPassword!", "DEVICE1");

            THEN("login fails and no access token is issued")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.value.empty());
            }
        }
    }
}

SCENARIO("login_local_user rejects login attempts for a user_id that does not exist",
         "[homeserver][auth][login][error]")
{
    GIVEN("a started runtime with no registered users")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("login is attempted for a non-existent user")
        {
            auto const result =
                merovingian::homeserver::login_local_user(runtime, "@ghost:example.org", "anypassword", "DEVICE1");

            THEN("login fails closed")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.value.empty());
            }
        }
    }
}

// --- Registration failure paths ----------------------------------------------

SCENARIO("register_local_user rejects a second registration for an existing localpart",
         "[homeserver][auth][registration][error]")
{
    GIVEN("a started runtime with alice already registered")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const first = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                        merovingian::tests::registration_token);
        REQUIRE(first.ok);

        WHEN("the same localpart is registered again")
        {
            auto const second = merovingian::homeserver::register_local_user(runtime, "alice", "DifferentPass99!",
                                                                             merovingian::tests::registration_token);

            THEN("the second registration fails — usernames are unique per homeserver")
            {
                REQUIRE_FALSE(second.ok);
            }
        }
    }
}

// --- Logout failure paths ----------------------------------------------------

SCENARIO("logout_local_user rejects an access token that was never issued", "[homeserver][auth][logout][error]")
{
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("logout is called with a syntactically valid but unknown token")
        {
            auto const result = merovingian::homeserver::logout_local_user(runtime, "syt_totally_unknown_token_abc123");

            THEN("logout fails closed — the token is not in the session store")
            {
                REQUIRE_FALSE(result.ok);
            }
        }

        WHEN("logout is called with an empty token")
        {
            auto const result = merovingian::homeserver::logout_local_user(runtime, "");

            THEN("logout fails closed on an empty token")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

// --- verify_local_user_password ----------------------------------------------

SCENARIO("verify_local_user_password returns false for a wrong password", "[homeserver][auth][password][error]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("password verification is called with the wrong password")
        {
            auto const verified =
                merovingian::homeserver::verify_local_user_password(runtime, login.value, "WrongPassword!");

            THEN("verification returns false")
            {
                REQUIRE_FALSE(verified);
            }
        }

        WHEN("password verification is called with the correct password")
        {
            auto const verified =
                merovingian::homeserver::verify_local_user_password(runtime, login.value, "CorrectHorse7!");

            THEN("verification returns true — confirming the positive path is exercised")
            {
                REQUIRE(verified);
            }
        }
    }
}

// --- HTTP dispatch error paths -----------------------------------------------

SCENARIO("handle_local_http_request returns a 4xx error for a completely unknown route",
         "[homeserver][http][router][error]")
{
    // Spec: Matrix Client-Server API v1.18
    // Unknown paths should return 404 M_NOT_FOUND.
    // URL: ../../docs/matrix-v1.18-spec/client-server-api.md#api-standards
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a GET request is made to a path that has no registered handler")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "GET";
            request.target = "/_matrix/client/v3/nonexistent/endpoint/xyz";

            auto const response = merovingian::homeserver::handle_local_http_request(runtime, request);

            THEN("the response is a client error (4xx) — fail closed for unknown paths")
            {
                REQUIRE(response.status >= 400U);
                REQUIRE(response.status < 500U);
            }
        }

        WHEN("a GET request is made to a completely non-Matrix path")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "GET";
            request.target = "/robots.txt";

            auto const response = merovingian::homeserver::handle_local_http_request(runtime, request);

            THEN("the response is a client error")
            {
                REQUIRE(response.status >= 400U);
                REQUIRE(response.status < 500U);
            }
        }
    }
}

SCENARIO("handle_local_http_request returns 401 for auth-required routes with no access token",
         "[homeserver][http][router][auth][error]")
{
    // handle_local_http_request is the internal pipe router (not the client-server
    // dispatcher). These tests exercise the two routes it directly auth-gates:
    //   - POST /_matrix/client/v3/logout  — delegates to logout_local_user
    //   - GET  /_merovingian/admin/health — requires admin token
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a logout request is made without an access token")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "POST";
            request.target = "/_matrix/client/v3/logout";
            // access_token deliberately left empty

            auto const response = merovingian::homeserver::handle_local_http_request(runtime, request);

            THEN("the response is 401 — logout_local_user rejects an empty token")
            {
                REQUIRE(response.status == 401U);
            }
        }

        WHEN("an admin health request is made without an access token")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "GET";
            request.target = "/_merovingian/admin/health";
            // access_token deliberately left empty

            auto const response = merovingian::homeserver::handle_local_http_request(runtime, request);

            THEN("the response is 401 — admin endpoint requires a valid admin token")
            {
                REQUIRE(response.status == 401U);
            }
        }
    }
}

SCENARIO("handle_federation_http_request returns a 4xx for non-federation paths",
         "[homeserver][http][federation][router][error]")
{
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a federation request targets a client-server path")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "GET";
            request.target = "/_matrix/client/v3/sync";

            auto const response = merovingian::homeserver::handle_federation_http_request(runtime, request);

            THEN("the federation handler returns a client error — it only serves /_matrix/federation/")
            {
                REQUIRE(response.status >= 400U);
                REQUIRE(response.status < 500U);
            }
        }

        WHEN("a federation request targets a completely unknown path")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "GET";
            request.target = "/garbage/path";

            auto const response = merovingian::homeserver::handle_federation_http_request(runtime, request);

            THEN("the federation handler returns a client error")
            {
                REQUIRE(response.status >= 400U);
                REQUIRE(response.status < 500U);
            }
        }
    }
}
