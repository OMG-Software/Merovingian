// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX USER REPORT CONFORMANCE TESTS                             |
// |                                                                          |
// |  Spec: Matrix Client-Server API v1.19 (added in v1.14)                   |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                  |
// |                                                                          |
// |  Covers POST /_matrix/client/v3/users/{userId}/report.                   |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
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

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                      std::string const& localpart) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    // Fixture: registration must succeed before the user can log in.
    REQUIRE(reg.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})"});
    // Fixture: login must succeed so the report is authenticated.
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    // Fixture: the login response must carry the token.
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto admin_token(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    auto const boot = merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "admin", "CorrectHorse7!");
    // Fixture: the admin account must exist to read the report listing.
    REQUIRE(boot.ok);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@admin:example.org"},"password":"CorrectHorse7!","device_id":"ADMIN_DEV"})"});
    // Fixture: the admin must be able to log in.
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    // Fixture: the login response must carry the token.
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto report(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                          std::string const& user_path, std::string const& body)
    -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/users/" + user_path + "/report", token, body});
}

[[nodiscard]] auto listing(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& admin)
    -> std::string
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {"GET", "/_matrix/client/v3/admin/safety/reports", admin, {}})
        .response.body;
}

} // namespace

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3usersuseridreport
// "Reports a user as inappropriate to the server ... The caller is not required to be joined to any rooms
// that the reported user is joined to." 200 {} "The user has been reported successfully".
// Endpoint / Section: POST /_matrix/client/v3/users/{userId}/report
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3usersuseridreport
SCENARIO("POST /users/{userId}/report records a report about a local user",
         "[conformance][client-server][trust-safety][user-report]")
{
    GIVEN("two users who share no room and an administrator")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice");
        std::ignore = register_and_login(runtime, "bob");
        auto const admin = admin_token(runtime);

        WHEN("alice reports bob with a reason")
        {
            auto const result = report(runtime, alice, "%40bob%3Aexample.org", R"({"reason":"spam"})");

            THEN("the answer is 200 {} and the administrators' listing holds the report")
            {
                REQUIRE(result.response.status == 200U);
                REQUIRE(result.response.body == "{}");
                auto const text = listing(runtime, admin);
                REQUIRE(text.find("@alice:example.org") != std::string::npos);
                REQUIRE(text.find("@bob:example.org") != std::string::npos);
            }
        }

        WHEN("alice reports bob twice")
        {
            REQUIRE(report(runtime, alice, "%40bob%3Aexample.org", R"({"reason":"spam"})").response.status == 200U);
            auto const second = report(runtime, alice, "%40bob%3Aexample.org", R"({"reason":"still spam"})");

            THEN("both answer 200 and the listing holds one row for the pair")
            {
                REQUIRE(second.response.status == 200U);
                auto const text = listing(runtime, admin);
                auto const first = text.find("@bob:example.org");
                REQUIRE(first != std::string::npos);
                REQUIRE(text.find("@bob:example.org", first + 1U) == std::string::npos);
            }
        }

        WHEN("the reason is blank")
        {
            auto const result = report(runtime, alice, "%40bob%3Aexample.org", R"({"reason":""})");

            THEN("the report is accepted (spec: the reason may be blank)")
            {
                REQUIRE(result.response.status == 200U);
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3usersuseridreport
// 404 "The user was not found on the homeserver."; the spec lets a server answer 200 for a user that does not
// exist instead. This server answers 404 for an unknown user of its own and stores nothing.
SCENARIO("POST /users/{userId}/report answers 404 for a local user that does not exist",
         "[conformance][client-server][trust-safety][user-report]")
{
    GIVEN("a logged-in user and an administrator")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice");
        auto const admin = admin_token(runtime);

        WHEN("she reports a local user ID nobody holds")
        {
            auto const result = report(runtime, alice, "%40nobody%3Aexample.org", R"({"reason":"x"})");

            THEN("the answer is 404 M_NOT_FOUND and no report is stored")
            {
                REQUIRE(result.response.status == 404U);
                auto const body = parse_object(result.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
                REQUIRE(listing(runtime, admin).find("@nobody:example.org") == std::string::npos);
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3usersuseridreport
// "Requires authentication: Yes"; the body is an object whose `reason` is a string.
SCENARIO("POST /users/{userId}/report needs authentication and a JSON object body",
         "[conformance][client-server][trust-safety][user-report]")
{
    GIVEN("a registered user to report")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice");
        std::ignore = register_and_login(runtime, "bob");

        WHEN("the request carries no access token")
        {
            auto const result = report(runtime, {}, "%40bob%3Aexample.org", R"({"reason":"x"})");

            THEN("the answer is 401 M_MISSING_TOKEN")
            {
                REQUIRE(result.response.status == 401U);
                auto const body = parse_object(result.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_MISSING_TOKEN");
            }
        }

        WHEN("the body is not a JSON object or the reason is not a string")
        {
            auto const not_json = report(runtime, alice, "%40bob%3Aexample.org", "nonsense");
            auto const bad_reason = report(runtime, alice, "%40bob%3Aexample.org", R"({"reason":7})");

            THEN("both are 400 M_BAD_JSON")
            {
                REQUIRE(not_json.response.status == 400U);
                REQUIRE(bad_reason.response.status == 400U);
                auto const body = parse_object(bad_reason.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_BAD_JSON");
            }
        }
    }
}
