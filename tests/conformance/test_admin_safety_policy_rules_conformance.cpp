// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         ADMIN SAFETY POLICY RULES CONFORMANCE TESTS                      |
// |                                                                          |
// |  Spec: Merovingian admin API (Matrix v1.19 trust-and-safety extension)   |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                   |
// |                                                                          |
// |  Covers GET/PUT/DELETE /_matrix/client/v3/admin/safety/policy_rules.     |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
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
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime,
                                   std::string_view localpart = "alice") -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} +
        std::string{localpart} + ":example.org\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"DEVICE1\"}";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);

    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    REQUIRE(!token->empty());
    return *token;
}

[[nodiscard]] auto admin_token(merovingian::homeserver::ClientServerRuntime& runtime,
                               std::string_view localpart = "admin") -> std::string
{
    auto const boot =
        merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, std::string{localpart}, "CorrectHorse7!");
    REQUIRE(boot.ok);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} +
        std::string{localpart} + ":example.org\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"ADMIN_DEV\"}";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);

    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    REQUIRE(!token->empty());
    return *token;
}

} // namespace

// Merovingian admin API: PUT /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}
// An administrator MUST be able to create or update a policy rule.
SCENARIO("Admin PUT /admin/safety/policy_rules creates a policy rule",
         "[conformance][client-server][trust-safety][admin][policy]")
{
    GIVEN("a running client-server with a bootstrapped admin")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        WHEN("the admin creates a room-scoped deny rule")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/admin/safety/policy_rules/room/%21badroom%3Aexample.org",
                                  admin, R"({"action":"deny","reason":"csam"})"});

            THEN("the server returns 200 with an empty object")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
            }
        }
    }
}

// Merovingian admin API: GET /_matrix/client/v3/admin/safety/policy_rules
// An administrator MUST be able to list existing policy rules.
SCENARIO("Admin GET /admin/safety/policy_rules lists created rules",
         "[conformance][client-server][trust-safety][admin][policy]")
{
    GIVEN("a running client-server with a created policy rule")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/admin/safety/policy_rules/user/%40baduser%3Aexample.org",
                                  admin, R"({"action":"suspend_account","reason":"harassment"})"})
                .response.status == 200U);

        WHEN("the admin requests the policy rules list")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/admin/safety/policy_rules", admin, {}});

            THEN("the response is 200 and contains the rule")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rules = object_member_as_array(body, "policy_rules");
                REQUIRE(rules != nullptr);
                REQUIRE(rules->size() == 1);
                auto const* rule_obj = std::get_if<merovingian::canonicaljson::Object>(&(*rules)[0].storage());
                REQUIRE(rule_obj != nullptr);
                REQUIRE(*string_member(*rule_obj, "scope") == "user");
                REQUIRE(*string_member(*rule_obj, "entity") == "@baduser:example.org");
                REQUIRE(*string_member(*rule_obj, "action") == "suspend_account");
            }
        }
    }
}

// Merovingian admin API: DELETE /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}
// An administrator MUST be able to remove an existing policy rule.
SCENARIO("Admin DELETE /admin/safety/policy_rules removes a rule",
         "[conformance][client-server][trust-safety][admin][policy]")
{
    GIVEN("a running client-server with a created policy rule")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"PUT", "/_matrix/client/v3/admin/safety/policy_rules/media/abc123", admin,
                                      R"({"action":"quarantine","reason":"malware"})"})
                    .response.status == 200U);

        WHEN("the admin deletes the rule and lists policy rules")
        {
            auto const delete_response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/admin/safety/policy_rules/media/abc123", admin, {}});

            auto const list_response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/admin/safety/policy_rules", admin, {}});

            THEN("the delete returns 200 and the rule no longer appears")
            {
                REQUIRE(delete_response.response.status == 200U);

                auto const body = parse_object(list_response.response.body);
                auto const* rules = object_member_as_array(body, "policy_rules");
                REQUIRE(rules != nullptr);
                REQUIRE(rules->empty());
            }
        }
    }
}

// Merovingian admin API: DELETE /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}
// Deleting a non-existent rule MUST return 404 M_NOT_FOUND.
SCENARIO("Admin DELETE /admin/safety/policy_rules returns 404 for a missing rule",
         "[conformance][client-server][trust-safety][admin][policy]")
{
    GIVEN("a running client-server with a bootstrapped admin")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        WHEN("the admin deletes a rule that was never created")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"DELETE", "/_matrix/client/v3/admin/safety/policy_rules/room/%21nosuchroom%3Aexample.org", admin, {}});

            THEN("the server responds with 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                REQUIRE(*string_member(body, "errcode") == "M_NOT_FOUND");
            }
        }
    }
}

// Merovingian admin API: PUT /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}
// The action field MUST be one of the supported values.
SCENARIO("Admin PUT /admin/safety/policy_rules rejects an invalid action",
         "[conformance][client-server][trust-safety][admin][policy]")
{
    GIVEN("a running client-server with a bootstrapped admin")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        WHEN("the admin supplies an unsupported action")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/admin/safety/policy_rules/room/%21badroom%3Aexample.org",
                                  admin, R"({"action":"nuclear_option","reason":"spam"})"});

            THEN("the server responds with 400 M_BAD_JSON")
            {
                REQUIRE(response.response.status == 400U);
                auto const body = parse_object(response.response.body);
                REQUIRE(*string_member(body, "errcode") == "M_BAD_JSON");
            }
        }
    }
}

// Merovingian admin API: /_matrix/client/v3/admin/safety/policy_rules
// Non-admin users MUST be rejected with 403 M_FORBIDDEN.
SCENARIO("Admin /admin/safety/policy_rules rejects non-admin access",
         "[conformance][client-server][trust-safety][admin][policy]")
{
    GIVEN("a running client-server with a regular user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const user = logged_in_token(started.runtime);

        WHEN("the user tries to list policy rules")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/admin/safety/policy_rules", user, {}});

            THEN("the server responds with 403 M_FORBIDDEN")
            {
                REQUIRE(response.response.status == 403U);
                auto const body = parse_object(response.response.body);
                REQUIRE(*string_member(body, "errcode") == "M_FORBIDDEN");
            }
        }
    }
}
