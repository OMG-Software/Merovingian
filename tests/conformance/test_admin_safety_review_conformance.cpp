// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         ADMIN SAFETY REVIEW CONFORMANCE TESTS                           |
// |                                                                         |
// |  Spec: Merovingian admin API (Matrix v1.19 trust-and-safety extension)  |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                  |
// |                                                                         |
// |  Covers POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}.|
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
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
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
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

// Merovingian admin API: POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}
// An administrator MUST be able to mark a room target for review and persist a policy rule.
SCENARIO("Admin POST /admin/safety/review creates a room policy rule",
         "[conformance][client-server][trust-safety][admin][review]")
{
    GIVEN("a running client-server with a bootstrapped admin")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        WHEN("the admin reviews a room target with a reason")
        {
            auto const room_id = "!badroom:example.org";
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/admin/safety/review/room/%21badroom%3Aexample.org", admin,
                                  R"({"reason":"csam investigation"})"});

            THEN("the server returns 200 with an empty object")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
            }

            AND_WHEN("the admin lists policy rules")
            {
                auto const list_response = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/admin/safety/policy_rules", admin, {}});

                THEN("a room-scoped rule for the reviewed target exists")
                {
                    REQUIRE(list_response.response.status == 200U);
                    auto const body = parse_object(list_response.response.body);
                    auto const* rules = object_member_as_array(body, "policy_rules");
                    REQUIRE(rules != nullptr);
                    REQUIRE(rules->size() == 1);
                    auto const* rule_obj = std::get_if<merovingian::canonicaljson::Object>(&(*rules)[0].storage());
                    REQUIRE(rule_obj != nullptr);
                    REQUIRE(*string_member(*rule_obj, "scope") == "room");
                    REQUIRE(*string_member(*rule_obj, "entity") == room_id);
                }
            }
        }
    }
}

// Merovingian admin API: POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}
// An administrator MUST be able to mark a media target for review.
SCENARIO("Admin POST /admin/safety/review creates a media policy rule",
         "[conformance][client-server][trust-safety][admin][review]")
{
    GIVEN("a running client-server with a bootstrapped admin")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        WHEN("the admin reviews a media target")
        {
            auto const media_id = "abc123";
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/admin/safety/review/media/abc123", admin,
                                  R"({"reason":"illegal content"})"});

            THEN("the server returns 200 with an empty object")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
            }

            AND_WHEN("the admin lists policy rules")
            {
                auto const list_response = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/admin/safety/policy_rules", admin, {}});

                THEN("a media-scoped rule for the reviewed target exists")
                {
                    REQUIRE(list_response.response.status == 200U);
                    auto const body = parse_object(list_response.response.body);
                    auto const* rules = object_member_as_array(body, "policy_rules");
                    REQUIRE(rules != nullptr);
                    REQUIRE(rules->size() == 1);
                    auto const* rule_obj = std::get_if<merovingian::canonicaljson::Object>(&(*rules)[0].storage());
                    REQUIRE(rule_obj != nullptr);
                    REQUIRE(*string_member(*rule_obj, "scope") == "media");
                    REQUIRE(*string_member(*rule_obj, "entity") == media_id);
                }
            }
        }
    }
}

// Merovingian admin API: POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}
// An administrator MUST be able to mark a federation server target for review.
SCENARIO("Admin POST /admin/safety/review creates a federation policy rule",
         "[conformance][client-server][trust-safety][admin][review]")
{
    GIVEN("a running client-server with a bootstrapped admin")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        WHEN("the admin reviews a federation server target")
        {
            auto const server_name = "badserver.example.org";
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/admin/safety/review/federation_server/badserver.example.org", admin,
                 R"({"reason":"spam origin"})"});

            THEN("the server returns 200 with an empty object")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
            }

            AND_WHEN("the admin lists policy rules")
            {
                auto const list_response = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/admin/safety/policy_rules", admin, {}});

                THEN("a federation-scoped rule for the reviewed target exists")
                {
                    REQUIRE(list_response.response.status == 200U);
                    auto const body = parse_object(list_response.response.body);
                    auto const* rules = object_member_as_array(body, "policy_rules");
                    REQUIRE(rules != nullptr);
                    REQUIRE(rules->size() == 1);
                    auto const* rule_obj = std::get_if<merovingian::canonicaljson::Object>(&(*rules)[0].storage());
                    REQUIRE(rule_obj != nullptr);
                    REQUIRE(*string_member(*rule_obj, "scope") == "federation");
                    REQUIRE(*string_member(*rule_obj, "entity") == server_name);
                }
            }
        }
    }
}

// Merovingian admin API: POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}
// An empty request body MUST be accepted (reason defaults to admin-visible text).
SCENARIO("Admin POST /admin/safety/review accepts an empty body",
         "[conformance][client-server][trust-safety][admin][review]")
{
    GIVEN("a running client-server with a bootstrapped admin")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        WHEN("the admin reviews a media target with no body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/admin/safety/review/media/silent123", admin, {}});

            THEN("the server returns 200 with an empty object")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
            }
        }
    }
}

// Merovingian admin API: POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}
// An unsupported target type MUST return 400 M_BAD_JSON.
SCENARIO("Admin POST /admin/safety/review rejects an invalid target type",
         "[conformance][client-server][trust-safety][admin][review]")
{
    GIVEN("a running client-server with a bootstrapped admin")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const admin = admin_token(started.runtime);

        WHEN("the admin uses an unsupported target type")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/admin/safety/review/account/%40baduser%3Aexample.org",
                                  admin, R"({"reason":"abuse"})"});

            THEN("the server responds with 400 M_BAD_JSON")
            {
                REQUIRE(response.response.status == 400U);
                auto const body = parse_object(response.response.body);
                REQUIRE(*string_member(body, "errcode") == "M_BAD_JSON");
            }
        }
    }
}

// Merovingian admin API: POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}
// Non-admin users MUST be rejected with 403 M_FORBIDDEN.
SCENARIO("Admin POST /admin/safety/review rejects non-admin access",
         "[conformance][client-server][trust-safety][admin][review]")
{
    GIVEN("a running client-server with a regular user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const user = logged_in_token(started.runtime);

        WHEN("the user attempts to review a target")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/admin/safety/review/media/forbidden123", user, R"({"reason":"report"})"});

            THEN("the server responds with 403 M_FORBIDDEN")
            {
                REQUIRE(response.response.status == 403U);
                auto const body = parse_object(response.response.body);
                REQUIRE(*string_member(body, "errcode") == "M_FORBIDDEN");
            }
        }
    }
}
