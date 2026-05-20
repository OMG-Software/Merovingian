// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/client_server_api.hpp"
#include "merovingian/database/statement.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Client-server auth route scaffold covers Milestone 9 endpoints", "[auth][client-api][routes]")
{
    GIVEN("the client auth route registry")
    {
        WHEN("routes are matched by Matrix client API method and target")
        {
            auto const login = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/login");
            auto const logout = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/logout");
            auto const logout_all = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/logout/all");
            auto const registration = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/register");
            auto const refresh = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/refresh");
            auto const list_devices = merovingian::auth::match_client_auth_route("GET", "/_matrix/client/v3/devices");
            auto const get_device =
                merovingian::auth::match_client_auth_route("GET", "/_matrix/client/v3/devices/DEVICE123");
            auto const update_device =
                merovingian::auth::match_client_auth_route("PUT", "/_matrix/client/v3/devices/DEVICE123");
            auto const delete_device =
                merovingian::auth::match_client_auth_route("DELETE", "/_matrix/client/v3/devices/DEVICE123");

            THEN("login, logout, registration, refresh, and device management routes exist")
            {
                REQUIRE(login.matched);
                REQUIRE(logout.matched);
                REQUIRE(logout_all.matched);
                REQUIRE(registration.matched);
                REQUIRE(refresh.matched);
                REQUIRE(list_devices.matched);
                REQUIRE(get_device.matched);
                REQUIRE(update_device.matched);
                REQUIRE(delete_device.matched);
                REQUIRE(login.route.endpoint == merovingian::auth::ClientAuthEndpoint::login);
                REQUIRE(delete_device.route.endpoint == merovingian::auth::ClientAuthEndpoint::delete_device);
            }
        }
    }
}

SCENARIO("Client-server auth route scaffold attaches token requirements and rate-limit hooks",
         "[auth][client-api][rate-limit]")
{
    GIVEN("public and token-protected client auth routes")
    {
        WHEN("the route metadata is inspected")
        {
            auto const login = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/login");
            auto const registration = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/register");
            auto const logout = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/logout");
            auto const devices = merovingian::auth::match_client_auth_route("GET", "/_matrix/client/v3/devices");

            THEN("public routes stay public and sensitive routes receive conservative rate limits")
            {
                REQUIRE_FALSE(login.route.requires_access_token);
                REQUIRE_FALSE(registration.route.requires_access_token);
                REQUIRE(logout.route.requires_access_token);
                REQUIRE(devices.route.requires_access_token);
                REQUIRE(login.route.rate_limit.max_requests == 5U);
                REQUIRE(registration.route.rate_limit.max_requests == 5U);
                REQUIRE(devices.route.rate_limit.max_requests == 30U);
                REQUIRE(login.route.emits_audit_event);
                REQUIRE(devices.route.emits_audit_event);
            }
        }
    }
}

SCENARIO("Client-server auth boundary plan persists only token hashes", "[auth][client-api][tokens][database]")
{
    GIVEN("a login route, a token hash, and a plaintext token outside the persistence boundary")
    {
        auto constexpr plaintext_token = "0123456789abcdefghijklmnopqrstuvwxyz";
        auto const token_hash = merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"};
        auto const login = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/login");

        WHEN("the boundary plan is built")
        {
            auto const plan = merovingian::auth::make_client_auth_boundary_plan(login.route, "@alice:example.org",
                                                                                "DEVICE123", token_hash, true, "");

            THEN("crypto hashing is required and database parameters never contain the plaintext token")
            {
                REQUIRE(plan.token_hashing.issues_token);
                REQUIRE(plan.token_hashing.requires_crypto_random);
                REQUIRE(plan.token_hashing.requires_external_hashing);
                REQUIRE_FALSE(plan.token_hashing.persists_plaintext_token);
                REQUIRE(plan.database_statements.size() == 3U);

                auto found_sensitive_hash = false;
                for (auto const& statement : plan.database_statements)
                {
                    auto const validation = merovingian::database::prepared_statement_is_valid(statement);
                    REQUIRE(validation.valid);
                    for (auto const& parameter : statement.parameters)
                    {
                        REQUIRE(parameter.value != plaintext_token);
                        found_sensitive_hash =
                            found_sensitive_hash || (parameter.sensitive && parameter.value == token_hash.value);
                    }
                }
                REQUIRE(found_sensitive_hash);
            }
        }
    }
}

SCENARIO("Client-server auth boundary plan covers device logout and global logout database actions",
         "[auth][client-api][database]")
{
    GIVEN("logout routes and a token hash placeholder")
    {
        auto const token_hash = merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"};
        auto const logout = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/logout");
        auto const logout_all = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/logout/all");
        auto const delete_device =
            merovingian::auth::match_client_auth_route("DELETE", "/_matrix/client/v3/devices/DEVICE123");

        WHEN("database statements are planned")
        {
            auto const logout_plan = merovingian::auth::make_client_auth_boundary_plan(
                logout.route, "@alice:example.org", "DEVICE123", token_hash, true, "");
            auto const logout_all_plan = merovingian::auth::make_client_auth_boundary_plan(
                logout_all.route, "@alice:example.org", "DEVICE123", token_hash, true, "");
            auto const delete_device_plan = merovingian::auth::make_client_auth_boundary_plan(
                delete_device.route, "@alice:example.org", "DEVICE123", token_hash, true, "");

            THEN("device-specific and global invalidation statements are represented")
            {
                REQUIRE(logout_plan.database_statements.size() == 2U);
                REQUIRE(logout_plan.database_statements.back().name == "client_auth_revoke_device_tokens");
                REQUIRE(logout_all_plan.database_statements.size() == 1U);
                REQUIRE(logout_all_plan.database_statements.front().name == "client_auth_revoke_all_tokens");
                REQUIRE(delete_device_plan.database_statements.size() == 3U);
                REQUIRE(delete_device_plan.database_statements.back().name == "client_auth_revoke_device_tokens");
            }
        }
    }
}

SCENARIO("Client-server auth INSERT statements use valid SQL syntax with parenthesised column lists",
         "[auth][client-api][database][sql]")
{
    GIVEN("login and register routes with a token hash")
    {
        auto const token_hash = merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"};
        auto const login = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/login");
        auto const registration =
            merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/register");

        WHEN("database statements are planned for login and register")
        {
            auto const login_plan = merovingian::auth::make_client_auth_boundary_plan(
                login.route, "@alice:example.org", "DEVICE123", token_hash, true, "");
            auto const register_plan = merovingian::auth::make_client_auth_boundary_plan(
                registration.route, "@alice:example.org", "DEVICE123", token_hash, true, "");

            THEN("all INSERT statements have parenthesised column lists and value tuples")
            {
                // Valid form: INSERT INTO table (col1, col2) VALUES ($1, $2)
                // Both a '(' before VALUES and a '(' after VALUES are required.
                auto const insert_syntax_is_valid = [](merovingian::database::PreparedStatement const& stmt) -> bool
                {
                    if (!stmt.sql.starts_with("INSERT "))
                    {
                        return true; // not an INSERT — skip
                    }
                    auto const values_pos = stmt.sql.find(" VALUES ");
                    if (values_pos == std::string::npos)
                    {
                        return false;
                    }
                    // Column list must be parenthesised: '(' must appear before VALUES
                    auto const col_lparen = stmt.sql.find('(');
                    if (col_lparen == std::string::npos || col_lparen >= values_pos)
                    {
                        return false;
                    }
                    // Value tuple must be parenthesised: '(' must appear after VALUES
                    auto const val_lparen = stmt.sql.find('(', values_pos + 8U);
                    return val_lparen != std::string::npos;
                };

                for (auto const& stmt : login_plan.database_statements)
                {
                    INFO("login statement: " << stmt.name << " sql: " << stmt.sql);
                    REQUIRE(insert_syntax_is_valid(stmt));
                }
                for (auto const& stmt : register_plan.database_statements)
                {
                    INFO("register statement: " << stmt.name << " sql: " << stmt.sql);
                    REQUIRE(insert_syntax_is_valid(stmt));
                }
            }
        }
    }
}

SCENARIO("Client-server auth boundary plan emits audit events for route decisions", "[auth][client-api][audit]")
{
    GIVEN("a denied device route decision")
    {
        auto const token_hash = merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"};
        auto const route = merovingian::auth::match_client_auth_route("DELETE", "/_matrix/client/v3/devices/DEVICE123");

        WHEN("the boundary plan is built")
        {
            auto const plan = merovingian::auth::make_client_auth_boundary_plan(
                route.route, "@alice:example.org", "DEVICE123", token_hash, false, "device deleted");
            auto const summary = merovingian::auth::client_auth_audit_summary(plan.audit_event);

            THEN("the audit event records the boundary decision")
            {
                REQUIRE(plan.route.emits_audit_event);
                REQUIRE(plan.audit_event.event_type == "client_auth.delete_device");
                REQUIRE(plan.audit_event.outcome == "denied");
                REQUIRE(summary.find("device deleted") != std::string::npos);
            }
        }
    }
}
