// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX CLIENT-SERVER AUTH API CONFORMANCE TESTS                 |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18, Sec. 5 Client Authentication         |
// |  Login:        https://spec.matrix.org/v1.18/client-server-api/#login   |
// |  Registration: https://spec.matrix.org/v1.18/client-server-api/         |
// |                #account-registration-and-management                      |
// |  Devices:      https://spec.matrix.org/v1.18/client-server-api/         |
// |                #device-management                                         |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec or a    |
// |  hard security invariant (token hashing, plaintext exclusion). If a     |
// |  test fails:                                                             |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec or policy.           |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// +-------------------------------------------------------------------------+

#include "merovingian/auth/client_server_api.hpp"
#include "merovingian/database/statement.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

// --- auth route coverage ------------------------------------------------------
// Spec: Matrix Client-Server API v1.18
// Login:        POST /_matrix/client/v3/login
// Logout:       POST /_matrix/client/v3/logout
// Registration: POST /_matrix/client/v3/register
// Refresh:      POST /_matrix/client/v3/refresh
// Devices:      GET/PUT/DELETE /_matrix/client/v3/devices/{deviceId}
// URLs: https://spec.matrix.org/v1.18/client-server-api/#login
//       https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3register
//       https://spec.matrix.org/v1.18/client-server-api/#device-management
//
// All listed endpoints MUST be routable - missing routes cause 404s that
// break standard Matrix clients.
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
                // Spec MUST: all standard auth endpoints must be routable.
                // Do NOT remove route checks - missing routes cause 404s in
                // standard Matrix clients (Element, FluffyChat, etc.).
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

// --- token requirements and rate limits --------------------------------------
// Spec: Matrix Client-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/client-server-api/#using-access-tokens
//       https://spec.matrix.org/v1.18/client-server-api/#rate-limiting
//
// Login and registration MUST NOT require an access token (they are how
// tokens are obtained). Logout and device management MUST require a token.
// Sensitive unauthenticated endpoints MUST be rate-limited to prevent
// credential brute-forcing.
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
                // Spec MUST: login and registration are publicly accessible.
                // Do NOT add requires_access_token to these routes.
                REQUIRE_FALSE(login.route.requires_access_token);
                REQUIRE_FALSE(registration.route.requires_access_token);
                // Spec MUST: authenticated endpoints require a valid token.
                REQUIRE(logout.route.requires_access_token);
                REQUIRE(devices.route.requires_access_token);
                // Security MUST: rate-limit unauthenticated sensitive endpoints.
                // Do NOT raise the limit above 5 without a security review.
                REQUIRE(login.route.rate_limit.max_requests == 5U);
                REQUIRE(registration.route.rate_limit.max_requests == 5U);
                REQUIRE(devices.route.rate_limit.max_requests == 30U);
                REQUIRE(login.route.emits_audit_event);
                REQUIRE(devices.route.emits_audit_event);
            }
        }
    }
}

// --- token hashing - no plaintext persistence ---------------------------------
// Spec: Merovingian security policy (stricter than Matrix spec requires)
//
// Access tokens MUST NEVER be stored in plaintext. The persistence boundary
// plan must:
//   1. Require crypto-random token generation.
//   2. Require external KDF hashing before storage.
//   3. Store only the token hash, never the plaintext token.
//
// A regression here would store access tokens in recoverable form, allowing
// database read access to escalate to account takeover.
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
                // Security MUST: token generation requires crypto randomness.
                // Do NOT remove - using a weak PRNG for tokens enables prediction attacks.
                REQUIRE(plan.token_hashing.issues_token);
                REQUIRE(plan.token_hashing.requires_crypto_random);
                REQUIRE(plan.token_hashing.requires_external_hashing);
                // Security MUST: plaintext token must never reach the database.
                // Do NOT change to true - plaintext tokens in the database allow
                // database read access to produce valid sessions.
                REQUIRE_FALSE(plan.token_hashing.persists_plaintext_token);
                REQUIRE(plan.database_statements.size() == 3U);

                auto found_sensitive_hash = false;
                for (auto const& statement : plan.database_statements)
                {
                    auto const validation = merovingian::database::prepared_statement_is_valid(statement);
                    REQUIRE(validation.valid);
                    for (auto const& parameter : statement.parameters)
                    {
                        // Security MUST: no parameter should equal the plaintext token.
                        REQUIRE(parameter.value != plaintext_token);
                        found_sensitive_hash =
                            found_sensitive_hash || (parameter.sensitive && parameter.value == token_hash.value);
                    }
                }
                // Security MUST: the hash must appear as a sensitive parameter.
                REQUIRE(found_sensitive_hash);
            }
        }
    }
}

// --- logout and device deletion database actions -------------------------------
// Spec: Matrix Client-Server API v1.18
// Logout:        POST /_matrix/client/v3/logout
// Logout all:    POST /_matrix/client/v3/logout/all
// Delete device: DELETE /_matrix/client/v3/devices/{deviceId}
// URL: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3logout
//
// Each operation MUST revoke the correct token scope: single-device for logout
// and delete-device, all-device for logout/all.
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
                // Spec MUST: logout revokes the current device's tokens only.
                REQUIRE(logout_plan.database_statements.size() == 2U);
                REQUIRE(logout_plan.database_statements.back().name == "client_auth_revoke_device_tokens");
                // Spec MUST: logout/all revokes tokens for all devices.
                REQUIRE(logout_all_plan.database_statements.size() == 1U);
                REQUIRE(logout_all_plan.database_statements.front().name == "client_auth_revoke_all_tokens");
                REQUIRE(delete_device_plan.database_statements.size() == 3U);
                REQUIRE(delete_device_plan.database_statements.back().name == "client_auth_revoke_device_tokens");
            }
        }
    }
}

// --- SQL INSERT syntax validation ---------------------------------------------
// Invariant: all INSERT statements must use parenthesised column lists.
//
// Valid:   INSERT INTO t (col1, col2) VALUES ($1, $2)
// Invalid: INSERT INTO t VALUES ($1, $2)    - ambiguous column mapping
//
// Unparenthesised INSERTs are fragile against schema changes and have caused
// production bugs. This test prevents the pattern from being re-introduced.
SCENARIO("Client-server auth INSERT statements use valid SQL syntax with parenthesised column lists",
         "[auth][client-api][database][sql]")
{
    GIVEN("login and register routes with a token hash")
    {
        auto const token_hash = merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"};
        auto const login = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/login");
        auto const registration = merovingian::auth::match_client_auth_route("POST", "/_matrix/client/v3/register");

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
                // Do NOT relax - ambiguous INSERTs break on schema changes.
                auto const insert_syntax_is_valid = [](merovingian::database::PreparedStatement const& stmt) -> bool {
                    if (!stmt.sql.starts_with("INSERT "))
                    {
                        return true; // not an INSERT - skip
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

// --- audit event emission -----------------------------------------------------
// Spec: Merovingian security policy - audit trail for auth decisions
//
// Sensitive auth operations (login, logout, device management) MUST emit
// structured audit events. The event type and outcome must be recorded
// accurately so security monitoring can detect suspicious patterns.
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
                // Security MUST: sensitive routes must emit audit events.
                // Do NOT change emits_audit_event to false - removing audit events
                // hides account access activity from security monitoring.
                REQUIRE(plan.route.emits_audit_event);
                REQUIRE(plan.audit_event.event_type == "client_auth.delete_device");
                REQUIRE(plan.audit_event.outcome == "denied");
                REQUIRE(summary.find("device deleted") != std::string::npos);
            }
        }
    }
}
