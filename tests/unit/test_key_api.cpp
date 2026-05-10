// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/auth/key_api.hpp>
#include <merovingian/database/statement.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Key API route scaffold covers device key and backup endpoints", "[auth][key-api][routes]")
{
    GIVEN("Matrix key API methods and targets")
    {
        WHEN("routes are matched")
        {
            auto const upload = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/upload");
            auto const query = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/query");
            auto const claim = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/claim");
            auto const cross_signing = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/device_signing/upload");
            auto const signatures = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/signatures/upload");
            auto const backup_version = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/room_keys/version");
            auto const room_key_backup = merovingian::auth::match_key_api_route("PUT", "/_matrix/client/v3/room_keys/keys/!room:example.org/session");
            auto const device_list_update = merovingian::auth::match_key_api_route("PUT", "/_matrix/client/v3/devices/DEVICE123");

            THEN("one-time, fallback, cross-signing, signatures, backup, and device-list routes exist")
            {
                REQUIRE(upload.matched);
                REQUIRE(query.matched);
                REQUIRE(claim.matched);
                REQUIRE(cross_signing.matched);
                REQUIRE(signatures.matched);
                REQUIRE(backup_version.matched);
                REQUIRE(room_key_backup.matched);
                REQUIRE(device_list_update.matched);
                REQUIRE(upload.route.endpoint == merovingian::auth::KeyApiEndpoint::upload_keys);
                REQUIRE(room_key_backup.route.endpoint == merovingian::auth::KeyApiEndpoint::put_room_key_backup);
                REQUIRE(device_list_update.route.endpoint == merovingian::auth::KeyApiEndpoint::device_list_update);
            }
        }
    }
}

SCENARIO("Key API routes require access tokens and explicit rate limits", "[auth][key-api][rate-limit]")
{
    GIVEN("key API routes")
    {
        WHEN("route metadata is inspected")
        {
            auto const upload = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/upload");
            auto const claim = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/claim");
            auto const backup = merovingian::auth::match_key_api_route("PUT", "/_matrix/client/v3/room_keys/keys/!room:example.org/session");

            THEN("all key routes are token-protected and rate-limited")
            {
                REQUIRE(upload.route.requires_access_token);
                REQUIRE(claim.route.requires_access_token);
                REQUIRE(backup.route.requires_access_token);
                REQUIRE(upload.route.rate_limit.max_requests == 30U);
                REQUIRE(claim.route.rate_limit.max_requests == 30U);
                REQUIRE(backup.route.rate_limit.max_requests > 0U);
                REQUIRE(upload.route.stores_server_blind_payload);
            }
        }
    }
}

SCENARIO("Key API database scaffold covers one-time keys and fallback keys", "[auth][key-api][database]")
{
    GIVEN("a key upload route")
    {
        auto const upload = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/upload");

        WHEN("the boundary plan is built")
        {
            auto const plan = merovingian::auth::make_key_api_boundary_plan(upload.route, "@alice:example.org", "DEVICE123");

            THEN("one-time and fallback key storage statements are represented as sensitive payloads")
            {
                REQUIRE(plan.database_statements.size() == 2U);
                REQUIRE(plan.database_statements[0].name == "key_api_store_one_time_keys");
                REQUIRE(plan.database_statements[1].name == "key_api_store_fallback_keys");
                for (auto const& statement : plan.database_statements)
                {
                    auto const validation = merovingian::database::prepared_statement_is_valid(statement);
                    REQUIRE(validation.valid);
                    REQUIRE(statement.parameters.back().sensitive);
                }
            }
        }
    }
}

SCENARIO("Key API database scaffold covers cross-signing and key backups", "[auth][key-api][database]")
{
    GIVEN("cross-signing and backup routes")
    {
        auto const cross_signing = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/device_signing/upload");
        auto const backup_version = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/room_keys/version");
        auto const room_key_backup = merovingian::auth::match_key_api_route("PUT", "/_matrix/client/v3/room_keys/keys/!room:example.org/session");

        WHEN("the boundary plans are built")
        {
            auto const cross_signing_plan = merovingian::auth::make_key_api_boundary_plan(cross_signing.route, "@alice:example.org", "DEVICE123");
            auto const backup_version_plan = merovingian::auth::make_key_api_boundary_plan(backup_version.route, "@alice:example.org", "DEVICE123");
            auto const room_key_backup_plan = merovingian::auth::make_key_api_boundary_plan(room_key_backup.route, "@alice:example.org", "DEVICE123");

            THEN("server-blind key material is represented as sensitive database payloads")
            {
                REQUIRE(cross_signing_plan.database_statements.front().name == "key_api_store_cross_signing_keys");
                REQUIRE(cross_signing_plan.database_statements.front().parameters.back().sensitive);
                REQUIRE(backup_version_plan.database_statements.front().name == "key_api_create_backup_version");
                REQUIRE(backup_version_plan.database_statements.front().parameters.back().sensitive);
                REQUIRE(room_key_backup_plan.database_statements.front().name == "key_api_put_room_key_backup");
                REQUIRE(room_key_backup_plan.database_statements.front().parameters.back().sensitive);
            }
        }
    }
}

SCENARIO("Key payload summaries never log server-blind key material", "[auth][key-api][logging]")
{
    GIVEN("server-blind key payload material")
    {
        auto constexpr payload = "curve25519:abc123-secret-key-material";

        WHEN("the payload is evaluated for logging")
        {
            auto const loggable = merovingian::auth::key_payload_is_loggable(payload);
            auto const summary = merovingian::auth::redacted_key_payload_summary(payload);

            THEN("the original payload is not exposed")
            {
                REQUIRE_FALSE(loggable);
                REQUIRE(summary.find(payload) == std::string::npos);
                REQUIRE(summary.find("redacted") != std::string::npos);
            }
        }
    }
}
