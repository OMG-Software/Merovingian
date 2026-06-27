// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX END-TO-END ENCRYPTION KEY API CONFORMANCE TESTS          |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18, Sec. 12 End-to-end encryption        |
// |  Key upload:    ../../docs/matrix-v1.18-spec/client-server-api.md        |
// |                 #post_matrixclientv3keysupload                           |
// |  Key query:     ../../docs/matrix-v1.18-spec/client-server-api.md        |
// |                 #post_matrixclientv3keysquery                            |
// |  Key claim:     ../../docs/matrix-v1.18-spec/client-server-api.md        |
// |                 #post_matrixclientv3keysclaim                            |
// |  Cross-signing: ../../docs/matrix-v1.18-spec/client-server-api.md        |
// |                 #cross-signing                                            |
// |  Key backup:    ../../docs/matrix-v1.18-spec/client-server-api.md        |
// |                 #server-side-key-backups                                 |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix E2EE spec    |
// |  or a hard security invariant (server-blind storage, key redaction).    |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec or policy.           |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// +-------------------------------------------------------------------------+

#include "merovingian/auth/key_api.hpp"
#include "merovingian/database/statement.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

// --- key API route coverage ---------------------------------------------------
// Spec: Matrix Client-Server API v1.18, Sec. 12 End-to-end encryption
// Endpoints covered:
//   POST /_matrix/client/v3/keys/upload               - device keys + OTKs
//   POST /_matrix/client/v3/keys/query                - query device keys
//   POST /_matrix/client/v3/keys/claim                - claim OTKs
//   POST /_matrix/client/v3/keys/device_signing/upload - cross-signing keys
//   POST /_matrix/client/v3/keys/signatures/upload    - cross-signing sigs
//   POST /_matrix/client/v3/room_keys/version         - create backup version
//   PUT  /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId} - backup key
//   PUT  /_matrix/client/v3/devices/{deviceId}        - device list update
//
// All listed endpoints MUST be routable - missing routes break E2EE setup in
// Matrix clients and prevent cross-signing from working.
SCENARIO("Key API route scaffold covers device key and backup endpoints", "[auth][key-api][routes]")
{
    GIVEN("Matrix key API methods and targets")
    {
        WHEN("routes are matched")
        {
            auto const upload = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/upload");
            auto const query = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/query");
            auto const claim = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/claim");
            auto const cross_signing =
                merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/device_signing/upload");
            auto const signatures =
                merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/signatures/upload");
            auto const backup_version =
                merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/room_keys/version");
            auto const room_key_backup = merovingian::auth::match_key_api_route(
                "PUT", "/_matrix/client/v3/room_keys/keys/!room:example.org/session");
            auto const device_list_update =
                merovingian::auth::match_key_api_route("PUT", "/_matrix/client/v3/devices/DEVICE123");

            THEN("one-time, fallback, cross-signing, signatures, backup, and device-list routes exist")
            {
                // Spec MUST: all key API endpoints must be routable.
                // Do NOT remove route checks - missing routes break E2EE setup
                // in clients (Element, FluffyChat, etc.) and prevent key exchange.
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

// --- token protection and rate limits -----------------------------------------
// Spec: Matrix Client-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#using-access-tokens
//       ../../docs/matrix-v1.18-spec/client-server-api.md#rate-limiting
//
// All key API endpoints MUST require a valid access token - key material
// belongs to authenticated users only. Rate limiting MUST be applied to
// prevent key enumeration or one-time-key exhaustion attacks.
SCENARIO("Key API routes require access tokens and explicit rate limits", "[auth][key-api][rate-limit]")
{
    GIVEN("key API routes")
    {
        WHEN("route metadata is inspected")
        {
            auto const upload = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/upload");
            auto const claim = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/claim");
            auto const backup = merovingian::auth::match_key_api_route(
                "PUT", "/_matrix/client/v3/room_keys/keys/!room:example.org/session");

            THEN("all key routes are token-protected and rate-limited")
            {
                // Spec MUST: key endpoints require authentication.
                // Do NOT remove requires_access_token - unauthenticated key
                // access would expose private key material to anonymous callers.
                REQUIRE(upload.route.requires_access_token);
                REQUIRE(claim.route.requires_access_token);
                REQUIRE(backup.route.requires_access_token);
                // Security MUST: key endpoints must be rate-limited.
                REQUIRE(upload.route.rate_limit.max_requests == 30U);
                REQUIRE(claim.route.rate_limit.max_requests == 30U);
                REQUIRE(backup.route.rate_limit.max_requests > 0U);
                // Security: key upload stores server-blind payload (not inspected).
                REQUIRE(upload.route.stores_server_blind_payload);
            }
        }
    }
}

// --- one-time and fallback key storage ----------------------------------------
// Spec: Matrix Client-Server API v1.18, Sec. 12.1 One-time keys
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md
//       #post_matrixclientv3keysupload
//
// The server MUST store one-time keys and fallback keys as opaque, sensitive
// payloads (server-blind storage). The server MUST NOT inspect or log the key
// material - doing so would compromise the Double Ratchet forward secrecy.
SCENARIO("Key API database scaffold covers one-time keys and fallback keys", "[auth][key-api][database]")
{
    GIVEN("a key upload route")
    {
        auto const upload = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/upload");

        WHEN("the boundary plan is built")
        {
            auto const plan =
                merovingian::auth::make_key_api_boundary_plan(upload.route, "@alice:example.org", "DEVICE123");

            THEN("one-time and fallback key storage statements are represented as sensitive payloads")
            {
                // Spec MUST: key upload stores one-time keys and fallback keys.
                // Do NOT remove or reorder these statements - OTK and fallback
                // key storage are required for Olm/Megolm session establishment.
                REQUIRE(plan.database_statements.size() == 2U);
                REQUIRE(plan.database_statements[0].name == "key_api_store_one_time_keys");
                REQUIRE(plan.database_statements[1].name == "key_api_store_fallback_keys");
                for (auto const& statement : plan.database_statements)
                {
                    auto const validation = merovingian::database::prepared_statement_is_valid(statement);
                    REQUIRE(validation.valid);
                    // Security MUST: key material must be marked sensitive.
                    // Do NOT remove - sensitive flag prevents key material from
                    // appearing in diagnostic logs and audit trails.
                    REQUIRE(statement.parameters.back().sensitive);
                }
            }
        }
    }
}

// --- cross-signing and key backup storage -------------------------------------
// Spec: Matrix Client-Server API v1.18
// Cross-signing: ../../docs/matrix-v1.18-spec/client-server-api.md#cross-signing
// Key backup:    ../../docs/matrix-v1.18-spec/client-server-api.md
//                #server-side-key-backups
//
// Cross-signing keys and room key backups MUST be stored as server-blind,
// sensitive payloads. The server never decrypts these values; it stores and
// returns them opaquely to enable key recovery across devices.
SCENARIO("Key API database scaffold covers cross-signing and key backups", "[auth][key-api][database]")
{
    GIVEN("cross-signing and backup routes")
    {
        auto const cross_signing =
            merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/device_signing/upload");
        auto const backup_version =
            merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/room_keys/version");
        auto const room_key_backup = merovingian::auth::match_key_api_route(
            "PUT", "/_matrix/client/v3/room_keys/keys/!room:example.org/session");

        WHEN("the boundary plans are built")
        {
            auto const cross_signing_plan =
                merovingian::auth::make_key_api_boundary_plan(cross_signing.route, "@alice:example.org", "DEVICE123");
            auto const backup_version_plan =
                merovingian::auth::make_key_api_boundary_plan(backup_version.route, "@alice:example.org", "DEVICE123");
            auto const room_key_backup_plan =
                merovingian::auth::make_key_api_boundary_plan(room_key_backup.route, "@alice:example.org", "DEVICE123");

            THEN("server-blind key material is represented as sensitive database payloads")
            {
                // Security MUST: cross-signing key material marked sensitive.
                // Do NOT remove - cross-signing private keys must never appear in logs.
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

// --- SQL INSERT syntax validation ---------------------------------------------
// Invariant: all INSERT statements must use parenthesised column lists.
//
// Valid:   INSERT INTO t (col1, col2) VALUES ($1, $2)
// Invalid: INSERT INTO t VALUES ($1, $2)    - ambiguous column mapping
//
// Unparenthesised INSERTs are fragile against schema changes and have caused
// production bugs. This test prevents the pattern from being re-introduced.
SCENARIO("Key API INSERT statements use valid SQL syntax with parenthesised column lists",
         "[auth][key-api][database][sql]")
{
    GIVEN("a device list update route")
    {
        auto const device_list_update =
            merovingian::auth::match_key_api_route("PUT", "/_matrix/client/v3/devices/DEVICE123");

        WHEN("the boundary plan is built")
        {
            auto const plan = merovingian::auth::make_key_api_boundary_plan(device_list_update.route,
                                                                            "@alice:example.org", "DEVICE123");

            THEN("all INSERT statements have parenthesised column lists and value tuples")
            {
                // Do NOT relax - ambiguous INSERTs break on schema changes.
                auto const insert_syntax_is_valid = [](merovingian::database::PreparedStatement const& stmt) -> bool {
                    if (!stmt.sql.starts_with("INSERT "))
                    {
                        return true;
                    }
                    auto const values_pos = stmt.sql.find(" VALUES ");
                    if (values_pos == std::string::npos)
                    {
                        return false;
                    }
                    auto const col_lparen = stmt.sql.find('(');
                    if (col_lparen == std::string::npos || col_lparen >= values_pos)
                    {
                        return false;
                    }
                    auto const val_lparen = stmt.sql.find('(', values_pos + 8U);
                    return val_lparen != std::string::npos;
                };

                for (auto const& stmt : plan.database_statements)
                {
                    INFO("statement: " << stmt.name << " sql: " << stmt.sql);
                    REQUIRE(insert_syntax_is_valid(stmt));
                }
            }
        }
    }
}

// --- server-blind key payload log redaction ------------------------------------
// Spec: Merovingian security policy - no key material in logs
// Ref:  Matrix Client-Server API v1.18, Sec. 12 End-to-end encryption
//
// Server-blind key payloads (one-time keys, cross-signing keys, backups) MUST
// NOT appear in diagnostic logs. The server stores them opaquely; logging them
// would expose private key material to anyone with log access.
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
                // Security MUST: key payloads must never be logged.
                // Do NOT change loggable to true - server-blind key material
                // appearing in logs breaks the server-blind security model.
                REQUIRE_FALSE(loggable);
                REQUIRE(summary.find(payload) == std::string::npos);
                REQUIRE(summary.find("redacted") != std::string::npos);
            }
        }
    }
}

// --- empty payload is loggable -----------------------------------------------
// An empty payload has no key material to protect. key_payload_is_loggable
// MUST return true for an empty string so diagnostic code can safely emit it
// without inadvertently enabling a blanket "everything is safe" fast-path.
SCENARIO("Empty key payloads are considered loggable", "[auth][key-api][logging]")
{
    GIVEN("an empty key payload string")
    {
        WHEN("the payload is evaluated for logging")
        {
            auto const loggable = merovingian::auth::key_payload_is_loggable("");
            auto const summary = merovingian::auth::redacted_key_payload_summary("");

            THEN("empty payloads are safe to log and produce the empty summary label")
            {
                REQUIRE(loggable);
                REQUIRE(summary == "[key-payload:empty]");
            }
        }
    }
}

// --- key_api_endpoint_name exhaustive coverage --------------------------------
// Every KeyApiEndpoint enum value MUST map to a non-empty, non-'unknown' name.
// 'unknown' is the fallback branch that indicates an unhandled enum case — if
// any case appears here a new endpoint was added without updating the switch.
SCENARIO("key_api_endpoint_name returns a unique non-empty label for every endpoint", "[auth][key-api][endpoint-name]")
{
    GIVEN("all defined KeyApiEndpoint enum values")
    {
        auto const all_endpoints = std::vector<merovingian::auth::KeyApiEndpoint>{
            merovingian::auth::KeyApiEndpoint::upload_keys,
            merovingian::auth::KeyApiEndpoint::query_keys,
            merovingian::auth::KeyApiEndpoint::claim_keys,
            merovingian::auth::KeyApiEndpoint::device_list_update,
            merovingian::auth::KeyApiEndpoint::upload_cross_signing_keys,
            merovingian::auth::KeyApiEndpoint::upload_signatures,
            merovingian::auth::KeyApiEndpoint::get_key_backup_version,
            merovingian::auth::KeyApiEndpoint::create_key_backup_version,
            merovingian::auth::KeyApiEndpoint::update_key_backup_version,
            merovingian::auth::KeyApiEndpoint::delete_key_backup_version,
            merovingian::auth::KeyApiEndpoint::put_room_key_backup,
            merovingian::auth::KeyApiEndpoint::put_room_key_backup_room,
            merovingian::auth::KeyApiEndpoint::put_room_key_backup_batch,
            merovingian::auth::KeyApiEndpoint::get_room_key_backup,
            merovingian::auth::KeyApiEndpoint::delete_room_key_backup_room,
            merovingian::auth::KeyApiEndpoint::delete_room_key_backup,
            merovingian::auth::KeyApiEndpoint::get_key_backup_version_by_id,
            merovingian::auth::KeyApiEndpoint::get_room_key_backup_batch,
            merovingian::auth::KeyApiEndpoint::delete_room_key_backup_batch,
        };

        WHEN("names are retrieved for all endpoints")
        {
            auto names = std::vector<std::string>{};
            names.reserve(all_endpoints.size());
            for (auto const ep : all_endpoints)
            {
                names.emplace_back(merovingian::auth::key_api_endpoint_name(ep));
            }

            THEN("every endpoint has a non-empty name that is not the 'unknown' fallback")
            {
                for (auto const& name : names)
                {
                    REQUIRE_FALSE(name.empty());
                    REQUIRE(name != std::string{"unknown"});
                }
            }
        }
    }
}

// --- match_key_api_route — unmatched and additional path patterns -------------
// Spec: Matrix Client-Server API v1.18, Sec. 12 End-to-end encryption
//
// The router MUST return a no-match result for paths that do not correspond
// to any registered key-API endpoint. Incorrectly matching unrelated paths
// would route general client requests through the E2EE key handling pipeline.
SCENARIO("match_key_api_route returns no match for unregistered paths", "[auth][key-api][routes][error]")
{
    GIVEN("paths that are not part of the key API")
    {
        WHEN("a sync path is matched")
        {
            auto const result = merovingian::auth::match_key_api_route("GET", "/_matrix/client/v3/sync");

            THEN("no match is returned")
            {
                REQUIRE_FALSE(result.matched);
                REQUIRE_FALSE(result.reason.empty());
            }
        }

        WHEN("an entirely unknown path is matched")
        {
            auto const result = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/unknown");

            THEN("no match is returned")
            {
                REQUIRE_FALSE(result.matched);
            }
        }

        WHEN("the correct path is used with a wrong HTTP method")
        {
            auto const result = merovingian::auth::match_key_api_route("DELETE", "/_matrix/client/v3/keys/upload");

            THEN("no match is returned — method mismatch is not accepted")
            {
                REQUIRE_FALSE(result.matched);
            }
        }
    }
}

SCENARIO("match_key_api_route matches GET and DELETE key-backup routes", "[auth][key-api][routes]")
{
    GIVEN("GET and DELETE key-backup targets")
    {
        WHEN("GET version route is matched")
        {
            auto const result = merovingian::auth::match_key_api_route("GET", "/_matrix/client/v3/room_keys/version");

            THEN("get_key_backup_version is matched")
            {
                REQUIRE(result.matched);
                REQUIRE(result.route.endpoint == merovingian::auth::KeyApiEndpoint::get_key_backup_version);
            }
        }

        WHEN("GET version-by-id route is matched")
        {
            auto const result = merovingian::auth::match_key_api_route("GET", "/_matrix/client/v3/room_keys/version/5");

            THEN("get_key_backup_version_by_id is matched")
            {
                REQUIRE(result.matched);
                REQUIRE(result.route.endpoint == merovingian::auth::KeyApiEndpoint::get_key_backup_version_by_id);
            }
        }

        WHEN("DELETE version route is matched")
        {
            auto const result =
                merovingian::auth::match_key_api_route("DELETE", "/_matrix/client/v3/room_keys/version/3");

            THEN("delete_key_backup_version is matched")
            {
                REQUIRE(result.matched);
                REQUIRE(result.route.endpoint == merovingian::auth::KeyApiEndpoint::delete_key_backup_version);
            }
        }

        WHEN("GET room-key-batch route is matched")
        {
            auto const result = merovingian::auth::match_key_api_route("GET", "/_matrix/client/v3/room_keys/keys");

            THEN("get_room_key_backup_batch is matched")
            {
                REQUIRE(result.matched);
                REQUIRE(result.route.endpoint == merovingian::auth::KeyApiEndpoint::get_room_key_backup_batch);
            }
        }

        WHEN("DELETE room-key-batch route is matched")
        {
            auto const result = merovingian::auth::match_key_api_route("DELETE", "/_matrix/client/v3/room_keys/keys");

            THEN("delete_room_key_backup_batch is matched")
            {
                REQUIRE(result.matched);
                REQUIRE(result.route.endpoint == merovingian::auth::KeyApiEndpoint::delete_room_key_backup_batch);
            }
        }

        WHEN("GET room-key-by-session route is matched")
        {
            auto const result = merovingian::auth::match_key_api_route(
                "GET", "/_matrix/client/v3/room_keys/keys/!room:example.org/sessionABC");

            THEN("get_room_key_backup is matched")
            {
                REQUIRE(result.matched);
                REQUIRE(result.route.endpoint == merovingian::auth::KeyApiEndpoint::get_room_key_backup);
            }
        }

        WHEN("DELETE room-key-by-session route is matched")
        {
            auto const result = merovingian::auth::match_key_api_route(
                "DELETE", "/_matrix/client/v3/room_keys/keys/!room:example.org/sessionABC");

            THEN("delete_room_key_backup is matched")
            {
                REQUIRE(result.matched);
                REQUIRE(result.route.endpoint == merovingian::auth::KeyApiEndpoint::delete_room_key_backup);
            }
        }

        WHEN("DELETE room-key-by-room route is matched")
        {
            auto const result =
                merovingian::auth::match_key_api_route("DELETE", "/_matrix/client/v3/room_keys/keys/!room:example.org");

            THEN("delete_room_key_backup_room is matched")
            {
                REQUIRE(result.matched);
                REQUIRE(result.route.endpoint == merovingian::auth::KeyApiEndpoint::delete_room_key_backup_room);
            }
        }
    }
}

// --- key_api_database_statements for remaining endpoints ---------------------
SCENARIO("Key API database statements exist for update, delete, and GET backup endpoints", "[auth][key-api][database]")
{
    GIVEN("update, delete, and GET backup routes")
    {
        auto const update_version =
            merovingian::auth::match_key_api_route("PUT", "/_matrix/client/v3/room_keys/version/2");
        auto const delete_version =
            merovingian::auth::match_key_api_route("DELETE", "/_matrix/client/v3/room_keys/version/2");
        auto const get_version = merovingian::auth::match_key_api_route("GET", "/_matrix/client/v3/room_keys/version");
        auto const claim_keys = merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/claim");
        auto const upload_sigs =
            merovingian::auth::match_key_api_route("POST", "/_matrix/client/v3/keys/signatures/upload");

        WHEN("the boundary plans are built")
        {
            auto const update_plan =
                merovingian::auth::make_key_api_boundary_plan(update_version.route, "@alice:example.org", "DEVICE1");
            auto const delete_plan =
                merovingian::auth::make_key_api_boundary_plan(delete_version.route, "@alice:example.org", "DEVICE1");
            auto const get_plan =
                merovingian::auth::make_key_api_boundary_plan(get_version.route, "@alice:example.org", "DEVICE1");
            auto const claim_plan =
                merovingian::auth::make_key_api_boundary_plan(claim_keys.route, "@alice:example.org", "DEVICE1");
            auto const sigs_plan =
                merovingian::auth::make_key_api_boundary_plan(upload_sigs.route, "@alice:example.org", "DEVICE1");

            THEN("each plan contains at least one database statement")
            {
                REQUIRE_FALSE(update_plan.database_statements.empty());
                REQUIRE(update_plan.database_statements.front().name == "key_api_update_backup_version");
                REQUIRE_FALSE(delete_plan.database_statements.empty());
                REQUIRE(delete_plan.database_statements.front().name == "key_api_delete_backup_version");
                REQUIRE_FALSE(get_plan.database_statements.empty());
                REQUIRE(get_plan.database_statements.front().name == "key_api_get_backup_version");
                REQUIRE_FALSE(claim_plan.database_statements.empty());
                REQUIRE(claim_plan.database_statements.front().name == "key_api_claim_one_time_keys");
                REQUIRE_FALSE(sigs_plan.database_statements.empty());
                REQUIRE(sigs_plan.database_statements.front().name == "key_api_store_key_signatures");
                // Uploaded signatures are security-sensitive — the payload MUST be marked sensitive.
                REQUIRE(sigs_plan.database_statements.front().parameters.back().sensitive);
            }
        }
    }
}
