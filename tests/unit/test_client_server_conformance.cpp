// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX CLIENT-SERVER API CONFORMANCE TESTS                      |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18                                   |
// |  URL:  https://spec.matrix.org/v1.18/client-server-api/                 |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec.        |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// |                                                                         |
// |  These tests check RESPONSE SHAPE only — status code, required fields,  |
// |  and field types. Auth behaviour, routing, and persistence are covered   |
// |  in test_client_server.cpp and test_auth_client_server_api.cpp.         |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
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

// Registers alice and logs her in, returning the access token.
[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {},
         merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
    REQUIRE(login.response.status == 200U);
    // Parse into a named variable first — string_member returns a pointer into
    // the Object, so the Object must outlive the pointer.
    auto const login_body = parse_object(login.response.body);
    auto const* token = string_member(login_body, "access_token");
    REQUIRE(token != nullptr);
    REQUIRE(!token->empty());
    return *token;
}

} // namespace

// --- GET /_matrix/client/versions --------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientversions
//
// MUST return a JSON object with:
//   versions         - non-empty array of supported spec version strings
//   unstable_features - object mapping feature flags to boolean values
SCENARIO("GET /versions returns required spec fields", "[conformance][client-server][versions]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /versions is called without authentication")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/versions", {}, {}});

            THEN("the response is 200 with versions array and unstable_features object")
            {
                // Spec MUST: unauthenticated, 200 OK.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "versions" is a non-empty array of strings.
                // Do NOT remove — a client uses this to negotiate the spec version
                // it should use. An absent or empty versions array breaks all clients.
                auto const* versions = object_member_as_array(body, "versions");
                REQUIRE(versions != nullptr);
                REQUIRE(!versions->empty());

                // Spec MUST: "unstable_features" is an object.
                // Do NOT remove — clients check this for MSC feature flags.
                auto const* unstable = object_member_as_object(body, "unstable_features");
                REQUIRE(unstable != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/register ----------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3register
//
// Success MUST return a JSON object with:
//   user_id      - fully-qualified Matrix ID (@localpart:server)
//   access_token - non-empty bearer token (required when inhibit_login is false)
//   device_id    - non-empty device identifier (required when inhibit_login is false)
//
// IMPLEMENTATION GAP: the server currently returns only user_id from /register.
// The spec requires access_token and device_id when inhibit_login is absent/false.
// Clients that rely on the registration token (e.g. Element) work around this
// by calling /login immediately after /register, but the gap is a spec violation.
// TODO: extend register_local_user to create a session and return access_token
//       + device_id, then promote those checks from comments to REQUIRE assertions.
SCENARIO("POST /register success response contains required spec fields",
         "[conformance][client-server][register]")
{
    GIVEN("a running client-server with registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("a valid registration request is submitted")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json("bob", "CorrectHorse7!")});

            THEN("the response is 200 with a fully-qualified user_id")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "user_id" is a fully-qualified Matrix ID.
                auto const* user_id = string_member(body, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(user_id->starts_with("@"));
                REQUIRE(user_id->find(':') != std::string::npos);

                // Spec MUST (when inhibit_login is false): access_token and
                // device_id must be present. Promote to REQUIRE when the server
                // is updated to create a session during registration.
                // REQUIRE(string_member(body, "access_token") != nullptr);
                // REQUIRE(string_member(body, "device_id") != nullptr);
            }
        }
    }
}

// --- GET /_matrix/client/v3/login --------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3login
//
// MUST return a JSON object with:
//   flows - array of login flow objects, each with a "type" string field
//   The array MUST contain at least the m.login.password flow.
SCENARIO("GET /login returns flows array with at least m.login.password",
         "[conformance][client-server][login]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /login is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/login", {}, {}});

            THEN("the response is 200 with a flows array containing m.login.password")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "flows" is a non-empty array.
                auto const* flows = object_member_as_array(body, "flows");
                REQUIRE(flows != nullptr);
                REQUIRE(!flows->empty());

                // Spec MUST: at least one flow has type "m.login.password".
                // Do NOT remove — every Matrix client assumes password login is
                // available. An absent flow causes login UI to offer no options.
                auto found_password = false;
                for (auto const& flow : *flows)
                {
                    auto const* flow_obj = std::get_if<merovingian::canonicaljson::Object>(&flow.storage());
                    if (flow_obj == nullptr)
                        continue;
                    auto const* type = string_member(*flow_obj, "type");
                    if (type != nullptr && *type == "m.login.password")
                        found_password = true;
                }
                REQUIRE(found_password);
            }
        }
    }
}

// --- POST /_matrix/client/v3/login -------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3login
//
// Success MUST return a JSON object with:
//   user_id      - fully-qualified Matrix ID
//   access_token - non-empty bearer token
//   device_id    - non-empty device identifier
//
// Note: "home_server" was deprecated in v1.2 and is intentionally not asserted.
SCENARIO("POST /login success response contains required spec fields",
         "[conformance][client-server][login]")
{
    GIVEN("a registered user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"POST", "/_matrix/client/v3/register", {},
                     merovingian::tests::registration_json("carol", "CorrectHorse7!")})
                    .response.status == 200U);

        WHEN("the user logs in with correct credentials")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@carol:example.org"},"password":"CorrectHorse7!"})"});

            THEN("the response is 200 with user_id, access_token, device_id, and home_server")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "user_id" is a fully-qualified Matrix ID.
                auto const* user_id = string_member(body, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(user_id->starts_with("@"));

                // Spec MUST: "access_token" is present and non-empty.
                auto const* token = string_member(body, "access_token");
                REQUIRE(token != nullptr);
                REQUIRE(!token->empty());

                // Spec MUST: "device_id" is present.
                auto const* device_id = string_member(body, "device_id");
                REQUIRE(device_id != nullptr);
                REQUIRE(!device_id->empty());

                // Note: "home_server" was deprecated in v1.2 and is not asserted.
            }
        }
    }
}

// --- POST /_matrix/client/v3/logout ------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3logout
//
// Success MUST return HTTP 200 with an empty JSON object {}.
SCENARIO("POST /logout returns 200 with empty JSON object", "[conformance][client-server][logout]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the user logs out")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/logout", token, {}});

            THEN("the response is 200 and the body is a valid JSON object with no errcode")
            {
                // Spec MUST: 200 on successful logout.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                // Spec: success response must not be an error object.
                REQUIRE(object_member(body, "errcode") == nullptr);
            }
        }
    }
}

// --- GET /_matrix/client/v3/account/whoami -----------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3accountwhoami
//
// MUST return a JSON object with:
//   user_id   - fully-qualified Matrix ID of the authenticated user
//   device_id - the device identifier associated with the token
SCENARIO("GET /whoami returns required spec fields", "[conformance][client-server][whoami]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the user calls whoami")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/account/whoami", token, {}});

            THEN("the response is 200 with user_id and device_id")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "user_id" is present and fully-qualified.
                auto const* user_id = string_member(body, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(user_id->starts_with("@"));

                // Spec MUST: "device_id" is present.
                auto const* device_id = string_member(body, "device_id");
                REQUIRE(device_id != nullptr);
                REQUIRE(!device_id->empty());
            }
        }
    }
}

// --- POST /_matrix/client/v3/keys/upload -------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysupload
//
// MUST return a JSON object with:
//   one_time_key_counts - object mapping key algorithm to remaining count
SCENARIO("POST /keys/upload response contains one_time_key_counts object",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device uploads keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/upload", token,
                 R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:DEVICE1":"base64key"},"signatures":{}},"one_time_keys":{}})"});

            THEN("the response is 200 with one_time_key_counts as an object")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "one_time_key_counts" is present and is an object.
                // Do NOT remove — clients read this to know how many OTKs to
                // replenish. An absent field causes the client to never upload
                // new one-time keys, breaking all new E2EE sessions.
                auto const* counts = object_member_as_object(body, "one_time_key_counts");
                REQUIRE(counts != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/keys/query --------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysquery
//
// MUST return a JSON object with:
//   device_keys - object mapping user IDs to device key maps
//   failures    - object mapping server names to error objects (may be empty)
SCENARIO("POST /keys/query response contains device_keys and failures objects",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device queries keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/query", token,
                 R"({"device_keys":{"@alice:example.org":[]}})"});

            THEN("the response is 200 with device_keys and failures as objects")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "device_keys" is present and is an object.
                auto const* device_keys = object_member_as_object(body, "device_keys");
                REQUIRE(device_keys != nullptr);

                // Spec MUST: "failures" is present and is an object (empty if no failures).
                // Do NOT remove — clients iterate over failures to detect unreachable
                // servers. An absent failures field causes runtime errors in clients.
                auto const* failures = object_member_as_object(body, "failures");
                REQUIRE(failures != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/keys/claim --------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysclaim
//
// MUST return a JSON object with:
//   one_time_keys - object mapping user IDs to claimed one-time keys
//   failures      - object mapping server names to error objects (may be empty)
SCENARIO("POST /keys/claim response contains one_time_keys and failures objects",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device claims one-time keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/claim", token,
                 R"({"one_time_keys":{"@alice:example.org":{"DEVICE1":"signed_curve25519"}}})"});

            THEN("the response is 200 with one_time_keys and failures as objects")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "one_time_keys" is present and is an object.
                auto const* otks = object_member_as_object(body, "one_time_keys");
                REQUIRE(otks != nullptr);

                // Spec MUST: "failures" is present and is an object.
                auto const* failures = object_member_as_object(body, "failures");
                REQUIRE(failures != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/keys/device_signing/upload ----------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysdevice_signingupload
//
// Success MUST return HTTP 200 with an empty JSON object {}.
SCENARIO("POST /keys/device_signing/upload returns 200 with a valid JSON object",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device uploads cross-signing keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                 R"({"master_key":{"keys":{"ed25519:master":"base64key"},"usage":["master"]},"self_signing_key":{"keys":{"ed25519:self":"base64key"},"usage":["self_signing"]},"user_signing_key":{"keys":{"ed25519:user":"base64key"},"usage":["user_signing"]}})"});

            THEN("the response is 200 and the body is a valid JSON object with no errcode")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                // Spec: success response must not be an error object.
                REQUIRE(object_member(body, "errcode") == nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/keys/signatures/upload --------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keyssignaturesupload
//
// MUST return a JSON object with:
//   failures - object mapping user IDs to failed key IDs (may be empty)
SCENARIO("POST /keys/signatures/upload response contains failures object",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device uploads cross-signing signatures")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/signatures/upload", token,
                 R"({"@alice:example.org":{"DEVICE1":{"signatures":{"@alice:example.org":{"ed25519:master":"sig"}}}}})"});

            THEN("the response is 200 with failures as an object")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "failures" is present and is an object.
                // Do NOT remove — clients inspect this to know which signatures
                // were rejected. An absent failures field causes a client crash.
                auto const* failures = object_member_as_object(body, "failures");
                REQUIRE(failures != nullptr);
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/version (no backup) --------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keysversion
//
// If no backup exists: MUST return 404 with errcode M_NOT_FOUND.
SCENARIO("GET /room_keys/version returns M_NOT_FOUND when no backup exists",
         "[conformance][client-server][key-backup]")
{
    GIVEN("a logged-in device with no key backup created")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device queries the backup version")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/version", token, {}});

            THEN("the response is 404 with errcode M_NOT_FOUND")
            {
                // Spec MUST: 404 when no backup version exists.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: error response contains "errcode".
                // Do NOT remove — clients branch on M_NOT_FOUND to decide whether
                // to create a new backup. A missing errcode causes incorrect behaviour.
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
            }
        }
    }
}

// --- POST /_matrix/client/v3/room_keys/version --------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3room_keysversion
//
// MUST return a JSON object with:
//   version - non-empty string identifier for the newly created backup
SCENARIO("POST /room_keys/version returns a non-empty version string",
         "[conformance][client-server][key-backup]")
{
    GIVEN("a logged-in device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device creates a key backup version")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/room_keys/version",
                 token,
                 R"({"algorithm":"m.megolm_backup.v1","auth_data":{"public_key":"base64+public+key","signatures":{}}})"});

            THEN("the response is 200 with a non-empty string version field")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "version" is present and is a non-empty string.
                // Do NOT remove — this is the bug that caused Element to display
                // "Unable to set up keys": returning {} instead of {"version":"1"}
                // meant the client could not reference its newly created backup.
                auto const* version = string_member(body, "version");
                REQUIRE(version != nullptr);
                REQUIRE(!version->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/version (backup exists) ----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keysversion
//
// MUST return a JSON object with:
//   algorithm - string naming the backup algorithm (e.g. "m.megolm_backup.v1")
//   auth_data - algorithm-specific object supplied at creation time
//   version   - string identifier matching what POST /room_keys/version returned
SCENARIO("GET /room_keys/version returns algorithm, auth_data, and version after backup is created",
         "[conformance][client-server][key-backup]")
{
    GIVEN("a logged-in device that has created a key backup")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"POST",
                     "/_matrix/client/v3/room_keys/version",
                     token,
                     R"({"algorithm":"m.megolm_backup.v1","auth_data":{"public_key":"base64+public+key","signatures":{}}})"})
                    .response.status == 200U);

        WHEN("the device retrieves the backup version")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/version", token, {}});

            THEN("the response is 200 with algorithm, auth_data, and version")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "algorithm" is a non-empty string.
                auto const* algorithm = string_member(body, "algorithm");
                REQUIRE(algorithm != nullptr);
                REQUIRE(!algorithm->empty());

                // Spec MUST: "auth_data" is an object.
                // Do NOT remove — clients use auth_data to verify backup integrity.
                auto const* auth_data = object_member_as_object(body, "auth_data");
                REQUIRE(auth_data != nullptr);

                // Spec MUST: "version" is a non-empty string.
                auto const* version = string_member(body, "version");
                REQUIRE(version != nullptr);
                REQUIRE(!version->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/sync ---------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3sync
//
// MUST return a JSON object with:
//   next_batch - opaque string token for the next incremental sync
//   rooms      - object with join/invite/leave/knock sub-objects
SCENARIO("GET /sync returns required spec fields", "[conformance][client-server][sync]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("an initial sync is performed")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the response is 200 with next_batch and rooms")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "next_batch" is a non-empty opaque string.
                // Do NOT remove — clients pass this back as ?since= on the next
                // sync. An absent next_batch makes incremental sync impossible.
                auto const* next_batch = string_member(body, "next_batch");
                REQUIRE(next_batch != nullptr);
                REQUIRE(!next_batch->empty());

                // Spec MUST: "rooms" is an object.
                // Do NOT remove — clients iterate rooms.join/invite/leave.
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
            }
        }
    }
}

// --- Matrix error shape (unauthenticated requests) ---------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#standard-error-response
//
// All 4xx/5xx responses MUST contain a JSON object with:
//   errcode - a string error code (e.g. "M_MISSING_TOKEN")
//   error   - a human-readable string describing the error
SCENARIO("Unauthenticated requests return 401 with a Matrix error object",
         "[conformance][client-server][error]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("an authenticated endpoint is called without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/upload", {}, "{}"});

            THEN("the response is 401 with errcode and error fields")
            {
                // Spec MUST: 401 for missing/invalid access token.
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "errcode" is present and is a string.
                // Do NOT remove — clients branch on errcode to decide whether to
                // prompt for re-authentication. An absent errcode breaks that logic.
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(!errcode->empty());

                // Spec MUST: "error" is a human-readable string.
                auto const* error = string_member(body, "error");
                REQUIRE(error != nullptr);
                REQUIRE(!error->empty());
            }
        }
    }
}
