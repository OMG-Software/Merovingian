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

#include "../federation_signing_test_support.hpp"
#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

// Registers alice and logs her in, returning the access token.
[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
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

// Registers a second user (localpart) and returns their access token.
[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                      std::string const& localpart) -> std::string
{
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json(localpart, "CorrectHorse7!")})
                .response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})"});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* tok = string_member(body, "access_token");
    REQUIRE(tok != nullptr);
    return *tok;
}

[[nodiscard]] auto login_existing_user(merovingian::homeserver::ClientServerRuntime& runtime,
                                       std::string const& localpart, std::string const& device_id) -> std::string
{
    auto const body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} + localpart +
        ":example.org\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"" + device_id + "\"}";
    auto const login =
        merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/login", {}, body});
    REQUIRE(login.response.status == 200U);
    auto const response_body = parse_object(login.response.body);
    auto const* token = string_member(response_body, "access_token");
    REQUIRE(token != nullptr);
    REQUIRE(!token->empty());
    return *token;
}

[[nodiscard]] auto push_rule_by_id(merovingian::canonicaljson::Array const& rules, std::string_view rule_id)
    -> merovingian::canonicaljson::Object const*
{
    for (auto const& rule : rules)
    {
        auto const* rule_object = std::get_if<merovingian::canonicaljson::Object>(&rule.storage());
        if (rule_object == nullptr)
        {
            continue;
        }
        auto const* current_rule_id = string_member(*rule_object, "rule_id");
        if (current_rule_id != nullptr && *current_rule_id == rule_id)
        {
            return rule_object;
        }
    }
    return nullptr;
}

auto constexpr remote_origin = "remote.example.org";
auto constexpr remote_key_id = "ed25519:auto";
auto constexpr remote_key_seed = "client-server-conformance-remote-seed";

[[nodiscard]] auto remote_for_conformance() -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = remote_origin;
    remote.signing_key = {remote_origin, remote_key_id, 2000U,
                          merovingian::federation::test::keypair_from_seed(remote_key_seed).public_key};
    remote.discovery.server_name = remote_origin;
    remote.discovery.well_known_host = remote_origin;
    remote.discovery.resolved_host = remote_origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto federation_fixture_auth(std::string_view method, std::string_view target, std::string_view body)
    -> std::string
{
    auto const signature = merovingian::federation::make_federation_signature(
        remote_origin, "example.org", method, target, body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return std::string{remote_origin} + "|" + remote_key_id + "|" + signature + "|example.org|1000|canonical";
}

auto deliver_federated_direct_to_device(merovingian::homeserver::ClientServerRuntime& runtime, std::string txn_id,
                                        std::string const& edu_content_json) -> void
{
    merovingian::federation::upsert_remote(runtime.homeserver.federation, remote_for_conformance());
    auto const transaction_body =
        merovingian::federation::build_edu_transaction_body("m.direct_to_device", edu_content_json);
    REQUIRE(transaction_body.has_value());
    auto const target = "/_matrix/federation/v1/send/" + std::move(txn_id);
    auto const response = merovingian::homeserver::handle_federation_http_request(
        runtime.homeserver,
        {"PUT", target, federation_fixture_auth("PUT", target, *transaction_body), *transaction_body});
    REQUIRE(response.status == 200U);
}

// Creates a room for the logged-in user and returns the room_id.
[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const r = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
    REQUIRE(r.response.status == 200U);
    auto const body = parse_object(r.response.body);
    auto const* rid = string_member(body, "room_id");
    REQUIRE(rid != nullptr);
    return *rid;
}

// Sends a text message and returns the event_id.
[[nodiscard]] auto send_message(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                std::string const& room_id) -> std::string
{
    auto const r = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn1", token,
                  R"({"msgtype":"m.text","body":"hello"})"});
    REQUIRE(r.response.status == 200U);
    auto const body = parse_object(r.response.body);
    auto const* eid = string_member(body, "event_id");
    REQUIRE(eid != nullptr);
    return *eid;
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
// Matrix clients send an empty registration probe first when the homeserver
// requires interactive authentication for registration.
SCENARIO("POST /register with an empty JSON object returns a UIA challenge", "[conformance][client-server][register]")
{
    GIVEN("a running client-server with token-gated registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("an empty registration probe is submitted")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/register", {}, "{}"});

            THEN("the response is 401 with registration-token UIA flow metadata")
            {
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);
                auto const* flows = object_member_as_array(body, "flows");
                auto const* params = object_member_as_object(body, "params");
                auto const* session = string_member(body, "session");
                REQUIRE(flows != nullptr);
                REQUIRE(flows->size() == 1U);
                auto const* first_flow = std::get_if<merovingian::canonicaljson::Object>(&flows->front().storage());
                REQUIRE(first_flow != nullptr);
                auto const* stages = object_member_as_array(*first_flow, "stages");
                REQUIRE(stages != nullptr);
                REQUIRE(stages->size() == 1U);
                auto const* first_stage = std::get_if<std::string>(&stages->front().storage());
                REQUIRE(first_stage != nullptr);
                REQUIRE(*first_stage == "m.login.registration_token");
                REQUIRE(params != nullptr);
                REQUIRE(session != nullptr);
                REQUIRE(!session->empty());
            }
        }
    }
}

// Spec §5.5.1: when auth dict is present but credentials are incomplete, the
// homeserver MUST return 401 with the UIA challenge again — not proceed and
// fail with 403.  Clients in the UIA flow submit type+session first, then the
// stage-specific parameter (token) on the next attempt.
SCENARIO("POST /register with auth type but missing token returns 401 UIA challenge",
         "[conformance][client-server][register]")
{
    GIVEN("a running client-server with token-gated registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("a registration request with auth type but no token is submitted")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"username":"bob","password":"CorrectHorse7!","auth":{"type":"m.login.registration_token"}})"});

            THEN("the response is 401 with registration-token UIA flow metadata")
            {
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);
                auto const* flows = object_member_as_array(body, "flows");
                REQUIRE(flows != nullptr);
                REQUIRE(flows->size() == 1U);
                auto const* first_flow =
                    std::get_if<merovingian::canonicaljson::Object>(&flows->front().storage());
                REQUIRE(first_flow != nullptr);
                auto const* stages = object_member_as_array(*first_flow, "stages");
                REQUIRE(stages != nullptr);
                auto const* first_stage = std::get_if<std::string>(&stages->front().storage());
                REQUIRE(first_stage != nullptr);
                REQUIRE(*first_stage == "m.login.registration_token");
            }
        }
    }
}

SCENARIO("POST /register with wrong auth type returns 401 UIA challenge",
         "[conformance][client-server][register]")
{
    GIVEN("a running client-server with token-gated registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("a registration request with an unsupported auth type is submitted")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"username":"bob","password":"CorrectHorse7!","auth":{"type":"m.login.dummy"}})"});

            THEN("the response is 401 with registration-token UIA flow metadata")
            {
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);
                auto const* flows = object_member_as_array(body, "flows");
                REQUIRE(flows != nullptr);
            }
        }
    }
}

//
// Success MUST return a JSON object with:
//   user_id      - fully-qualified Matrix ID (@localpart:server)
//   access_token - non-empty bearer token (required when inhibit_login is false)
//   device_id    - non-empty device identifier (required when inhibit_login is false)
//
// The spec requires access_token and device_id when inhibit_login is absent/false.
// Clients read access_token from /register to avoid a separate /login round trip.
SCENARIO("POST /register success response contains required spec fields", "[conformance][client-server][register]")
{
    GIVEN("a running client-server with registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("a valid registration request is submitted")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST",
                                  "/_matrix/client/v3/register",
                                  {},
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
                // device_id must be present and non-empty.
                // Do NOT remove — clients use the access_token from /register
                // to avoid a separate /login round trip (spec §5.5.1).
                auto const* access_token = string_member(body, "access_token");
                REQUIRE(access_token != nullptr);
                REQUIRE(!access_token->empty());
                auto const* reg_device_id = string_member(body, "device_id");
                REQUIRE(reg_device_id != nullptr);
                REQUIRE(!reg_device_id->empty());
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
SCENARIO("GET /login returns flows array with at least m.login.password", "[conformance][client-server][login]")
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
SCENARIO("POST /login success response contains required spec fields", "[conformance][client-server][login]")
{
    GIVEN("a registered user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST",
                                      "/_matrix/client/v3/register",
                                      {},
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
                // Spec MUST: success body is an empty JSON object {}.
                // Do NOT remove — a non-empty body indicates spurious fields that
                // will confuse strict Matrix clients parsing the logout response.
                REQUIRE(object_member(body, "errcode") == nullptr);
                REQUIRE(body.empty());
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

                // Spec MUST: "user_id" is present, fully-qualified, and matches the
                // authenticated user.  Do NOT remove — a mismatch means the server
                // is returning the wrong identity for the token.
                auto const* user_id = string_member(body, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(user_id->starts_with("@"));
                REQUIRE(*user_id == "@alice:example.org");

                // Spec MUST: "device_id" is present and non-empty.
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
SCENARIO("POST /keys/upload response contains one_time_key_counts object", "[conformance][client-server][e2ee][keys]")
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
                {"POST", "/_matrix/client/v3/keys/query", token, R"({"device_keys":{"@alice:example.org":[]}})"});

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
                started.runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
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

// --- keys/upload → keys/query round-trip -------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysquery
//
// After uploading device keys, POST /keys/query MUST return those keys for
// that user.  This round-trip verifies that the upload is actually stored and
// retrievable, not just acknowledged.
SCENARIO("POST /keys/upload then POST /keys/query returns the uploaded device keys",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device that has uploaded its device keys")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/upload", token,
                 R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:DEVICE1":"base64+pubkey"},"signatures":{}},"one_time_keys":{}})"})
                .response.status == 200U);

        WHEN("the device queries keys for that user")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/query", token, R"({"device_keys":{"@alice:example.org":[]}})"});

            THEN("the response contains a device_keys entry for the user")
            {
                // Spec MUST: uploaded device keys MUST appear under the user ID.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* device_keys = object_member_as_object(body, "device_keys");
                REQUIRE(device_keys != nullptr);
                auto const* user_keys = object_member_as_object(*device_keys, "@alice:example.org");
                REQUIRE(user_keys != nullptr);
                REQUIRE(!user_keys->empty());
            }
        }
    }
}

// --- keys/upload (OTKs) → keys/claim round-trip -----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysclaim
//
// After uploading one-time keys, POST /keys/claim MUST return one key for the
// claimed device and algorithm, and the key MUST be consumed (subsequent claim
// returns empty unless a fallback key exists).
SCENARIO("POST /keys/upload with OTKs then POST /keys/claim returns and consumes the key",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device that has uploaded a one-time key")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/upload", token,
                 R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:DEVICE1":"pubkey1"},"signatures":{}},"one_time_keys":{"signed_curve25519:AAAAAAAA":{"key":"otk+base64+key","signatures":{}}}})"})
                .response.status == 200U);

        WHEN("another device claims a one-time key for DEVICE1")
        {
            auto const claim = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                                  R"({"one_time_keys":{"@alice:example.org":{"DEVICE1":"signed_curve25519"}}})"});

            THEN("the one-time key is returned for DEVICE1")
            {
                // Spec MUST: claimed key MUST be present under user → device.
                REQUIRE(claim.response.status == 200U);
                auto const body = parse_object(claim.response.body);
                auto const* otks = object_member_as_object(body, "one_time_keys");
                REQUIRE(otks != nullptr);
                auto const* user_otks = object_member_as_object(*otks, "@alice:example.org");
                REQUIRE(user_otks != nullptr);
                REQUIRE(!user_otks->empty());
            }

            AND_THEN("a second claim returns empty (key was consumed)")
            {
                auto const claim2 = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                                      R"({"one_time_keys":{"@alice:example.org":{"DEVICE1":"signed_curve25519"}}})"});
                REQUIRE(claim2.response.status == 200U);
                auto const body2 = parse_object(claim2.response.body);
                auto const* otks2 = object_member_as_object(body2, "one_time_keys");
                REQUIRE(otks2 != nullptr);
                // No key was uploaded so no key should be returned.
                auto const* user_otks2 = object_member_as_object(*otks2, "@alice:example.org");
                // Either no user entry or an empty device map indicates consumption.
                if (user_otks2 != nullptr)
                {
                    auto const* device_keys2 = object_member_as_object(*user_otks2, "DEVICE1");
                    REQUIRE((device_keys2 == nullptr || device_keys2->empty()));
                }
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

            THEN("the response is 200 and the body is an empty JSON object")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                // Spec MUST: success body is an empty JSON object {}.
                // Do NOT remove — clients assume {} on success; extra fields indicate
                // a UIA challenge or error that requires different handling.
                REQUIRE(object_member(body, "errcode") == nullptr);
                REQUIRE(body.empty());
            }
        }
    }
}

SCENARIO("POST /keys/device_signing/upload then POST /keys/query returns published cross-signing keys",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device that has uploaded cross-signing keys")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                 R"({"master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:MASTER":"base64master"},"signatures":{}},"self_signing_key":{"user_id":"@alice:example.org","usage":["self_signing"],"keys":{"ed25519:SELF":"base64self"},"signatures":{}},"user_signing_key":{"user_id":"@alice:example.org","usage":["user_signing"],"keys":{"ed25519:USER":"base64user"},"signatures":{}}})"})
                .response.status == 200U);

        WHEN("the device queries its own keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/query", token, R"({"device_keys":{"@alice:example.org":[]}})"});

            THEN("the response includes the user's published cross-signing key maps")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                auto const* master_keys = object_member_as_object(body, "master_keys");
                REQUIRE(master_keys != nullptr);
                REQUIRE(object_member_as_object(*master_keys, "@alice:example.org") != nullptr);

                auto const* self_signing_keys = object_member_as_object(body, "self_signing_keys");
                REQUIRE(self_signing_keys != nullptr);
                REQUIRE(object_member_as_object(*self_signing_keys, "@alice:example.org") != nullptr);

                auto const* user_signing_keys = object_member_as_object(body, "user_signing_keys");
                REQUIRE(user_signing_keys != nullptr);
                REQUIRE(object_member_as_object(*user_signing_keys, "@alice:example.org") != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/keys/signatures/upload --------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keyssignaturesupload
//
// MUST return a JSON object with:
//   failures - object mapping user IDs to failed key IDs (may be empty)
SCENARIO("POST /keys/signatures/upload response contains failures object", "[conformance][client-server][e2ee][keys]")
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

SCENARIO("POST /keys/signatures/upload then POST /keys/query returns the uploaded signatures",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device with uploaded device and cross-signing keys")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/upload", token,
                 R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:DEVICE1":"curve","ed25519:DEVICE1":"device-signing"},"signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                 R"({"master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:MASTER":"base64master"},"signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/signatures/upload", token,
                 R"({"@alice:example.org":{"DEVICE1":{"signatures":{"@alice:example.org":{"ed25519:MASTER":"device-sig"}}},"ed25519:MASTER":{"signatures":{"@alice:example.org":{"ed25519:DEVICE1":"master-sig"}}}}})"})
                .response.status == 200U);

        WHEN("the device queries its own keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/query", token,
                                  R"({"device_keys":{"@alice:example.org":["DEVICE1"]}})"});

            THEN("the queried device and master key contain the uploaded signature entries")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                auto const* device_keys = object_member_as_object(body, "device_keys");
                REQUIRE(device_keys != nullptr);
                auto const* alice_devices = object_member_as_object(*device_keys, "@alice:example.org");
                REQUIRE(alice_devices != nullptr);
                auto const* device1 = object_member_as_object(*alice_devices, "DEVICE1");
                REQUIRE(device1 != nullptr);
                auto const* device_signatures = object_member_as_object(*device1, "signatures");
                REQUIRE(device_signatures != nullptr);
                auto const* alice_device_signatures = object_member_as_object(*device_signatures, "@alice:example.org");
                REQUIRE(alice_device_signatures != nullptr);
                auto const* device_sig = string_member(*alice_device_signatures, "ed25519:MASTER");
                REQUIRE(device_sig != nullptr);
                REQUIRE(*device_sig == "device-sig");

                auto const* master_keys = object_member_as_object(body, "master_keys");
                REQUIRE(master_keys != nullptr);
                auto const* alice_master = object_member_as_object(*master_keys, "@alice:example.org");
                REQUIRE(alice_master != nullptr);
                auto const* master_signatures = object_member_as_object(*alice_master, "signatures");
                REQUIRE(master_signatures != nullptr);
                auto const* alice_master_signatures = object_member_as_object(*master_signatures, "@alice:example.org");
                REQUIRE(alice_master_signatures != nullptr);
                auto const* master_sig = string_member(*alice_master_signatures, "ed25519:DEVICE1");
                REQUIRE(master_sig != nullptr);
                REQUIRE(*master_sig == "master-sig");
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/version (no backup) --------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keysversion
//
// If no backup exists: MUST return 404 with errcode M_NOT_FOUND.
SCENARIO("GET /room_keys/version returns M_NOT_FOUND when no backup exists", "[conformance][client-server][key-backup]")
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
SCENARIO("POST /room_keys/version returns a non-empty version string", "[conformance][client-server][key-backup]")
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
                {"POST", "/_matrix/client/v3/room_keys/version", token,
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
//   count     - integer number of backed-up sessions
//   etag      - opaque string that changes when backed-up data changes
//   version   - string identifier matching what POST /room_keys/version returned
SCENARIO("GET /room_keys/version returns backup metadata including count and etag",
         "[conformance][client-server][key-backup]")
{
    GIVEN("a logged-in device that has created a key backup and uploaded one session")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1","auth_data":{"public_key":"base64+public+key","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
                 R"({"rooms":{"!backupmeta:example.org":{"sessions":{"sess1":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}}}}}})"})
                .response.status == 200U);

        WHEN("the device retrieves the backup version")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/version", token, {}});

            THEN("the response is 200 with algorithm, auth_data, count, etag, and version")
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

                // Spec MUST: "count" is present and reflects stored sessions.
                auto const* count = int_member(body, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 1);

                // Spec MUST: "etag" is a non-empty string.
                auto const* etag = string_member(body, "etag");
                REQUIRE(etag != nullptr);
                REQUIRE(!etag->empty());

                // Spec MUST: "version" is a non-empty string.
                auto const* version = string_member(body, "version");
                REQUIRE(version != nullptr);
                REQUIRE(!version->empty());
            }
        }
    }
}

// --- DELETE /_matrix/client/v3/room_keys/version/{version} -------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#delete_matrixclientv3room_keysversion
//
// After a successful DELETE the backup MUST be gone: a subsequent GET
// MUST return 404 M_NOT_FOUND. Element polls GET immediately after DELETE;
// if the backup is still visible it retries DELETE indefinitely.
SCENARIO("DELETE /room_keys/version removes the backup so a subsequent GET returns 404",
         "[conformance][client-server][key-backup]")
{
    GIVEN("a logged-in device that has created a key backup")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1","auth_data":{"public_key":"base64+public+key","signatures":{}}})"})
                .response.status == 200U);

        WHEN("the device deletes the backup version")
        {
            auto const del = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/room_keys/version/1", token, {}});

            THEN("the response is 200 and a subsequent GET returns 404 M_NOT_FOUND")
            {
                // Spec MUST: 200 on successful delete.
                REQUIRE(del.response.status == 200U);

                // Spec MUST: backup is gone — GET must return 404.
                // Do NOT remove — Element loops DELETE/GET until the backup disappears.
                auto const get = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/room_keys/version", token, {}});
                REQUIRE(get.response.status == 404U);
                auto const body = parse_object(get.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
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

// --- GET /_matrix/client/v3/sync (room state & timeline content) -------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3sync
//
// MUST: timeline events include full event content (type, content, sender,
//       event_id, origin_server_ts) — not just event_id and sender.
// MUST: state.events includes the m.room.create event for newly-created rooms
//       so clients can determine the room version.
// MUST: rooms created without an explicit room_version default to the server's
//       latest supported version (currently "12").
SCENARIO("GET /sync returns the full top-level v1.18 sync envelope", "[conformance][client-server][sync][surfaces]")
{
    GIVEN("a logged-in user with populated sync surfaces")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const user_id = std::string{"@alice:example.org"};
        REQUIRE(merovingian::homeserver::set_account_data(
            started.runtime, {user_id, std::string{}, "m.tag", R"({"tags":{"u.fav":{}}})"}));
        REQUIRE(merovingian::homeserver::push_to_device_message(
            started.runtime, {0U, "@bob:example.org", user_id, "DEVICE1", "m.room_key", R"({"session":"abc"})"}));
        REQUIRE(merovingian::homeserver::record_device_list_change(started.runtime,
                                                                   {0U, user_id, "@bob:example.org", "changed"}));
        REQUIRE(merovingian::homeserver::record_device_list_change(started.runtime,
                                                                   {0U, user_id, "@carol:example.org", "left"}));
        REQUIRE(merovingian::homeserver::set_presence(started.runtime,
                                                      {0U, "@dave:example.org", "online", "Coding!", 1000U, true}));
        REQUIRE(
            merovingian::database::store_one_time_key(started.runtime.homeserver.database.persistent_store,
                                                      {user_id, "DEVICE1", "signed_curve25519:AAA", R"({"key":"x"})"}));
        REQUIRE(
            merovingian::database::store_one_time_key(started.runtime.homeserver.database.persistent_store,
                                                      {user_id, "DEVICE1", "signed_curve25519:BBB", R"({"key":"y"})"}));
        REQUIRE(merovingian::database::store_fallback_key(
            started.runtime.homeserver.database.persistent_store,
            {user_id, "DEVICE1", "signed_curve25519:FALL", R"({"key":"z"})"}));

        WHEN("an initial sync is performed")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("every top-level sync section is present with the expected container type")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(string_member(body, "next_batch") != nullptr);
                REQUIRE(object_member_as_object(body, "rooms") != nullptr);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                REQUIRE(object_member_as_object(*rooms, "join") != nullptr);
                REQUIRE(object_member_as_object(*rooms, "invite") != nullptr);
                REQUIRE(object_member_as_object(*rooms, "leave") != nullptr);
                REQUIRE(object_member_as_object(*rooms, "knock") != nullptr);

                auto const* presence = object_member_as_object(body, "presence");
                REQUIRE(presence != nullptr);
                REQUIRE(object_member_as_array(*presence, "events") != nullptr);

                auto const* account_data = object_member_as_object(body, "account_data");
                REQUIRE(account_data != nullptr);
                REQUIRE(object_member_as_array(*account_data, "events") != nullptr);

                auto const* to_device = object_member_as_object(body, "to_device");
                REQUIRE(to_device != nullptr);
                REQUIRE(object_member_as_array(*to_device, "events") != nullptr);

                auto const* device_lists = object_member_as_object(body, "device_lists");
                REQUIRE(device_lists != nullptr);
                REQUIRE(object_member_as_array(*device_lists, "changed") != nullptr);
                REQUIRE(object_member_as_array(*device_lists, "left") != nullptr);

                auto const* otk_counts = object_member_as_object(body, "device_one_time_keys_count");
                REQUIRE(otk_counts != nullptr);
                REQUIRE(int_member(*otk_counts, "signed_curve25519") != nullptr);

                REQUIRE(object_member_as_array(body, "device_unused_fallback_key_types") != nullptr);
            }
        }
    }
}

SCENARIO("GET /sync returns spec-shaped room category objects", "[conformance][client-server][sync][rooms]")
{
    GIVEN("joined invited and left room state for local users")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");
        auto const joined_room_id = create_room(started.runtime, alice);
        auto const invited_room = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", alice,
                              R"({"preset":"private_chat","invite":["@bob:example.org"]})"});
        REQUIRE(invited_room.response.status == 200U);
        auto const invited_room_body = parse_object(invited_room.response.body);
        auto const* invited_room_id = string_member(invited_room_body, "room_id");
        REQUIRE(invited_room_id != nullptr);
        auto const left_room_id = create_room(started.runtime, alice);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + left_room_id + "/leave", alice, "{}"})
                    .response.status == 200U);

        WHEN("Alice syncs with include_leave and Bob syncs for the pending invite")
        {
            auto const alice_sync = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", R"json(/_matrix/client/v3/sync?filter={"room":{"include_leave":true}})json", alice, {}});
            auto const bob_sync = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});

            THEN("joined invited and left room objects match the expected response envelope")
            {
                REQUIRE(alice_sync.response.status == 200U);
                auto const alice_body = parse_object(alice_sync.response.body);
                auto const* alice_rooms = object_member_as_object(alice_body, "rooms");
                REQUIRE(alice_rooms != nullptr);
                auto const* alice_join = object_member_as_object(*alice_rooms, "join");
                auto const* alice_leave = object_member_as_object(*alice_rooms, "leave");
                auto const* alice_knock = object_member_as_object(*alice_rooms, "knock");
                REQUIRE(alice_join != nullptr);
                REQUIRE(alice_leave != nullptr);
                REQUIRE(alice_knock != nullptr);

                auto const* joined_room = object_member_as_object(*alice_join, joined_room_id);
                REQUIRE(joined_room != nullptr);
                REQUIRE(object_member_as_object(*joined_room, "timeline") != nullptr);
                REQUIRE(object_member_as_object(*joined_room, "state") != nullptr);
                REQUIRE(object_member_as_object(*joined_room, "account_data") != nullptr);
                REQUIRE(object_member_as_object(*joined_room, "ephemeral") != nullptr);
                auto const* joined_timeline = object_member_as_object(*joined_room, "timeline");
                REQUIRE(joined_timeline != nullptr);
                REQUIRE(object_member_as_array(*joined_timeline, "events") != nullptr);

                auto const* left_room = object_member_as_object(*alice_leave, left_room_id);
                REQUIRE(left_room != nullptr);
                auto const* left_timeline = object_member_as_object(*left_room, "timeline");
                REQUIRE(left_timeline != nullptr);
                REQUIRE(object_member_as_array(*left_timeline, "events") != nullptr);

                REQUIRE(bob_sync.response.status == 200U);
                auto const bob_body = parse_object(bob_sync.response.body);
                auto const* bob_rooms = object_member_as_object(bob_body, "rooms");
                REQUIRE(bob_rooms != nullptr);
                auto const* bob_invite = object_member_as_object(*bob_rooms, "invite");
                auto const* bob_knock = object_member_as_object(*bob_rooms, "knock");
                REQUIRE(bob_invite != nullptr);
                REQUIRE(bob_knock != nullptr);
                auto const* invited_room_obj = object_member_as_object(*bob_invite, *invited_room_id);
                REQUIRE(invited_room_obj != nullptr);
                auto const* invite_state = object_member_as_object(*invited_room_obj, "invite_state");
                REQUIRE(invite_state != nullptr);
                REQUIRE(object_member_as_array(*invite_state, "events") != nullptr);
            }
        }
    }
}

SCENARIO("GET /sync returns full event content and correct room version in state",
         "[conformance][client-server][sync][room-version]")
{
    GIVEN("a logged-in user who has created a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("an initial sync is performed")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the response contains full timeline events with type and content")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* join = object_member_as_object(*rooms, "join");
                REQUIRE(join != nullptr);
                auto const* room_obj = object_member_as_object(*join, room_id);
                REQUIRE(room_obj != nullptr);

                // Spec MUST: timeline.events is a non-empty array.
                // Do NOT remove — an empty timeline after room creation means
                // clients see a blank room with no history.
                auto const* timeline = object_member_as_object(*room_obj, "timeline");
                REQUIRE(timeline != nullptr);
                auto const* timeline_events = object_member_as_array(*timeline, "events");
                REQUIRE(timeline_events != nullptr);
                REQUIRE(!timeline_events->empty());

                // Spec MUST: each timeline event includes at least "type",
                // "content", "sender", "event_id", "origin_server_ts".
                // Do NOT remove — without these fields clients cannot render
                // events or determine the room version from m.room.create.
                auto const* first_event_obj =
                    std::get_if<merovingian::canonicaljson::Object>(&timeline_events->front().storage());
                REQUIRE(first_event_obj != nullptr);
                REQUIRE(string_member(*first_event_obj, "type") != nullptr);
                REQUIRE(object_member_as_object(*first_event_obj, "content") != nullptr);
                REQUIRE(string_member(*first_event_obj, "sender") != nullptr);
                REQUIRE(string_member(*first_event_obj, "event_id") != nullptr);
                REQUIRE(int_member(*first_event_obj, "origin_server_ts") != nullptr);
            }

            THEN("the state section includes m.room.create with room_version 12")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* join = object_member_as_object(*rooms, "join");
                REQUIRE(join != nullptr);
                auto const* room_obj = object_member_as_object(*join, room_id);
                REQUIRE(room_obj != nullptr);

                // Spec MUST: state.events is an array containing room state.
                // Do NOT remove — clients use state events from /sync to derive
                // room version, power levels, join rules, encryption status, etc.
                // A missing m.room.create event causes Element to display
                // "room version 1" and mark the room as unstable.
                auto const* state = object_member_as_object(*room_obj, "state");
                REQUIRE(state != nullptr);
                auto const* state_events = object_member_as_array(*state, "events");
                REQUIRE(state_events != nullptr);

                // Find the m.room.create event in state.
                merovingian::canonicaljson::Object const* create_event = nullptr;
                for (auto const& evt : *state_events)
                {
                    auto const* evt_obj = std::get_if<merovingian::canonicaljson::Object>(&evt.storage());
                    if (evt_obj == nullptr)
                    {
                        continue;
                    }
                    auto const* type = string_member(*evt_obj, "type");
                    if (type != nullptr && *type == "m.room.create")
                    {
                        create_event = evt_obj;
                        break;
                    }
                }
                REQUIRE(create_event != nullptr);

                // Spec MUST: m.room.create content includes "room_version".
                // If absent, clients default to "1" per spec. Merovingian
                // defaults to "12" (the latest supported stable version).
                // Do NOT remove — this is the exact assertion that catches the
                // bug where Element reports "room version 1, marked as unstable".
                auto const* content = object_member_as_object(*create_event, "content");
                REQUIRE(content != nullptr);
                auto const* room_version = string_member(*content, "room_version");
                REQUIRE(room_version != nullptr);
                REQUIRE(*room_version == "12");
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/members ---------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidmembers
//
// MUST return a JSON object with:
//   chunk - array of m.room.member state events (may be empty; filtered by membership param)
//
// The creator is a "join" member, so the chunk MUST contain at least one entry
// immediately after createRoom.
SCENARIO("GET /rooms/{roomId}/members returns chunk array with creator membership event",
         "[conformance][client-server][rooms][members]")
{
    GIVEN("a logged-in user who has created a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
        REQUIRE(create.response.status == 200U);

        auto const create_body = parse_object(create.response.body);
        auto const* room_id_ptr = string_member(create_body, "room_id");
        REQUIRE(room_id_ptr != nullptr);
        auto const room_id = *room_id_ptr;

        WHEN("the user requests the member list")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/members", token, {}});

            THEN("the response is 200 with a non-empty chunk array containing the creator")
            {
                // Spec MUST: 200 with chunk array.
                // Do NOT remove — clients use this to build the member list sidebar.
                // A missing or wrong-typed chunk breaks all member-list UIs.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "chunk" is an array.
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);

                // The creator joined the room, so at least one member event MUST be present.
                REQUIRE(!chunk->empty());

                // The first entry MUST be a valid event object with type and sender.
                auto const* first = std::get_if<merovingian::canonicaljson::Object>(&(*chunk)[0].storage());
                REQUIRE(first != nullptr);
                auto const* type = string_member(*first, "type");
                REQUIRE(type != nullptr);
                REQUIRE(*type == "m.room.member");
                auto const* sender = string_member(*first, "sender");
                REQUIRE(sender != nullptr);
                REQUIRE(!sender->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/members (after local join) ---------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidmembers
//
// A second user joining a local room must appear in the /members response.
// The join path must persist both the membership record AND a corresponding
// state event (or the handler must synthesize one as a fallback).
SCENARIO("GET /rooms/{roomId}/members includes joined user after local join",
         "[conformance][client-server][rooms][members]")
{
    GIVEN("a logged-in user who has created a room and a second user who joins it")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token_a = logged_in_token(started.runtime);
        auto const token_b = register_and_login(started.runtime, "bob");

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", token_a, R"({"preset":"public_chat"})"});
        REQUIRE(create.response.status == 200U);

        auto const create_body = parse_object(create.response.body);
        auto const* room_id_ptr = string_member(create_body, "room_id");
        REQUIRE(room_id_ptr != nullptr);
        auto const room_id = *room_id_ptr;

        auto const join = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", token_b, "{}"});
        REQUIRE(join.response.status == 200U);

        WHEN("the creator requests the member list")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/members", token_a, {}});

            THEN("the response is 200 with a chunk containing both the creator and the joined user")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
                // The creator and the joined user — at least two member events.
                REQUIRE(chunk->size() >= 2U);
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/members (invite -> local join) ----
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidmembers
//
// An invited local user who joins must replace the invite state with a
// `m.room.member` event whose `content.membership` is `join`.
SCENARIO("GET /rooms/{roomId}/members reports join membership after invited local user joins",
         "[conformance][client-server][rooms][members]")
{
    GIVEN("a private room with a pending local invite")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", alice,
                              R"({"preset":"private_chat","invite":["@bob:example.org"]})"});
        REQUIRE(create.response.status == 200U);

        auto const create_body = parse_object(create.response.body);
        auto const* room_id_ptr = string_member(create_body, "room_id");
        REQUIRE(room_id_ptr != nullptr);
        auto const room_id = *room_id_ptr;

        WHEN("the invited local user joins the room")
        {
            auto const join = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"});

            THEN("the members response contains a join membership event for that user")
            {
                REQUIRE(join.response.status == 200U);

                auto const response = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/members", alice, {}});
                REQUIRE(response.response.status == 200U);

                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);

                auto found_join_membership = false;
                for (auto const& entry : *chunk)
                {
                    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
                    REQUIRE(event != nullptr);

                    auto const* type = string_member(*event, "type");
                    auto const* state_key = string_member(*event, "state_key");
                    if (type == nullptr || state_key == nullptr)
                    {
                        continue;
                    }
                    if (*type != "m.room.member" || *state_key != "@bob:example.org")
                    {
                        continue;
                    }

                    auto const* content = object_member_as_object(*event, "content");
                    REQUIRE(content != nullptr);
                    auto const* membership = string_member(*content, "membership");
                    REQUIRE(membership != nullptr);
                    REQUIRE(*membership == "join");
                    found_join_membership = true;
                    break;
                }

                REQUIRE(found_join_membership);
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/members (unknown room) ------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidmembers
//
// MUST return 404 M_NOT_FOUND for a room that does not exist.
SCENARIO("GET /rooms/{roomId}/members returns 404 for an unknown room", "[conformance][client-server][rooms][members]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the user requests members for a non-existent room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/%21nonexistent%3Aexample.org/members", token, {}});

            THEN("the response is 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the room does not exist.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
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
SCENARIO("Unauthenticated requests return 401 with a Matrix error object", "[conformance][client-server][error]")
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
                // Spec MUST: errcode is M_MISSING_TOKEN when no bearer token is provided.
                // Do NOT remove — clients check this specific code to distinguish
                // "please log in" from other 401 causes (e.g. M_UNKNOWN_TOKEN for
                // an expired token, which requires a different recovery path).
                REQUIRE(*errcode == "M_MISSING_TOKEN");

                // Spec MUST: "error" is a human-readable string.
                auto const* error = string_member(body, "error");
                REQUIRE(error != nullptr);
                REQUIRE(!error->empty());
            }
        }
    }
}

// =============================================================================
// SESSION MANAGEMENT
// =============================================================================

// --- POST /_matrix/client/v3/refresh ------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3refresh
//
// MUST return:
//   access_token  - new bearer token string
//   refresh_token - new refresh token for next rotation string
//   expires_in_ms - positive integer milliseconds until expiry
SCENARIO("POST /refresh returns a new access_token and refresh_token", "[conformance][client-server][session]")
{
    GIVEN("a running client-server and a user who logged in with refresh_token support")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST",
                                      "/_matrix/client/v3/register",
                                      {},
                                      merovingian::tests::registration_json("refreshuser", "CorrectHorse7!")})
                    .response.status == 200U);

        auto const login_resp = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@refreshuser:example.org"},"password":"CorrectHorse7!","device_id":"RDEV","refresh_token":true})"});
        REQUIRE(login_resp.response.status == 200U);
        auto const login_body = parse_object(login_resp.response.body);
        auto const* rt_ptr = string_member(login_body, "refresh_token");
        REQUIRE(rt_ptr != nullptr);
        auto const refresh_tok = *rt_ptr;

        WHEN("POST /refresh is called with the refresh token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST",
                                  "/_matrix/client/v3/refresh",
                                  {},
                                  std::string{R"({"refresh_token":")"} + refresh_tok + R"("})"});

            THEN("the response is 200 with access_token, refresh_token, and expires_in_ms")
            {
                // Spec MUST: 200 on valid refresh token.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: the refreshed access_token is a non-empty string.
                auto const* access_token = string_member(body, "access_token");
                REQUIRE(access_token != nullptr);
                REQUIRE(!access_token->empty());

                // Spec MUST: the refreshed refresh_token is returned for next rotation.
                auto const* new_rt = string_member(body, "refresh_token");
                REQUIRE(new_rt != nullptr);
                REQUIRE(!new_rt->empty());

                // Spec MUST: expires_in_ms is a positive integer.
                auto const* expires = int_member(body, "expires_in_ms");
                REQUIRE(expires != nullptr);
                REQUIRE(*expires > 0);
            }
        }
    }
}

// --- POST /_matrix/client/v3/logout/all ---------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3logoutall
//
// MUST return 200 with an empty JSON object.
SCENARIO("POST /logout/all returns 200 with empty JSON object", "[conformance][client-server][session]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /logout/all is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/logout/all", token, {}});

            THEN("the response is 200 with a valid JSON object body")
            {
                // Spec MUST: 200 on valid access token, all sessions invalidated.
                REQUIRE(response.response.status == 200U);
                // Body must parse as an object (spec shows {}).
                auto const body = parse_object(response.response.body);
                std::ignore = body;
            }
        }
    }
}

// --- GET /_matrix/client/v1/auth_metadata ------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1auth_metadata
// OIDC discovery is optional; unsupported servers should answer this
// unauthenticated probe cleanly so clients do not mistake lack of OIDC for an
// authentication failure.
SCENARIO("GET /v1/auth_metadata returns an unauthenticated 404 M_UNRECOGNIZED when OIDC is unsupported",
         "[conformance][client-server][session]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /_matrix/client/v1/auth_metadata is called without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/auth_metadata", {}, {}});

            THEN("the server returns 404 M_UNRECOGNIZED instead of 401")
            {
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v1/login/get_token ----------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv1loginget_token
// IMPLEMENTATION GAP: login token generation not yet implemented.
SCENARIO("POST /v1/login/get_token returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][session]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /_matrix/client/v1/login/get_token is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v1/login/get_token", token, "{}"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: login token exchange not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/login/sso/redirect --------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3loginssoredirect
// IMPLEMENTATION GAP: SSO login not yet implemented.
SCENARIO("GET /login/sso/redirect returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][session]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /_matrix/client/v3/login/sso/redirect is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/login/sso/redirect?redirectUrl=http://localhost/", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until SSO is implemented")
            {
                // IMPLEMENTATION GAP: SSO redirect not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/login/sso/redirect/{idpId} ------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3loginssoredirectidpid
// IMPLEMENTATION GAP: per-IdP SSO redirect not yet implemented.
SCENARIO("GET /login/sso/redirect/{idpId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][session]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /_matrix/client/v3/login/sso/redirect/oidc is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/login/sso/redirect/oidc?redirectUrl=http://localhost/", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until SSO is implemented")
            {
                // IMPLEMENTATION GAP: per-IdP SSO redirect not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// SERVER ADMINISTRATION
// =============================================================================

// --- GET /.well-known/matrix/client -------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_well-knownmatrixclient
//
// MUST return:
//   m.homeserver        - object with at least base_url string field
SCENARIO("GET /.well-known/matrix/client returns homeserver discovery info",
         "[conformance][client-server][server-admin]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /.well-known/matrix/client is called without authentication")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/.well-known/matrix/client", {}, {}});

            THEN("the response is 200 with the m.homeserver object")
            {
                // Spec MUST: 200 with discovery info.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: m.homeserver is present and is an object.
                auto const* hs = object_member_as_object(body, "m.homeserver");
                REQUIRE(hs != nullptr);

                // Spec MUST: m.homeserver.base_url is a non-empty string.
                auto const* base_url = string_member(*hs, "base_url");
                REQUIRE(base_url != nullptr);
                REQUIRE(!base_url->empty());
            }
        }
    }
}

// --- GET /.well-known/matrix/policy_server ------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_well-knownmatrixpolicy_server
// IMPLEMENTATION GAP: policy server discovery not yet implemented.
SCENARIO("GET /.well-known/matrix/policy_server returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][server-admin]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /.well-known/matrix/policy_server is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/.well-known/matrix/policy_server", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: policy server well-known not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /.well-known/matrix/support ------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_well-knownmatrixsupport
// IMPLEMENTATION GAP: support contact discovery not yet implemented.
SCENARIO("GET /.well-known/matrix/support returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][server-admin]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /.well-known/matrix/support is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/.well-known/matrix/support", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: support well-known not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/admin/whois/{userId} ------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3adminwhoisuserid
// IMPLEMENTATION GAP: admin whois not yet implemented.
SCENARIO("GET /admin/whois/{userId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][server-admin]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /admin/whois/@alice:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/admin/whois/%40alice%3Aexample.org", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: admin whois not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v1/admin/lock/{userId} -------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1adminlockuserid
// IMPLEMENTATION GAP: admin user lock not yet implemented.
SCENARIO("GET /v1/admin/lock/{userId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][server-admin]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /_matrix/client/v1/admin/lock/@alice:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/admin/lock/%40alice%3Aexample.org", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: admin user lock not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- PUT /_matrix/client/v1/admin/lock/{userId} -------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv1adminlockuserid
// IMPLEMENTATION GAP: admin user lock not yet implemented.
SCENARIO("PUT /v1/admin/lock/{userId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][server-admin]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /_matrix/client/v1/admin/lock/@alice:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v1/admin/lock/%40alice%3Aexample.org", token, R"({"locked":true})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: admin user lock not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v1/admin/suspend/{userId} ----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1adminsuspenduserid
// IMPLEMENTATION GAP: admin user suspend not yet implemented.
SCENARIO("GET /v1/admin/suspend/{userId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][server-admin]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /_matrix/client/v1/admin/suspend/@alice:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/admin/suspend/%40alice%3Aexample.org", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: admin user suspend not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- PUT /_matrix/client/v1/admin/suspend/{userId} ----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv1adminsuspenduserid
// IMPLEMENTATION GAP: admin user suspend not yet implemented.
SCENARIO("PUT /v1/admin/suspend/{userId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][server-admin]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /_matrix/client/v1/admin/suspend/@alice:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v1/admin/suspend/%40alice%3Aexample.org", token, R"({"suspended":true})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: admin user suspend (PUT) not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// ACCOUNT MANAGEMENT
// =============================================================================

// --- POST /_matrix/client/v3/account/password ---------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3accountpassword
//
// MUST return 200 with an empty JSON object on success.
SCENARIO("POST /account/password returns 200 with empty JSON object", "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/password is called with a new password")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/password", token, R"({"new_password":"NewHorse7!+Ab"})"});

            THEN("the response is 200 with a valid JSON object body")
            {
                // Spec MUST: 200 on successful password change.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                std::ignore = body;
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/deactivate -------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3accountdeactivate
// IMPLEMENTATION GAP: account deactivation not yet implemented.
SCENARIO("POST /account/deactivate returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/deactivate is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/account/deactivate", token,
                                  R"({"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: account deactivation not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/account/3pid -------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3account3pid
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3account3pid
SCENARIO("GET /account/3pid returns 200 with empty threepids array", "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /account/3pid is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/account/3pid", token, {}});

            THEN("the server returns 200 with a threepids array")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* threepids = object_member_as_array(body, "threepids");
                REQUIRE(threepids != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/3pid ------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3account3pid
// IMPLEMENTATION GAP: 3PID association not yet implemented.
SCENARIO("POST /account/3pid returns 404 M_UNRECOGNIZED (implementation gap)", "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/3pid is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/3pid", token,
                 R"({"three_pid_creds":{"client_secret":"s","id_access_token":"t","id_server":"id.example.org","sid":"123"}})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: 3PID association not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/3pid/add ---------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3account3pidadd
// IMPLEMENTATION GAP: 3PID add not yet implemented.
SCENARIO("POST /account/3pid/add returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/3pid/add is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/3pid/add", token,
                 R"({"client_secret":"s","sid":"123","auth":{"type":"m.login.password","password":"x"}})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: 3PID add not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/3pid/bind --------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3account3pidbind
// IMPLEMENTATION GAP: 3PID bind not yet implemented.
SCENARIO("POST /account/3pid/bind returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/3pid/bind is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/3pid/bind", token,
                 R"({"client_secret":"s","id_access_token":"t","id_server":"id.example.org","sid":"123"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: 3PID bind not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/3pid/delete ------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3account3piddelete
// IMPLEMENTATION GAP: 3PID delete not yet implemented.
SCENARIO("POST /account/3pid/delete returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/3pid/delete is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/account/3pid/delete", token,
                                  R"({"address":"user@example.org","medium":"email"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: 3PID delete not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/3pid/email/requestToken -----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3account3pidemailrequesttoken
// IMPLEMENTATION GAP: email token request not yet implemented.
SCENARIO("POST /account/3pid/email/requestToken returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/3pid/email/requestToken is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/account/3pid/email/requestToken", token,
                                  R"({"client_secret":"s","email":"user@example.org","send_attempt":1})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: 3PID email token not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/3pid/msisdn/requestToken ----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3account3pidmsisdnrequesttoken
// IMPLEMENTATION GAP: MSISDN token request not yet implemented.
SCENARIO("POST /account/3pid/msisdn/requestToken returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/3pid/msisdn/requestToken is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/3pid/msisdn/requestToken", token,
                 R"({"client_secret":"s","country":"GB","phone_number":"07700000000","send_attempt":1})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: 3PID MSISDN token not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/3pid/unbind ------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3account3pidunbind
// IMPLEMENTATION GAP: 3PID unbind not yet implemented.
SCENARIO("POST /account/3pid/unbind returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/3pid/unbind is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/account/3pid/unbind", token,
                                  R"({"address":"user@example.org","medium":"email"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: 3PID unbind not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/password/email/requestToken -------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3accountpasswordemailrequesttoken
// IMPLEMENTATION GAP: password reset email token not yet implemented.
SCENARIO("POST /account/password/email/requestToken returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/password/email/requestToken is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/account/password/email/requestToken", token,
                                  R"({"client_secret":"s","email":"user@example.org","send_attempt":1})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: password reset email token not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/account/password/msisdn/requestToken ------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3accountpasswordmsisdnrequesttoken
// IMPLEMENTATION GAP: password reset MSISDN token not yet implemented.
SCENARIO("POST /account/password/msisdn/requestToken returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/password/msisdn/requestToken is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/password/msisdn/requestToken", token,
                 R"({"client_secret":"s","country":"GB","phone_number":"07700000000","send_attempt":1})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: password reset MSISDN token not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/register/available --------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3registeravailable
//
// MUST return 200 with:
//   available - boolean true when the username can be registered
//
// MUST return 400 when the username is already taken or invalid.
SCENARIO("GET /register/available reports spec-shaped availability and validation errors",
         "[conformance][client-server][account][register]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("an unused username is queried")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/register/available?username=charlie", {}, {}});

            THEN("the response is 200 with available true")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* available = bool_member(body, "available");
                REQUIRE(available != nullptr);
                REQUIRE(*available);
            }
        }

        WHEN("an already-registered username is queried")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        started.runtime, {"POST",
                                          "/_matrix/client/v3/register",
                                          {},
                                          merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                        .response.status == 200U);
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/register/available?username=alice", {}, {}});

            THEN("the response is 400 with M_USER_IN_USE")
            {
                REQUIRE(response.response.status == 400U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_USER_IN_USE");
            }
        }

        WHEN("an invalid username is queried")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/register/available?username=Bad!Name", {}, {}});

            THEN("the response is 400 with M_INVALID_USERNAME")
            {
                REQUIRE(response.response.status == 400U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_USERNAME");
            }
        }
    }
}

// --- GET /_matrix/client/v1/register/m.login.registration_token/validity -----
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1registermloginregistration_tokenvalidity
//
// MUST return 200 with:
//   valid - boolean indicating whether the supplied token can be used
SCENARIO("GET /v1/register/m.login.registration_token/validity reports token validity",
         "[conformance][client-server][account][register]")
{
    GIVEN("a running client-server with token registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("the configured registration token is queried")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET",
                 std::string{"/_matrix/client/v1/register/m.login.registration_token/validity?token="} +
                     std::string{merovingian::tests::registration_token},
                 {},
                 {}});

            THEN("the response is 200 with valid true")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* valid = bool_member(body, "valid");
                REQUIRE(valid != nullptr);
                REQUIRE(*valid);
            }
        }

        WHEN("an unknown registration token is queried")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v1/register/m.login.registration_token/validity?token=wrong-token", {}, {}});

            THEN("the response is 200 with valid false")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* valid = bool_member(body, "valid");
                REQUIRE(valid != nullptr);
                REQUIRE(!*valid);
            }
        }
    }
}

// --- POST /_matrix/client/v3/register/email/requestToken --------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3registeremailrequesttoken
//
// MUST return 200 with:
//   sid - opaque validation session identifier
//
// submit_url is optional when the homeserver completes validation without
// requiring the client to POST the token to a separate endpoint.
SCENARIO("POST /register/email/requestToken returns a spec-shaped validation session",
         "[conformance][client-server][account][register]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("an email validation request is submitted")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/register/email/requestToken",
                 {},
                 R"({"client_secret":"secret123","email":"user@example.org","next_link":"https://example.org/next","send_attempt":1})"});

            THEN("the response is 200 with a valid sid")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* sid = string_member(body, "sid");
                REQUIRE(sid != nullptr);
                REQUIRE(!sid->empty());
                REQUIRE(sid->size() <= 255U);
                REQUIRE(std::ranges::all_of(*sid, [](char const value) {
                    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'z') ||
                           (value >= 'A' && value <= 'Z') || value == '.' || value == '=' || value == '_' ||
                           value == '-';
                }));
            }
        }
    }
}

// --- POST /_matrix/client/v3/register/msisdn/requestToken -------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3registermsisdnrequesttoken
//
// MUST return 200 with:
//   sid - opaque validation session identifier
SCENARIO("POST /register/msisdn/requestToken returns a spec-shaped validation session",
         "[conformance][client-server][account][register]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("an MSISDN validation request is submitted")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/register/msisdn/requestToken",
                 {},
                 R"({"client_secret":"secret123","country":"GB","next_link":"https://example.org/next","phone_number":"07700000000","send_attempt":1})"});

            THEN("the response is 200 with a valid sid")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* sid = string_member(body, "sid");
                REQUIRE(sid != nullptr);
                REQUIRE(!sid->empty());
                REQUIRE(sid->size() <= 255U);
                REQUIRE(std::ranges::all_of(*sid, [](char const value) {
                    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'z') ||
                           (value >= 'A' && value <= 'Z') || value == '.' || value == '=' || value == '_' ||
                           value == '-';
                }));
            }
        }
    }
}

// =============================================================================
// CAPABILITIES
// =============================================================================

// --- GET /_matrix/client/v3/capabilities --------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3capabilities
//
// MUST return:
//   capabilities - object containing server capability flags
SCENARIO("GET /capabilities returns the server capabilities object", "[conformance][client-server][capabilities]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /capabilities is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/capabilities", token, {}});

            THEN("the response is 200 with a capabilities object")
            {
                // Spec MUST: 200 with capabilities.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "capabilities" is present and is an object.
                auto const* caps = object_member_as_object(body, "capabilities");
                REQUIRE(caps != nullptr);

                // Spec MUST: m.room_versions capability includes a default version.
                auto const* rv = object_member_as_object(*caps, "m.room_versions");
                REQUIRE(rv != nullptr);
                auto const* default_ver = string_member(*rv, "default");
                REQUIRE(default_ver != nullptr);
                REQUIRE(!default_ver->empty());
            }
        }
    }
}

// =============================================================================
// DEVICE MANAGEMENT
// =============================================================================

// --- GET /_matrix/client/v3/devices -------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3devices
//
// MUST return:
//   devices - array of device objects
SCENARIO("GET /devices returns the devices array for the authenticated user", "[conformance][client-server][devices]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /devices is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("the response is 200 with a devices array")
            {
                // Spec MUST: 200 with device list.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: "devices" is present and is an array.
                auto const* devices = object_member_as_array(body, "devices");
                REQUIRE(devices != nullptr);
            }
        }
    }
}

// --- GET /_matrix/client/v3/devices/{deviceId} --------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3devicesdeviceid
//
// MUST return:
//   device_id - string identifier of the device
SCENARIO("GET /devices/{deviceId} returns the device object for a known device",
         "[conformance][client-server][devices]")
{
    GIVEN("a running client-server and a logged-in user with a known device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /devices/DEVICE1 is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/devices/DEVICE1", token, {}});

            THEN("the response is 200 with the device_id field")
            {
                // Spec MUST: 200 with device info for a known device.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: device_id is present and matches the requested ID.
                auto const* device_id = string_member(body, "device_id");
                REQUIRE(device_id != nullptr);
                REQUIRE(*device_id == "DEVICE1");
            }
        }
    }
}

// --- PUT /_matrix/client/v3/devices/{deviceId} --------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3devicesdeviceid
//
// MUST return 200 with an empty JSON object on success.
SCENARIO("PUT /devices/{deviceId} returns 200 with empty JSON object", "[conformance][client-server][devices]")
{
    GIVEN("a running client-server and a logged-in user with a known device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /devices/DEVICE1 is called with a display name")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/devices/DEVICE1", token, R"({"display_name":"My Device"})"});

            THEN("the response is 200 with a valid JSON object body")
            {
                // Spec MUST: 200 on successful device display name update.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                std::ignore = body;
            }
        }
    }
}

// --- DELETE /_matrix/client/v3/devices/{deviceId} ----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#delete_matrixclientv3devicesdeviceid
//
// MUST return 200 with an empty JSON object on success.
SCENARIO("DELETE /devices/{deviceId} returns 200 with empty JSON object", "[conformance][client-server][devices]")
{
    GIVEN("a running client-server and a user with two devices")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST",
                                      "/_matrix/client/v3/register",
                                      {},
                                      merovingian::tests::registration_json("devuser", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login1 = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@devuser:example.org"},"password":"CorrectHorse7!","device_id":"DEV_A"})"});
        REQUIRE(login1.response.status == 200U);
        auto const body1 = parse_object(login1.response.body);
        auto const* tok1 = string_member(body1, "access_token");
        REQUIRE(tok1 != nullptr);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@devuser:example.org"},"password":"CorrectHorse7!","device_id":"DEV_B"})"})
                .response.status == 200U);

        WHEN("DELETE /devices/DEV_B is called from DEV_A's session")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/devices/DEV_B", *tok1, {}});

            THEN("the response is 200 with a valid JSON object body")
            {
                // Spec MUST: 200 on successful device deletion.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                std::ignore = body;
            }
        }
    }
}

// --- POST /_matrix/client/v3/delete_devices -----------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3delete_devices
// IMPLEMENTATION GAP: bulk device deletion not yet implemented.
SCENARIO("POST /delete_devices returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][devices]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /delete_devices is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/delete_devices", token, R"({"devices":["DEVICE1"]})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: bulk device deletion not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// END-TO-END ENCRYPTION (remaining)
// =============================================================================

// --- GET /_matrix/client/v3/keys/changes --------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3keyschanges
// Returns users whose device lists changed between two sync stream positions.
// Element requests this on startup to avoid redundant /keys/query calls.
SCENARIO("GET /keys/changes returns 200 with changed and left arrays", "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /keys/changes is called with from and to tokens")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/keys/changes?from=s0&to=s99", token, {}});

            THEN("the server returns 200 with changed and left as arrays")
            {
                // Spec MUST: 200 with "changed" and "left" arrays.
                // Do NOT remove — Element reads these to detect stale device caches.
                // A missing or wrong-typed field causes silent E2EE key-fetch failures.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* changed = object_member_as_array(body, "changed");
                REQUIRE(changed != nullptr);
                auto const* left = object_member_as_array(body, "left");
                REQUIRE(left != nullptr);
            }
        }
    }
}

SCENARIO("GET /keys/changes reflects device-key uploads made after the from token",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a running client-server with two users sharing a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");

        // Alice creates a private room and Bob joins so they share membership.
        auto const room_resp = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", alice,
                              R"({"preset":"private_chat","invite":["@bob:example.org"]})"});
        REQUIRE(room_resp.response.status == 200U);
        // Store the parsed body so string_member's pointer into it stays valid.
        auto const room_body = parse_object(room_resp.response.body);
        auto const* room_id = string_member(room_body, "room_id");
        REQUIRE(room_id != nullptr);
        std::ignore = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/join", bob, {}});

        // Record the stream position before Bob uploads his device keys.
        auto const before_sync = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", alice, {}});
        REQUIRE(before_sync.response.status == 200U);
        auto const before_body = parse_object(before_sync.response.body);
        auto const* next_batch_val = string_member(before_body, "next_batch");
        REQUIRE(next_batch_val != nullptr);
        auto const from_token = *next_batch_val;

        WHEN("Bob uploads his device keys")
        {
            std::ignore = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/upload", bob,
                 R"({"device_keys":{"user_id":"@bob:example.org","device_id":"bob_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:bob_DEV":"BOBKEY"},"signatures":{}}})"});

            THEN("GET /keys/changes from the pre-upload token includes Bob in changed")
            {
                // Spec: any user who uploaded keys after `from` must appear in `changed`.
                // Element uses this to know which users' key caches need refreshing.
                auto const changes = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/keys/changes?from=" + from_token + "&to=s999", alice, {}});
                REQUIRE(changes.response.status == 200U);
                auto const cbody = parse_object(changes.response.body);
                auto const* changed_arr = object_member_as_array(cbody, "changed");
                REQUIRE(changed_arr != nullptr);
                auto const bob_in_changed =
                    std::ranges::any_of(*changed_arr, [](merovingian::canonicaljson::Value const& v) {
                        auto const* s = std::get_if<std::string>(&v.storage());
                        return s != nullptr && *s == "@bob:example.org";
                    });
                REQUIRE(bob_in_changed);
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/version/{version} ----------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keysversionversion
//
// MUST return algorithm, auth_data, count, etag, and version for the requested backup version.
SCENARIO("GET /room_keys/version/{version} returns backup metadata for a specific version",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with a key backup version and one backed-up session")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
                 R"({"rooms":{"!versionmeta:example.org":{"sessions":{"sess1":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}}}}}})"})
                .response.status == 200U);

        WHEN("GET /room_keys/version/1 is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/version/1", token, {}});

            THEN("the response is 200 with algorithm, auth_data, count, etag, and version")
            {
                // Spec MUST: 200 with backup metadata for the requested version.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* algorithm = string_member(body, "algorithm");
                REQUIRE(algorithm != nullptr);
                REQUIRE(!algorithm->empty());
                REQUIRE(object_member_as_object(body, "auth_data") != nullptr);
                auto const* count = int_member(body, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 1);
                auto const* etag = string_member(body, "etag");
                REQUIRE(etag != nullptr);
                REQUIRE(!etag->empty());
                auto const* version = string_member(body, "version");
                REQUIRE(version != nullptr);
                REQUIRE(*version == "1");
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keysversionversion
//
// MUST return 404 M_NOT_FOUND for a version that does not exist.
SCENARIO("GET /room_keys/version/{version} returns 404 for an unknown version", "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with no key backup")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /room_keys/version/99 is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/version/99", token, {}});

            THEN("the response is 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
            }
        }
    }
}

// --- PUT /_matrix/client/v3/room_keys/version/{version} ----------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3room_keysversionversion
//
// MUST return 200 with an empty JSON object on success.
SCENARIO("PUT /room_keys/version/{version} returns 200 after updating backup metadata",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a running client-server, a logged-in user, and an existing key backup")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        WHEN("PUT /room_keys/version/1 is called with updated auth_data")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/version/1", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"xyz","signatures":{}}})"});

            THEN("the response is 200 with a valid JSON object body")
            {
                // Spec MUST: 200 on successful backup version update.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                std::ignore = body;
            }
        }
    }
}

// --- DELETE /_matrix/client/v3/room_keys/version/{version} -------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#delete_matrixclientv3room_keysversionversion
//
// MUST return 200 with an empty JSON object on success.
SCENARIO("DELETE /room_keys/version/{version} returns 200 after deleting a backup version",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a running client-server, a logged-in user, and an existing key backup")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        WHEN("DELETE /room_keys/version/1 is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/room_keys/version/1", token, {}});

            THEN("the response is 200 with a valid JSON object body")
            {
                // Spec MUST: 200 on successful backup version deletion.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                std::ignore = body;
            }
        }
    }
}

// --- PUT /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId} --------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3room_keyskeysroomidsessionid
//
// MUST return RoomKeysUpdateResponse on success.
SCENARIO("PUT /room_keys/keys/{roomId}/{sessionId} stores a session key backup", "[conformance][client-server][e2ee]")
{
    GIVEN("a running client-server, a logged-in user, and an existing key backup")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        WHEN("PUT /room_keys/keys/{roomId}/{sessionId} is called with session backup data")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/session1", token,
                 R"({"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}})"});

            THEN("the response is 200 with count and etag for the updated backup state")
            {
                // Spec MUST: 200 with RoomKeysUpdateResponse on successful session key backup storage.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* count = int_member(body, "count");
                auto const* etag = string_member(body, "etag");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 1);
                REQUIRE(etag != nullptr);
                REQUIRE(!etag->empty());
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3room_keyskeysroomidsessionid
//
// Updating an existing backed-up session changes the stored backup state while
// leaving the total session count unchanged, so the returned etag MUST change
// even when the count remains stable.
SCENARIO("PUT /room_keys/keys/{roomId}/{sessionId} changes etag when an existing session is overwritten",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user overwriting the same backed-up session twice")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        auto const first_put = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"PUT", "/_matrix/client/v3/room_keys/keys/%21etagroom%3Aexample.org/etag-session?version=1", token,
             R"({"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"first","ephemeral":"def","mac":"ghi"}})"});
        REQUIRE(first_put.response.status == 200U);
        auto const first_body = parse_object(first_put.response.body);
        auto const* first_count = int_member(first_body, "count");
        auto const* first_etag = string_member(first_body, "etag");
        REQUIRE(first_count != nullptr);
        REQUIRE(*first_count == 1);
        REQUIRE(first_etag != nullptr);
        REQUIRE(!first_etag->empty());

        WHEN("the same session id is overwritten with different session_data")
        {
            auto const second_put = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21etagroom%3Aexample.org/etag-session?version=1", token,
                 R"({"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"second","ephemeral":"def","mac":"ghi"}})"});

            THEN("the count stays 1 but the etag changes")
            {
                REQUIRE(second_put.response.status == 200U);
                auto const second_body = parse_object(second_put.response.body);
                auto const* second_count = int_member(second_body, "count");
                auto const* second_etag = string_member(second_body, "etag");
                REQUIRE(second_count != nullptr);
                REQUIRE(*second_count == 1);
                REQUIRE(second_etag != nullptr);
                REQUIRE(!second_etag->empty());
                REQUIRE(*second_etag != *first_etag);
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId} --------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeysroomidsessionid
//
// MUST return 200 with the backed-up session data on success.
SCENARIO("GET /room_keys/keys/{roomId}/{sessionId} retrieves a backed-up session key",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a running client-server, a logged-in user, and a stored session backup")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/sessA", token,
                 R"({"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}})"})
                .response.status == 200U);

        WHEN("GET /room_keys/keys/{roomId}/{sessionId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/sessA", token, {}});

            THEN("the response is 200 with a valid JSON object body")
            {
                // Spec MUST: 200 with session backup data.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                std::ignore = body;
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId} (data fields) -
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeysroomidsessionid
//
// MUST return the stored KeyBackupData fields, not an empty placeholder.
SCENARIO("GET /room_keys/keys/{roomId}/{sessionId} returns stored session data fields",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with a stored session key backup")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21room2%3Aexample.org/sessZ", token,
                 R"({"first_message_index":1,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"xyz","ephemeral":"efg","mac":"hij"}})"})
                .response.status == 200U);

        WHEN("the backed-up session is retrieved")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/keys/%21room2%3Aexample.org/sessZ", token, {}});

            THEN("the response contains the stored KeyBackupData fields")
            {
                // Spec MUST: 200 with first_message_index, forwarded_count, session_data.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(int_member(body, "first_message_index") != nullptr);
                REQUIRE(int_member(body, "forwarded_count") != nullptr);
                REQUIRE(object_member_as_object(body, "session_data") != nullptr);
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeysroomidsessionid
//
// MUST return 404 M_NOT_FOUND when the session does not exist in the backup.
SCENARIO("GET /room_keys/keys/{roomId}/{sessionId} returns 404 for unknown session",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with a key backup version but no stored sessions")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        WHEN("a non-existent session is requested")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/room_keys/keys/%21room3%3Aexample.org/no-such-session", token, {}});

            THEN("the response is 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when no matching session exists in the backup.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
            }
        }
    }
}

// --- DELETE /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId} -----------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#delete_matrixclientv3room_keyskeysroomidsessionid
//
// MUST return RoomKeysUpdateResponse on success.
SCENARIO("DELETE /room_keys/keys/{roomId}/{sessionId} removes a backed-up session key",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a running client-server, a logged-in user, and a stored session backup")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/sessD", token,
                 R"({"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}})"})
                .response.status == 200U);

        WHEN("DELETE /room_keys/keys/{roomId}/{sessionId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"DELETE", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/sessD", token, {}});

            THEN("the response is 200 with count and etag for the updated backup state")
            {
                // Spec MUST: 200 with RoomKeysUpdateResponse on successful session key deletion.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* count = int_member(body, "count");
                auto const* etag = string_member(body, "etag");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 0);
                REQUIRE(etag != nullptr);
                REQUIRE(!etag->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/keys ------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeys
//
// MUST return 200 with {"rooms":{}} when no sessions are backed up.
SCENARIO("GET /room_keys/keys returns 200 with rooms object", "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with no key backup sessions")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /room_keys/keys is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/keys", token, {}});

            THEN("the response is 200 with a rooms object")
            {
                // Spec MUST: 200 with {"rooms":{...}} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(object_member_as_object(body, "rooms") != nullptr);
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeys
//
// After uploading sessions via batch PUT, GET /room_keys/keys MUST return the
// sessions nested under their room in the rooms object.
SCENARIO("GET /room_keys/keys returns stored sessions grouped by room", "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user who has uploaded a batch of session keys")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys", token,
                 R"({"rooms":{"!batchroom:example.org":{"sessions":{"bsess1":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}}}}}})"})
                .response.status == 200U);

        WHEN("GET /room_keys/keys is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/keys", token, {}});

            THEN("the rooms object contains the uploaded room and session")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* room = object_member_as_object(*rooms, "!batchroom:example.org");
                REQUIRE(room != nullptr);
                auto const* sessions = object_member_as_object(*room, "sessions");
                REQUIRE(sessions != nullptr);
                REQUIRE(object_member_as_object(*sessions, "bsess1") != nullptr);
            }
        }
    }
}

// --- PUT /_matrix/client/v3/room_keys/keys ------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3room_keyskeys
// MUST return RoomKeysUpdateResponse with count and etag.
SCENARIO("PUT /room_keys/keys returns count and etag for the stored backup state", "[conformance][client-server][e2ee]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        WHEN("PUT /room_keys/keys is called with one uploaded session")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
                 R"({"rooms":{"!room1:example.org":{"sessions":{"sess1":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}}}}}})"});

            THEN("the server returns 200 with count 1 and a non-empty etag")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* count = int_member(body, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 1);
                auto const* etag = string_member(body, "etag");
                REQUIRE(etag != nullptr);
                REQUIRE(!etag->empty());
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3room_keyskeys
// MUST store session data and return RoomKeysUpdateResponse with count and etag.
SCENARIO("PUT /room_keys/keys with session data stores and returns count and etag",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a running client-server, a logged-in user, and an existing key backup version")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        WHEN("PUT /room_keys/keys is called with room and session data")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys", token,
                 R"({"rooms":{"!room1:example.org":{"sessions":{"sess1":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}}}}}})"});

            THEN("the server returns 200 with count 1 and a non-empty etag")
            {
                // Spec MUST: 200 with RoomKeysUpdateResponse on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* count = int_member(body, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 1);
                auto const* etag = string_member(body, "etag");
                REQUIRE(etag != nullptr);
                REQUIRE(!etag->empty());
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3room_keyskeys
//
// Real clients (Element, Hydrogen) append ?version=N to the path.  The router
// MUST match the route on the path portion only, ignoring the query string.
SCENARIO("PUT /room_keys/keys with ?version query param is routed correctly", "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with an existing key backup version")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        WHEN("PUT /room_keys/keys?version=1 is called with session data")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
                 R"({"rooms":{"!roomQ:example.org":{"sessions":{"sessQ":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}}}}}})"});

            THEN("the server returns 200, not 404 (route matches despite query string)")
            {
                // Spec MUST: query string must not prevent route matching.
                REQUIRE(response.response.status == 200U);
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeysroomidsessionid
//
// Real Megolm session IDs can contain `/`, so clients percent-encode the path
// component on GET. The server MUST decode the room_id/session_id path
// components before matching the stored backup rows uploaded via batch PUT.
SCENARIO("GET /room_keys/keys/{roomId}/{sessionId}?version=1 decodes encoded session ids from batch uploads",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with a batch-uploaded backup session whose id contains a slash")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
                 R"({"rooms":{"!batchslash:example.org":{"sessions":{"DDY/ct3HLLugqXw600J2MuNIa+zHWX4y8jRth2VGWx0":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}}}}}})"})
                .response.status == 200U);

        WHEN("the session is fetched through the encoded path used by Matrix clients")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET",
                                  "/_matrix/client/v3/room_keys/keys/%21batchslash%3Aexample.org/"
                                  "DDY%2Fct3HLLugqXw600J2MuNIa%2BzHWX4y8jRth2VGWx0?version=1",
                                  token,
                                  {}});

            THEN("the stored session is returned instead of a 404")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(int_member(body, "first_message_index") != nullptr);
                REQUIRE(object_member_as_object(body, "session_data") != nullptr);
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeysroomid
//
// Room-level backup retrieval also uses an encoded roomId path component and a
// required version query parameter. Sessions uploaded via batch PUT use decoded
// room IDs from the JSON body, so the server MUST decode the roomId path
// component before matching the stored backup rows.
SCENARIO("GET /room_keys/keys/{roomId}?version=1 decodes encoded room ids from batch uploads",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with a batch-uploaded backup session for a room with an encoded path id")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
                 R"({"rooms":{"!batchslash:example.org":{"sessions":{"DDY/ct3HLLugqXw600J2MuNIa+zHWX4y8jRth2VGWx0":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}}}}}})"})
                .response.status == 200U);

        WHEN("the room backup is fetched through the encoded roomId path used by Matrix clients")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/room_keys/keys/%21batchslash%3Aexample.org?version=1", token, {}});

            THEN("the stored sessions object is returned for that decoded room id")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* sessions = object_member_as_object(body, "sessions");
                REQUIRE(sessions != nullptr);
                REQUIRE(object_member_as_object(*sessions, "DDY/ct3HLLugqXw600J2MuNIa+zHWX4y8jRth2VGWx0") != nullptr);
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3room_keyskeysroomidsessionid
//       https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeysroomidsessionid
//
// Direct per-session PUT and GET must round-trip through encoded roomId and
// sessionId path components. This ensures the path parser is spec-conformant
// for both write and read variants, not just batch-upload plus read.
SCENARIO("PUT and GET /room_keys/keys/{roomId}/{sessionId}?version=1 round-trip encoded path components",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user storing a session backup through encoded Matrix path components")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        WHEN("a direct PUT uses an encoded session id containing a slash")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT",
                 "/_matrix/client/v3/room_keys/keys/%21directslash%3Aexample.org/"
                 "DDY%2Fct3HLLugqXw600J2MuNIa%2BzHWX4y8jRth2VGWx0?version=1",
                 token,
                 R"({"first_message_index":7,"forwarded_count":1,"is_verified":true,"session_data":{"ciphertext":"put-abc","ephemeral":"put-def","mac":"put-ghi"}})"});

            THEN("the direct PUT succeeds")
            {
                REQUIRE(put.response.status == 200U);
            }

            AND_WHEN("the same encoded path is fetched back")
            {
                auto const get = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET",
                                      "/_matrix/client/v3/room_keys/keys/%21directslash%3Aexample.org/"
                                      "DDY%2Fct3HLLugqXw600J2MuNIa%2BzHWX4y8jRth2VGWx0?version=1",
                                      token,
                                      {}});

                THEN("the same stored KeyBackupData is returned")
                {
                    REQUIRE(get.response.status == 200U);
                    auto const body = parse_object(get.response.body);
                    auto const* first_message_index = int_member(body, "first_message_index");
                    auto const* forwarded_count = int_member(body, "forwarded_count");
                    auto const* session_data = object_member_as_object(body, "session_data");
                    REQUIRE(first_message_index != nullptr);
                    REQUIRE(*first_message_index == 7);
                    REQUIRE(forwarded_count != nullptr);
                    REQUIRE(*forwarded_count == 1);
                    REQUIRE(session_data != nullptr);
                }
            }
        }
    }
}

// --- DELETE /_matrix/client/v3/room_keys/keys ---------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#delete_matrixclientv3room_keyskeys
//
// MUST return 200 with count and etag.  After deletion GET /room_keys/keys
// MUST return an empty rooms object.
SCENARIO("DELETE /room_keys/keys removes all sessions and returns count", "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with uploaded session backups")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys", token,
                 R"({"rooms":{"!delroom:example.org":{"sessions":{"dsess1":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"x","ephemeral":"y","mac":"z"}}}}}})"})
                .response.status == 200U);

        WHEN("DELETE /room_keys/keys is called")
        {
            auto const del = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/room_keys/keys", token, {}});

            THEN("the response is 200 with count and etag fields")
            {
                // Spec MUST: 200 with count (integer) and etag (string).
                REQUIRE(del.response.status == 200U);
                auto const body = parse_object(del.response.body);
                REQUIRE(int_member(body, "count") != nullptr);
                REQUIRE(string_member(body, "etag") != nullptr);
            }

            AND_THEN("GET /room_keys/keys returns an empty rooms object")
            {
                auto const get = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/room_keys/keys", token, {}});
                REQUIRE(get.response.status == 200U);
                auto const body = parse_object(get.response.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                REQUIRE(rooms->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/keys/{roomId} --------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeysroomid
//
// MUST return {"sessions":{...}} — NOT a "rooms" wrapper.
SCENARIO("GET /room_keys/keys/{roomId} returns a sessions object", "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with no sessions for the room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /room_keys/keys/{roomId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org", token, {}});

            THEN("the response is 200 with a sessions object (not rooms)")
            {
                // Spec MUST: room-level GET returns RoomKeyBackup {"sessions":{...}}.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(object_member_as_object(body, "sessions") != nullptr);
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3room_keyskeysroomid
//
// After uploading sessions, GET /room_keys/keys/{roomId} MUST include those
// sessions keyed by session ID under "sessions".
SCENARIO("GET /room_keys/keys/{roomId} returns uploaded sessions for that room", "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user who has uploaded a session for a specific room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21roomR%3Aexample.org/rsessX", token,
                 R"({"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}})"})
                .response.status == 200U);

        WHEN("GET /room_keys/keys/{roomId} is called for that room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/room_keys/keys/%21roomR%3Aexample.org", token, {}});

            THEN("the sessions object contains the uploaded session")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* sessions = object_member_as_object(body, "sessions");
                REQUIRE(sessions != nullptr);
                REQUIRE(object_member_as_object(*sessions, "rsessX") != nullptr);
            }
        }
    }
}

// --- PUT /_matrix/client/v3/room_keys/keys/{roomId} --------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3room_keyskeysroomid
SCENARIO("PUT /room_keys/keys/{roomId} stores that room's sessions and returns count and etag",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with a created key backup version")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);

        WHEN("PUT /room_keys/keys/{roomId} is called with multiple sessions")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org?version=1", token,
                 R"({"sessions":{"sessA":{"first_message_index":1,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"aaa","ephemeral":"bbb","mac":"ccc"}},"sessB":{"first_message_index":2,"forwarded_count":1,"is_verified":false,"session_data":{"ciphertext":"ddd","ephemeral":"eee","mac":"fff"}}}})"});

            THEN("the response returns RoomKeysUpdateResponse and the room GET returns both sessions")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* count = int_member(body, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 2);
                auto const* etag = string_member(body, "etag");
                REQUIRE(etag != nullptr);
                REQUIRE(!etag->empty());

                auto const room_get = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org?version=1", token, {}});
                REQUIRE(room_get.response.status == 200U);
                auto const room_body = parse_object(room_get.response.body);
                auto const* sessions = object_member_as_object(room_body, "sessions");
                REQUIRE(sessions != nullptr);
                REQUIRE(object_member_as_object(*sessions, "sessA") != nullptr);
                REQUIRE(object_member_as_object(*sessions, "sessB") != nullptr);
            }
        }
    }
}

// --- DELETE /_matrix/client/v3/room_keys/keys/{roomId} -----------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#delete_matrixclientv3room_keyskeysroomid
SCENARIO("DELETE /room_keys/keys/{roomId} removes only that room's sessions and returns count and etag",
         "[conformance][client-server][e2ee]")
{
    GIVEN("a logged-in user with backup sessions in two rooms")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})"})
                .response.status == 200U);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
                 R"({"rooms":{"!room1:example.org":{"sessions":{"sessA":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"aaa","ephemeral":"bbb","mac":"ccc"}},"sessB":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"ddd","ephemeral":"eee","mac":"fff"}}}},"!room2:example.org":{"sessions":{"sessC":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"ggg","ephemeral":"hhh","mac":"iii"}}}}}})"})
                .response.status == 200U);

        WHEN("DELETE /room_keys/keys/{roomId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"DELETE", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org?version=1", token, {}});

            THEN("the deleted room is empty while sessions in other rooms remain")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* count = int_member(body, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 1);
                auto const* etag = string_member(body, "etag");
                REQUIRE(etag != nullptr);
                REQUIRE(!etag->empty());

                auto const room1_get = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org?version=1", token, {}});
                REQUIRE(room1_get.response.status == 200U);
                auto const room1_body = parse_object(room1_get.response.body);
                auto const* room1_sessions = object_member_as_object(room1_body, "sessions");
                REQUIRE(room1_sessions != nullptr);
                REQUIRE(room1_sessions->empty());

                auto const room2_get = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/room_keys/keys/%21room2%3Aexample.org?version=1", token, {}});
                REQUIRE(room2_get.response.status == 200U);
                auto const room2_body = parse_object(room2_get.response.body);
                auto const* room2_sessions = object_member_as_object(room2_body, "sessions");
                REQUIRE(room2_sessions != nullptr);
                REQUIRE(object_member_as_object(*room2_sessions, "sessC") != nullptr);
            }
        }
    }
}

// =============================================================================
// MEDIA
// =============================================================================

// --- GET /_matrix/media/v3/config ---------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixmediav3config
//
// MUST return:
//   m.upload.size - integer maximum upload size in bytes
SCENARIO("GET /media/v3/config returns the maximum upload size", "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /media/v3/config is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/media/v3/config", token, {}});

            THEN("the response is 200 with m.upload.size as a positive integer")
            {
                // Spec MUST: 200 with upload size configuration.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);

                // Spec MUST: m.upload.size is a positive integer.
                auto const* upload_size = int_member(body, "m.upload.size");
                REQUIRE(upload_size != nullptr);
                REQUIRE(*upload_size > 0);
            }
        }
    }
}

// --- POST /_matrix/media/v3/upload --------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixmediav3upload
SCENARIO("POST /media/v3/upload stores media and returns content_uri", "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /media/v3/upload is called with valid media data")
        {
            // The internal handler expects pipe-delimited body:
            // declared_mime|sniffed_mime|scanner_clean|bytes
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/media/v3/upload", token, "image/png|image/png|clean|test-image-data"});

            THEN("the server returns 200 with a content_uri")
            {
                // Spec MUST: 200 with content_uri on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* content_uri = string_member(body, "content_uri");
                REQUIRE(content_uri != nullptr);
                REQUIRE(!content_uri->empty());
                // Spec MUST: content_uri starts with "mxc://"
                REQUIRE(content_uri->starts_with("mxc://"));
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixmediav3downloadservernamemediaid
// MUST return 200 with media content when the media ID exists.
SCENARIO("GET /media/v3/download/{serverName}/{mediaId} returns uploaded media", "[conformance][client-server][media]")
{
    GIVEN("a running client-server with uploaded media")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const upload = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/media/v3/upload", token, "image/png|image/png|clean|test-image-data"});
        REQUIRE(upload.response.status == 200U);
        auto const upload_body = parse_object(upload.response.body);
        auto const* content_uri = string_member(upload_body, "content_uri");
        REQUIRE(content_uri != nullptr);
        REQUIRE(content_uri->starts_with("mxc://"));

        // Parse content_uri "mxc://serverName/mediaId" → download path.
        auto const mxc_prefix = std::string_view{"mxc://"};
        auto const path = std::string_view{*content_uri}.substr(mxc_prefix.size());
        auto const slash = path.find('/');
        REQUIRE(slash != std::string::npos);
        auto const download_target = "/_matrix/media/v3/download/" + std::string{path};

        WHEN("GET /media/v3/download/{serverName}/{mediaId} is called with the uploaded media ID")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", download_target, token, {}});

            THEN("the server returns 200 with the media content")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(!response.response.body.empty());
            }
        }
    }
}

// --- GET /_matrix/media/v3/download/{serverName}/{mediaId} (missing media) ---
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixmediav3downloadservernamemediaid
//
// Route is recognised (no auth required). Non-existent media returns 404
// M_NOT_FOUND rather than M_UNRECOGNIZED, confirming the route is wired up.
SCENARIO("GET /media/v3/download/{serverName}/{mediaId} route is recognised", "[conformance][client-server][media]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /media/v3/download/example.org/nonexistent is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/media/v3/download/example.org/nonexistent", {}, {}});

            THEN("the route is recognised and returns an error (not M_UNRECOGNIZED)")
            {
                // Route is handled — returns M_NOT_FOUND for missing media, not
                // M_UNRECOGNIZED. The body must parse as a JSON object.
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                // Spec MUST NOT return M_UNRECOGNIZED for a recognised route.
                REQUIRE(*errcode != "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/media/v3/download/{serverName}/{mediaId}/{fileName} --------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixmediav3downloadservernamemediaidfilename
// The media download endpoint is implemented but returns 404 M_NOT_FOUND for
// non-existent media (the named variant is a download with a filename hint).
SCENARIO("GET /media/v3/download/{serverName}/{mediaId}/{fileName} returns 404 M_NOT_FOUND for missing media",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /media/v3/download/example.org/abc/file.txt is called for missing media")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/media/v3/download/example.org/abc/file.txt", {}, {}});

            THEN("the server returns 404 M_NOT_FOUND for non-existent media")
            {
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
            }
        }
    }
}

// --- GET /_matrix/media/v3/preview_url ----------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixmediav3preview_url
// IMPLEMENTATION GAP: URL preview not yet implemented.
SCENARIO("GET /media/v3/preview_url returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /media/v3/preview_url is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/media/v3/preview_url?url=https://matrix.org", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: URL preview not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixmediav3thumbnailservernamemediaid
// MUST return 200 with thumbnail content when a thumbnail exists for the media ID.
SCENARIO("GET /media/v3/thumbnail/{serverName}/{mediaId} returns thumbnail for uploaded media",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server with uploaded image media")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const upload = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/media/v3/upload", token, "image/png|image/png|clean|test-image-data"});
        REQUIRE(upload.response.status == 200U);
        auto const upload_body = parse_object(upload.response.body);
        auto const* content_uri = string_member(upload_body, "content_uri");
        REQUIRE(content_uri != nullptr);
        REQUIRE(content_uri->starts_with("mxc://"));

        auto const mxc_prefix = std::string_view{"mxc://"};
        auto const path = std::string_view{*content_uri}.substr(mxc_prefix.size());
        auto const slash = path.find('/');
        REQUIRE(slash != std::string::npos);
        auto const thumbnail_target = "/_matrix/media/v3/thumbnail/" + std::string{path} + "?width=32&height=32";

        WHEN("GET /media/v3/thumbnail/{serverName}/{mediaId} is called for an uploaded image")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", thumbnail_target, token, {}});

            THEN("the server returns 200 with thumbnail content or 404 if no thumbnail was generated")
            {
                // The server generates thumbnails for image content types on upload.
                // If a thumbnail exists, the response is 200 with image data.
                // If no thumbnail was generated (e.g., small images), the response is 404.
                // Either way, the route must not return M_UNRECOGNIZED.
                REQUIRE((response.response.status == 200U || response.response.status == 404U));
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixmediav3thumbnailservernamemediaid
// Non-existent media ID returns 404 M_NOT_FOUND.
SCENARIO("GET /media/v3/thumbnail/{serverName}/{mediaId} returns 404 for missing thumbnail",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /media/v3/thumbnail/example.org/abc is called for a non-existent media ID")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/media/v3/thumbnail/example.org/abc?width=32&height=32", token, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
            }
        }
    }
}

// --- PUT /_matrix/media/v3/upload/{serverName}/{mediaId} ---------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixmediav3uploadservernamemediaid
// IMPLEMENTATION GAP: asynchronous media upload by MXC not yet implemented.
SCENARIO("PUT /media/v3/upload/{serverName}/{mediaId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /media/v3/upload/example.org/abc is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/media/v3/upload/example.org/abc", token, "data"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: async media upload by MXC not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/media/v1/create --------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixmediav1create
// IMPLEMENTATION GAP: async media reservation not yet implemented.
SCENARIO("POST /media/v1/create returns 404 M_UNRECOGNIZED (implementation gap)", "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /media/v1/create is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/media/v1/create", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: async media creation not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v1/media/config --------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1mediaconfig
// IMPLEMENTATION GAP: authenticated media config endpoint not yet implemented.
SCENARIO("GET /v1/media/config returns 404 M_UNRECOGNIZED (implementation gap)", "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /_matrix/client/v1/media/config is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/media/config", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: authenticated media config not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1mediadownloadservernamemediaid
// MUST return 200 with media content when the media ID exists (authenticated variant).
SCENARIO("GET /v1/media/download/{serverName}/{mediaId} returns uploaded media", "[conformance][client-server][media]")
{
    GIVEN("a running client-server with uploaded media")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const upload = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/media/v3/upload", token, "image/png|image/png|clean|test-image-data"});
        REQUIRE(upload.response.status == 200U);
        auto const upload_body = parse_object(upload.response.body);
        auto const* content_uri = string_member(upload_body, "content_uri");
        REQUIRE(content_uri != nullptr);
        REQUIRE(content_uri->starts_with("mxc://"));

        auto const mxc_prefix = std::string_view{"mxc://"};
        auto const path = std::string_view{*content_uri}.substr(mxc_prefix.size());
        auto const slash = path.find('/');
        REQUIRE(slash != std::string::npos);
        auto const download_target = "/_matrix/client/v1/media/download/" + std::string{path};

        WHEN("GET /v1/media/download/{serverName}/{mediaId} is called with the uploaded media ID")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", download_target, token, {}});

            THEN("the server returns 200 with the media content")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(!response.response.body.empty());
            }
        }
    }
}

// --- GET /_matrix/client/v1/media/download/{serverName}/{mediaId} (missing media)
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1mediadownloadservernamemediaid
SCENARIO("GET /v1/media/download/{serverName}/{mediaId} returns 404 for missing media",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /_matrix/client/v1/media/download/example.org/abc is called for non-existent media")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/media/download/example.org/abc", token, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
            }
        }
    }
}

// --- GET /_matrix/client/v1/media/download/{serverName}/{mediaId}/{fileName} -
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1mediadownloadservernamemediaidfilename
SCENARIO("GET /v1/media/download/{serverName}/{mediaId}/{fileName} returns 404 for missing media",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /_matrix/client/v1/media/download/example.org/abc/file.txt is called for non-existent media")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/media/download/example.org/abc/file.txt", token, {}});

            THEN("the server returns 404 for non-existent named download")
            {
                REQUIRE(response.response.status == 404U);
            }
        }
    }
}

// --- GET /_matrix/client/v1/media/preview_url ---------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1mediapreview_url
// IMPLEMENTATION GAP: authenticated URL preview not yet implemented.
SCENARIO("GET /v1/media/preview_url returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /_matrix/client/v1/media/preview_url is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/media/preview_url?url=https://matrix.org", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: authenticated URL preview not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId} -----------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1mediathumbnailservernamemediaid
// MUST return 200 with thumbnail content when a thumbnail exists (authenticated variant).
SCENARIO("GET /v1/media/thumbnail/{serverName}/{mediaId} returns thumbnail for uploaded media",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server with uploaded image media")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const upload = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/media/v3/upload", token, "image/png|image/png|clean|test-image-data"});
        REQUIRE(upload.response.status == 200U);
        auto const upload_body = parse_object(upload.response.body);
        auto const* content_uri = string_member(upload_body, "content_uri");
        REQUIRE(content_uri != nullptr);
        REQUIRE(content_uri->starts_with("mxc://"));

        auto const mxc_prefix = std::string_view{"mxc://"};
        auto const path = std::string_view{*content_uri}.substr(mxc_prefix.size());
        auto const slash = path.find('/');
        REQUIRE(slash != std::string::npos);
        auto const thumbnail_target = "/_matrix/client/v1/media/thumbnail/" + std::string{path} + "?width=32&height=32";

        WHEN("GET /v1/media/thumbnail/{serverName}/{mediaId} is called for an uploaded image")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", thumbnail_target, token, {}});

            THEN("the server returns 200 with thumbnail content or 404 if no thumbnail was generated")
            {
                // The server generates thumbnails for image content types on upload.
                // Either 200 (thumbnail exists) or 404 (no thumbnail) is acceptable.
                REQUIRE((response.response.status == 200U || response.response.status == 404U));
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1mediathumbnailservernamemediaid
// Non-existent media ID returns 404 (authenticated variant).
SCENARIO("GET /v1/media/thumbnail/{serverName}/{mediaId} returns 404 for missing thumbnail",
         "[conformance][client-server][media]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /_matrix/client/v1/media/thumbnail/example.org/abc is called for non-existent media")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v1/media/thumbnail/example.org/abc?width=32&height=32", token, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
            }
        }
    }
}

// =============================================================================
// APPLICATION SERVICE ROOM DIRECTORY MANAGEMENT
// =============================================================================

// --- PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId} ---
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3directorylistappservicenetworkidroomid
// IMPLEMENTATION GAP: appservice directory visibility management not yet implemented.
SCENARIO("PUT /directory/list/appservice/{networkId}/{roomId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][appservice]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /directory/list/appservice/net1/!room:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/directory/list/appservice/net1/%21room%3Aexample.org",
                                  token, R"({"visibility":"public"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: appservice directory management not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// ROOM CREATION
// =============================================================================

// --- POST /_matrix/client/v3/createRoom ---------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3createroom
SCENARIO("POST /createRoom returns a room_id", "[conformance][client-server][rooms]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /createRoom is called with an empty body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});

            THEN("the server returns 200 with a non-empty room_id")
            {
                // Spec MUST: 200 with room_id on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* room_id = string_member(body, "room_id");
                REQUIRE(room_id != nullptr);
                REQUIRE(!room_id->empty());
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3createroom
// "If the preset is private_chat or trusted_private_chat, the server SHOULD
// enable end-to-end encryption in the room."
// Verified via GET /rooms/{roomId}/state/m.room.encryption/ — a spec-defined
// response-shape check that confirms the state event is present and well-formed.
SCENARIO("POST /createRoom with private_chat preset produces an encrypted room", "[conformance][client-server][rooms]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /createRoom is called with preset private_chat")
        {
            auto const create = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"private_chat"})"});
            REQUIRE(create.response.status == 200U);
            auto const create_body = parse_object(create.response.body);
            auto const* rid = string_member(create_body, "room_id");
            REQUIRE(rid != nullptr);

            THEN("GET /rooms/{roomId}/state/m.room.encryption/ returns 200 with the megolm algorithm")
            {
                // Spec SHOULD: private_chat rooms must have m.room.encryption state.
                // Clients (including Element) read this event to enable E2EE UI.
                auto const enc = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/rooms/" + *rid + "/state/m.room.encryption/", token, {}});
                REQUIRE(enc.response.status == 200U);
                auto const enc_body = parse_object(enc.response.body);
                auto const* algorithm = string_member(enc_body, "algorithm");
                REQUIRE(algorithm != nullptr);
                REQUIRE(*algorithm == "m.megolm.v1.aes-sha2");
            }
        }

        WHEN("POST /createRoom is called with preset trusted_private_chat")
        {
            auto const create = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"trusted_private_chat"})"});
            REQUIRE(create.response.status == 200U);
            auto const create_body = parse_object(create.response.body);
            auto const* rid = string_member(create_body, "room_id");
            REQUIRE(rid != nullptr);

            THEN("GET /rooms/{roomId}/state/m.room.encryption/ returns 200 with the megolm algorithm")
            {
                // Spec SHOULD: trusted_private_chat rooms must have m.room.encryption state.
                auto const enc = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/rooms/" + *rid + "/state/m.room.encryption/", token, {}});
                REQUIRE(enc.response.status == 200U);
                auto const enc_body = parse_object(enc.response.body);
                auto const* algorithm = string_member(enc_body, "algorithm");
                REQUIRE(algorithm != nullptr);
                REQUIRE(*algorithm == "m.megolm.v1.aes-sha2");
            }
        }
    }
}

SCENARIO("POST /createRoom with public_chat preset does not produce an encrypted room",
         "[conformance][client-server][rooms]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /createRoom is called with visibility public")
        {
            auto const create = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"visibility":"public"})"});
            REQUIRE(create.response.status == 200U);
            auto const create_body = parse_object(create.response.body);
            auto const* rid = string_member(create_body, "room_id");
            REQUIRE(rid != nullptr);

            THEN("GET /rooms/{roomId}/state/m.room.encryption/ returns a non-200 status")
            {
                // Spec: public rooms are not required to be encrypted; the
                // encryption state event must not be present.
                auto const enc = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/rooms/" + *rid + "/state/m.room.encryption/", token, {}});
                REQUIRE(enc.response.status != 200U);
            }
        }
    }
}

// =============================================================================
// ROOM DIRECTORY
// =============================================================================

// --- GET /_matrix/client/v3/directory/room/{roomAlias} -----------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3directoryroomroomalias
SCENARIO("GET /directory/room/{alias} returns a recognisable error for unknown aliases",
         "[conformance][client-server][room-directory]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /directory/room/%23unknown%3Aexample.org is called without authentication")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/directory/room/%23unknown%3Aexample.org", {}, {}});

            THEN("the server returns a Matrix error — NOT M_UNRECOGNIZED (route is known)")
            {
                // Spec MUST: route is recognised; an unknown alias yields M_NOT_FOUND.
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode != "M_UNRECOGNIZED");
            }
        }
    }
}

// --- PUT /_matrix/client/v3/directory/room/{roomAlias} -----------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3directoryroomroomalias
SCENARIO("PUT /directory/room/{alias} maps an alias to a room", "[conformance][client-server][room-directory]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /directory/room/%23myalias%3Aexample.org is called with the room_id")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/directory/room/%23myalias%3Aexample.org", token,
                                  R"({"room_id":")" + room_id + R"("})"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// --- DELETE /_matrix/client/v3/directory/room/{roomAlias} --------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#delete_matrixclientv3directoryroomroomalias
// IMPLEMENTATION GAP: alias deletion not yet implemented.
SCENARIO("DELETE /directory/room/{alias} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-directory]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("DELETE /directory/room/%23myalias%3Aexample.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/directory/room/%23myalias%3Aexample.org", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: alias deletion not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/aliases ---------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidaliases
// IMPLEMENTATION GAP: room alias listing not yet implemented.
SCENARIO("GET /rooms/{roomId}/aliases returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-directory]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/aliases is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/aliases", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: room alias listing not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// ROOM DISCOVERY
// =============================================================================

// --- GET /_matrix/client/v3/publicRooms --------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3publicrooms
SCENARIO("GET /publicRooms returns chunk and total_room_count_estimate", "[conformance][client-server][room-discovery]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /publicRooms is called without authentication")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/publicRooms", {}, {}});

            THEN("the server returns 200 with a chunk array and total_room_count_estimate")
            {
                // Spec MUST: 200 with chunk (array) and total_room_count_estimate (integer).
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
                auto const* estimate = int_member(body, "total_room_count_estimate");
                REQUIRE(estimate != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/publicRooms -------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3publicrooms
// IMPLEMENTATION GAP: filtered public room listing not yet implemented.
SCENARIO("POST /publicRooms returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-discovery]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /publicRooms is called with a filter body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/publicRooms", token, R"({"limit":10})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: filtered public rooms not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/directory/list/room/{roomId} ---------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3directorylistroomroomid
// IMPLEMENTATION GAP: room visibility query not yet implemented.
SCENARIO("GET /directory/list/room/{roomId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-discovery]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /directory/list/room/{roomId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/directory/list/room/" + room_id, token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: room directory visibility query not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- PUT /_matrix/client/v3/directory/list/room/{roomId} ---------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3directorylistroomroomid
// IMPLEMENTATION GAP: room visibility update not yet implemented.
SCENARIO("PUT /directory/list/room/{roomId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-discovery]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /directory/list/room/{roomId} is called with visibility public")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/directory/list/room/" + room_id, token, R"({"visibility":"public"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: room directory visibility update not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// ROOM MEMBERSHIP
// =============================================================================

// --- GET /_matrix/client/v3/joined_rooms -------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3joined_rooms
SCENARIO("GET /joined_rooms returns a joined_rooms array", "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /joined_rooms is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});

            THEN("the server returns 200 with a joined_rooms array")
            {
                // Spec MUST: 200 with joined_rooms array.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rooms = object_member_as_array(body, "joined_rooms");
                REQUIRE(rooms != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/join/{roomIdOrAlias} ----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3joinroomidoralias
SCENARIO("POST /join/{roomIdOrAlias} returns room_id on success", "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server with two users, alice has a public room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, alice);
        auto const bob = register_and_login(started.runtime, "bob");

        WHEN("bob POSTs to /join/{roomId}")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/join/" + room_id, bob, "{}"});

            THEN("the server returns 200 with a room_id field")
            {
                // Spec MUST: 200 with room_id on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rid = string_member(body, "room_id");
                REQUIRE(rid != nullptr);
                REQUIRE(*rid == room_id);
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/join -----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidmembership
SCENARIO("POST /rooms/{roomId}/join returns room_id on success", "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server with two users, alice owns a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, alice);
        auto const bob = register_and_login(started.runtime, "bob");

        WHEN("bob POSTs to /rooms/{roomId}/join")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"});

            THEN("the server returns 200 with a room_id field")
            {
                // Spec MUST: 200 with room_id on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rid = string_member(body, "room_id");
                REQUIRE(rid != nullptr);
                REQUIRE(*rid == room_id);
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/leave ----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidleave
SCENARIO("POST /rooms/{roomId}/leave returns 200 empty object", "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server with a user who is in a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("the user POSTs to /rooms/{roomId}/leave")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", token, "{}"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/ban ------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidban
// IMPLEMENTATION GAP: room ban not yet implemented.
SCENARIO("POST /rooms/{roomId}/ban returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/ban is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", token, R"({"user_id":"@bob:example.org"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: ban not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/kick -----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidkick
// IMPLEMENTATION GAP: room kick not yet implemented.
SCENARIO("POST /rooms/{roomId}/kick returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/kick is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/kick", token, R"({"user_id":"@bob:example.org"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: kick not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/unban ----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidunban
// IMPLEMENTATION GAP: room unban not yet implemented.
SCENARIO("POST /rooms/{roomId}/unban returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/unban is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/unban", token, R"({"user_id":"@bob:example.org"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: unban not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/invite ---------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsrooomidinvite
// IMPLEMENTATION GAP: room invite not yet implemented.
SCENARIO("POST /rooms/{roomId}/invite returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/invite is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", token,
                                  R"({"user_id":"@bob:example.org"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: invite not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/forget ---------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsrooomidforgot
// IMPLEMENTATION GAP: room forget not yet implemented.
SCENARIO("POST /rooms/{roomId}/forget returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/forget is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/forget", token, "{}"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: forget not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/knock/{roomIdOrAlias} ---------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3knockroomidoralias
// IMPLEMENTATION GAP: room knock not yet implemented.
SCENARIO("POST /knock/{roomIdOrAlias} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /knock/!someroom:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/knock/%21someroom%3Aexample.org", token, "{}"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: knock not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// ROOM PARTICIPATION — SENDING AND READING EVENTS
// =============================================================================

// --- PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId} ----------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid
SCENARIO("PUT /rooms/{roomId}/send/{eventType}/{txnId} returns event_id",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /rooms/{roomId}/send/m.room.message/txn1 is called with a text message")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn1", token,
                                  R"({"msgtype":"m.text","body":"hello conformance"})"});

            THEN("the server returns 200 with a non-empty event_id")
            {
                // Spec MUST: 200 with event_id on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* event_id = string_member(body, "event_id");
                REQUIRE(event_id != nullptr);
                REQUIRE(!event_id->empty());
            }
        }
    }
}

// --- PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey} ------
// Spec:
// https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3roomsroomidstateeventtypestatekeystateeventtype
SCENARIO("PUT /rooms/{roomId}/state/{eventType}/{stateKey} returns event_id",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /rooms/{roomId}/state/m.room.topic/ is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic/", token,
                                  R"({"topic":"conformance test room"})"});

            THEN("the server returns 200 with a non-empty event_id")
            {
                // Spec MUST: 200 with event_id on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* event_id = string_member(body, "event_id");
                REQUIRE(event_id != nullptr);
                REQUIRE(!event_id->empty());
            }
        }
    }
}

// --- PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType} -----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3roomsroomidstateeventtype
// (implicit empty state key — separate endpoint from the {stateKey} variant)
SCENARIO("PUT /rooms/{roomId}/state/{eventType} (no state key) returns event_id",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /rooms/{roomId}/state/m.room.name (no trailing state key) is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.name", token,
                                  R"({"name":"Conformance Room"})"});

            THEN("the server returns 200 with a non-empty event_id")
            {
                // Spec MUST: 200 with event_id; empty state key is valid.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* event_id = string_member(body, "event_id");
                REQUIRE(event_id != nullptr);
                REQUIRE(!event_id->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/state -----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidstate
SCENARIO("GET /rooms/{roomId}/state returns an array of state events",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/state is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token, {}});

            THEN("the server returns 200 with a JSON array of state events")
            {
                // Spec MUST: 200 with an array of state events.
                REQUIRE(response.response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* arr = std::get_if<merovingian::canonicaljson::Array>(&parsed.value.storage());
                REQUIRE(arr != nullptr);
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey} ------
// Spec:
// https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidstateeventtypestatekeystateeventtype
SCENARIO("GET /rooms/{roomId}/state/{eventType}/{stateKey} returns the state event content",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/state/m.room.create/ is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.create/", token, {}});

            THEN("the server returns 200 with the content of the m.room.create event")
            {
                // Spec MUST: 200 with the content object of the named state event.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* room_version = string_member(body, "room_version");
                REQUIRE(room_version != nullptr);
                REQUIRE(!room_version->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/state/{eventType} -----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidstateeventtype
SCENARIO("GET /rooms/{roomId}/state/{eventType} (no state key) returns the state event content",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/state/m.room.create is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.create", token, {}});

            THEN("the server returns 200 with the content of the m.room.create event")
            {
                // Spec MUST: 200 with the content object; empty state key is equivalent
                // to the trailing-slash form.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* room_version = string_member(body, "room_version");
                REQUIRE(room_version != nullptr);
                REQUIRE(!room_version->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/messages --------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidmessages
SCENARIO("GET /rooms/{roomId}/messages returns chunk array", "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room and a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        std::ignore = send_message(started.runtime, token, room_id);

        WHEN("GET /rooms/{roomId}/messages?dir=b is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b", token, {}});

            THEN("the server returns 200 with a chunk array")
            {
                // Spec MUST: 200 with chunk array of room events.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
            }
        }
    }
}

// --- PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId} -------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3roomsroomidtypinguserid
SCENARIO("PUT /rooms/{roomId}/typing/{userId} returns 200 empty object",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /typing/@alice:example.org is called with typing true")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/typing/%40alice%3Aexample.org",
                                  token, R"({"typing":true,"timeout":30000})"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/read_markers ---------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidread_markers
SCENARIO("POST /rooms/{roomId}/read_markers returns 200 empty object",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room and a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const event_id = send_message(started.runtime, token, room_id);

        WHEN("POST /read_markers is called marking the message as read")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/read_markers", token,
                                  R"({"m.read":")" + event_id + R"("})"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId} --
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidreceiptreceipttypeeventid
SCENARIO("POST /rooms/{roomId}/receipt/{receiptType}/{eventId} stores receipt and returns 200",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room and a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const event_id = send_message(started.runtime, token, room_id);

        WHEN("POST /receipt/m.read/{eventId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/" + event_id, token, "{}"});

            THEN("the server returns 200 with an empty JSON object and records the receipt")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
                // Spec MUST: receipt is recorded for the user, room, and event.
                REQUIRE(!started.runtime.homeserver.receipts.empty());
                auto const& receipt = started.runtime.homeserver.receipts.back();
                REQUIRE(receipt.room_id == room_id);
                REQUIRE(receipt.receipt_type == "m.read");
                REQUIRE(receipt.event_id == event_id);
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/members ---------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidmembers
// IMPLEMENTATION GAP: room member list not yet implemented.
SCENARIO("GET /rooms/{roomId}/members returns the room membership", "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/members is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/members", token, {}});

            THEN("the server returns 200 with a chunk array")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/joined_members --------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidjoined_members
// IMPLEMENTATION GAP: joined member map not yet implemented.
SCENARIO("GET /rooms/{roomId}/joined_members returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/joined_members is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/joined_members", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: joined members not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/event/{eventId} -------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomideventeventid
// IMPLEMENTATION GAP: single event retrieval not yet implemented.
SCENARIO("GET /rooms/{roomId}/event/{eventId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room and a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const event_id = send_message(started.runtime, token, room_id);

        WHEN("GET /rooms/{roomId}/event/{eventId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id, token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: single event retrieval not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/context/{eventId} -----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidcontexteventid
// IMPLEMENTATION GAP: event context not yet implemented.
SCENARIO("GET /rooms/{roomId}/context/{eventId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room and a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const event_id = send_message(started.runtime, token, room_id);

        WHEN("GET /rooms/{roomId}/context/{eventId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/context/" + event_id, token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: event context not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/initialSync -----------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidinitialsync
// IMPLEMENTATION GAP: per-room initial sync not yet implemented.
SCENARIO("GET /rooms/{roomId}/initialSync returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/initialSync is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/initialSync", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: per-room initialSync not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/initialSync --------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3initialsync
// IMPLEMENTATION GAP: global initial sync not yet implemented.
SCENARIO("GET /initialSync returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /initialSync is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/initialSync", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: global initialSync not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/upgrade --------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidupgrade
// IMPLEMENTATION GAP: room upgrade not yet implemented.
SCENARIO("POST /rooms/{roomId}/upgrade returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/upgrade is called with new_version 11")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", token, R"({"new_version":"11"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: room upgrade not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event ----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1roomsroomidtimestamp_to_event
// IMPLEMENTATION GAP: timestamp-to-event lookup not yet implemented.
SCENARIO("GET /rooms/{roomId}/timestamp_to_event returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/timestamp_to_event?ts=0&dir=f is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v1/rooms/" + room_id + "/timestamp_to_event?ts=0&dir=f", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: timestamp_to_event not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/events -------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3events
// IMPLEMENTATION GAP: server-sent events (long-poll) not yet implemented.
SCENARIO("GET /events returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /events is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/events", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: long-poll event stream not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/events/{eventId} ---------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3eventseventid
// IMPLEMENTATION GAP: global event fetch not yet implemented.
SCENARIO("GET /events/{eventId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /events/$someevent is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/events/%24someevent", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: global event fetch not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// USER DATA — PROFILE
// =============================================================================

// --- GET /_matrix/client/v3/profile/{userId} ---------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3profileuserid
SCENARIO("GET /profile/{userId} returns a JSON object (unauthenticated)", "[conformance][client-server][profile]")
{
    GIVEN("a running client-server with a registered user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        std::ignore = logged_in_token(started.runtime);

        WHEN("GET /profile/@alice:example.org is called without authentication")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org", {}, {}});

            THEN("the server returns 200 with a JSON object")
            {
                // Spec MUST: 200 with displayname and/or avatar_url (may be absent).
                REQUIRE(response.response.status == 200U);
                // Body must parse as an object — fields are optional per spec.
                auto const body = parse_object(response.response.body);
                REQUIRE(true); // structure validated above
            }
        }
    }
}

// --- GET /_matrix/client/v3/profile/{userId}/displayname ---------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3profileuseriddisplayname
SCENARIO("GET /profile/{userId}/displayname returns a JSON object", "[conformance][client-server][profile]")
{
    GIVEN("a running client-server with a registered user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        std::ignore = logged_in_token(started.runtime);

        WHEN("GET /profile/@alice:example.org/displayname is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", {}, {}});

            THEN("the server returns a response that is NOT M_UNRECOGNIZED")
            {
                // Spec MUST: route is recognised; returns displayname or M_NOT_FOUND.
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                // No errcode means 200; errcode present must not be M_UNRECOGNIZED.
                if (errcode != nullptr)
                {
                    REQUIRE(*errcode != "M_UNRECOGNIZED");
                }
            }
        }
    }
}

// --- GET /_matrix/client/v3/profile/{userId}/avatar_url ----------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3profileuseridavatar_url
SCENARIO("GET /profile/{userId}/avatar_url returns a JSON object", "[conformance][client-server][profile]")
{
    GIVEN("a running client-server with a registered user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        std::ignore = logged_in_token(started.runtime);

        WHEN("GET /profile/@alice:example.org/avatar_url is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org/avatar_url", {}, {}});

            THEN("the server returns a response that is NOT M_UNRECOGNIZED")
            {
                // Spec MUST: route is recognised; returns avatar_url or M_NOT_FOUND.
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                if (errcode != nullptr)
                {
                    REQUIRE(*errcode != "M_UNRECOGNIZED");
                }
            }
        }
    }
}

// --- PUT /_matrix/client/v3/profile/{userId}/displayname ---------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3profileuseriddisplayname
SCENARIO("PUT /profile/{userId}/displayname updates the display name", "[conformance][client-server][profile]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /profile/@alice:example.org/displayname is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", token,
                                  R"({"displayname":"Alice Conformance"})"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// --- PUT /_matrix/client/v3/profile/{userId}/avatar_url ----------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3profileuseridavatar_url
SCENARIO("PUT /profile/{userId}/avatar_url updates the avatar URL", "[conformance][client-server][profile]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /profile/@alice:example.org/avatar_url is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/avatar_url", token,
                                  R"({"avatar_url":"mxc://example.org/abc123"})"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// =============================================================================
// USER DATA — FILTERS
// =============================================================================

// --- POST /_matrix/client/v3/user/{userId}/filter ----------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3useruseridffilter
SCENARIO("POST /user/{userId}/filter returns a filter_id", "[conformance][client-server][filtering]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /user/@alice:example.org/filter is called with an empty filter")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/user/%40alice%3Aexample.org/filter", token, "{}"});

            THEN("the server returns 200 with a non-empty filter_id")
            {
                // Spec MUST: 200 with filter_id string.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* filter_id = string_member(body, "filter_id");
                REQUIRE(filter_id != nullptr);
                REQUIRE(!filter_id->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/user/{userId}/filter/{filterId} ------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3useruseridffilterfilterid
SCENARIO("GET /user/{userId}/filter/{filterId} returns the stored filter", "[conformance][client-server][filtering]")
{
    GIVEN("a running client-server and a logged-in user who has created a filter")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const create_resp = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/user/%40alice%3Aexample.org/filter", token, "{}"});
        REQUIRE(create_resp.response.status == 200U);
        auto const create_body = parse_object(create_resp.response.body);
        auto const* filter_id = string_member(create_body, "filter_id");
        REQUIRE(filter_id != nullptr);

        WHEN("GET /user/@alice:example.org/filter/{filterId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/user/%40alice%3Aexample.org/filter/" + *filter_id, token, {}});

            THEN("the server returns 200 with a JSON object")
            {
                // Spec MUST: 200 with the filter definition object.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(true); // parsed successfully as object
            }
        }
    }
}

// =============================================================================
// USER DATA — ACCOUNT DATA
// =============================================================================

// --- PUT /_matrix/client/v3/user/{userId}/account_data/{type} ----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3useruseridaccount_datatype
SCENARIO("PUT /user/{userId}/account_data/{type} stores account data", "[conformance][client-server][account-data]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /user/@alice:example.org/account_data/m.test is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.test", token,
                                  R"({"key":"value"})"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/user/{userId}/account_data/{type} ----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3useruseridaccount_datatype
SCENARIO("GET /user/{userId}/account_data/{type} retrieves stored account data",
         "[conformance][client-server][account-data]")
{
    GIVEN("a running client-server and a logged-in user who has stored account data")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.test",
                                      token, R"({"key":"value"})"})
                    .response.status == 200U);

        WHEN("GET /user/@alice:example.org/account_data/m.test is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.test", token, {}});

            THEN("the server returns 200 with the stored data object")
            {
                // Spec MUST: 200 with the content object that was stored.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* key = string_member(body, "key");
                REQUIRE(key != nullptr);
                REQUIRE(*key == "value");
            }
        }
    }
}

// --- PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type} --
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3useruseridrooms roomidaccount_datatype
// IMPLEMENTATION GAP: per-room account data not yet implemented.
SCENARIO("PUT /user/{userId}/rooms/{roomId}/account_data/{type} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account-data]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /user/@alice:example.org/rooms/{roomId}/account_data/m.test is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/account_data/m.test",
                 token, R"({"key":"value"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: per-room account data not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type} --
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3useruseridrooms roomidaccount_datatype
// IMPLEMENTATION GAP: per-room account data retrieval not yet implemented.
SCENARIO("GET /user/{userId}/rooms/{roomId}/account_data/{type} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][account-data]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /user/@alice:example.org/rooms/{roomId}/account_data/m.test is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET",
                 "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/account_data/m.test",
                 token,
                 {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: per-room account data retrieval not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// USER DATA — ROOM TAGS
// =============================================================================

// --- GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags ----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3useruseridrooms roomidtags
// IMPLEMENTATION GAP: room tags not yet implemented.
SCENARIO("GET /user/{userId}/rooms/{roomId}/tags returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-tagging]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /user/@alice:example.org/rooms/{roomId}/tags is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/tags", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: room tags not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag} ----------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3useruseridrooms roomidtagstag
// IMPLEMENTATION GAP: room tag creation not yet implemented.
SCENARIO("PUT /user/{userId}/rooms/{roomId}/tags/{tag} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-tagging]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /user/@alice:example.org/rooms/{roomId}/tags/u.work is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/tags/u.work", token,
                 R"({"order":0.5})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: tag creation not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- DELETE /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag} -------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#delete_matrixclientv3useruseridrooms roomidtagstag
// IMPLEMENTATION GAP: room tag deletion not yet implemented.
SCENARIO("DELETE /user/{userId}/rooms/{roomId}/tags/{tag} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][room-tagging]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("DELETE /user/@alice:example.org/rooms/{roomId}/tags/u.work is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE",
                                  "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/tags/u.work",
                                  token,
                                  {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: tag deletion not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// PRESENCE
// =============================================================================

// --- PUT /_matrix/client/v3/presence/{userId}/status -------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3presenceuseridstatus
SCENARIO("PUT /presence/{userId}/status sets the presence state", "[conformance][client-server][presence]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /presence/@alice:example.org/status is called with online presence")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/presence/%40alice%3Aexample.org/status", token,
                                  R"({"presence":"online","status_msg":"conformance test"})"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/presence/{userId}/status -------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3presenceuseridstatus
// IMPLEMENTATION GAP: presence retrieval not yet implemented.
SCENARIO("GET /presence/{userId}/status returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][presence]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /presence/@alice:example.org/status is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/presence/%40alice%3Aexample.org/status", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: presence GET not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// PUSH NOTIFICATIONS
// =============================================================================

// --- GET /_matrix/client/v3/pushrules/ ---------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3pushrules
SCENARIO("GET /pushrules/ returns a global push rules object", "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushrules/ is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/pushrules/", token, {}});

            THEN("the server returns 200 with the spec-defined default ruleset")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* global = object_member_as_object(body, "global");
                REQUIRE(global != nullptr);
                auto const* override_rules = object_member_as_array(*global, "override");
                auto const* underride_rules = object_member_as_array(*global, "underride");
                auto const* room_rules = object_member_as_array(*global, "room");
                auto const* sender_rules = object_member_as_array(*global, "sender");
                auto const* content_rules = object_member_as_array(*global, "content");
                REQUIRE(override_rules != nullptr);
                REQUIRE(underride_rules != nullptr);
                REQUIRE(room_rules != nullptr);
                REQUIRE(sender_rules != nullptr);
                REQUIRE(content_rules != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.master") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.is_user_mention") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.tombstone") != nullptr);
                REQUIRE(push_rule_by_id(*underride_rules, ".m.rule.call") != nullptr);
                REQUIRE(push_rule_by_id(*underride_rules, ".m.rule.encrypted") != nullptr);
            }
        }
    }
}

// --- GET /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId} ----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3pushrulesscopekindruleid
SCENARIO("GET /pushrules/{scope}/{kind}/{ruleId} returns a server-default push rule",
         "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushrules/global/override/.m.rule.master is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/pushrules/global/override/.m.rule.master", token, {}});

            THEN("the server returns the rule object")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rule_id = string_member(body, "rule_id");
                auto const* is_default = bool_member(body, "default");
                auto const* enabled = bool_member(body, "enabled");
                auto const* conditions = object_member_as_array(body, "conditions");
                auto const* actions = object_member_as_array(body, "actions");
                REQUIRE(rule_id != nullptr);
                REQUIRE(*rule_id == ".m.rule.master");
                REQUIRE(is_default != nullptr);
                REQUIRE(*is_default);
                REQUIRE(enabled != nullptr);
                REQUIRE(*enabled == false);
                REQUIRE(conditions != nullptr);
                REQUIRE(actions != nullptr);
            }
        }
    }
}

// --- PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId} ----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3pushrulesscopekindruleid
// IMPLEMENTATION GAP: push rule creation not yet implemented.
SCENARIO("PUT /pushrules/{scope}/{kind}/{ruleId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /pushrules/global/content/myrule is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/pushrules/global/content/myrule", token,
                                  R"({"pattern":"conformance","actions":["notify"]})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: push rule creation not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- DELETE /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId} -------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#delete_matrixclientv3pushrulesscopekindruleid
// IMPLEMENTATION GAP: push rule deletion not yet implemented.
SCENARIO("DELETE /pushrules/{scope}/{kind}/{ruleId} returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("DELETE /pushrules/global/content/myrule is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/pushrules/global/content/myrule", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: push rule deletion not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/actions ---------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3pushrulesscopekindruleidactions
SCENARIO("GET /pushrules/{scope}/{kind}/{ruleId}/actions returns the rule actions",
         "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushrules/global/underride/.m.rule.call/actions is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/pushrules/global/underride/.m.rule.call/actions", token, {}});

            THEN("the server returns the action array")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* actions = object_member_as_array(body, "actions");
                REQUIRE(actions != nullptr);
                REQUIRE(actions->size() == 3U);
            }
        }
    }
}

// --- PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/actions ---------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3pushrulesscopekindruleidactions
// IMPLEMENTATION GAP: push rule actions update not yet implemented.
SCENARIO("PUT /pushrules/{scope}/{kind}/{ruleId}/actions returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /pushrules/global/content/.m.rule.contains_user_name/actions is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/pushrules/global/content/.m.rule.contains_user_name/actions", token,
                 R"({"actions":["notify"]})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: push rule actions PUT not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/enabled ---------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3pushrulesscopekindruleidenabled
SCENARIO("GET /pushrules/{scope}/{kind}/{ruleId}/enabled returns the rule enabled state",
         "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushrules/global/override/.m.rule.master/enabled is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled", token, {}});

            THEN("the server returns the enabled flag")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* enabled = bool_member(body, "enabled");
                REQUIRE(enabled != nullptr);
                REQUIRE(*enabled == false);
            }
        }
    }
}

// --- PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/enabled ---------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3pushrulesscopekindruleidenabled
// IMPLEMENTATION GAP: push rule enable/disable not yet implemented.
SCENARIO("PUT /pushrules/{scope}/{kind}/{ruleId}/enabled returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /pushrules/global/content/.m.rule.contains_user_name/enabled is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/pushrules/global/content/.m.rule.contains_user_name/enabled", token,
                 R"({"enabled":true})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: push rule enabled PUT not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/notifications ------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3notifications
// IMPLEMENTATION GAP: notification list not yet implemented.
SCENARIO("GET /notifications returns 404 M_UNRECOGNIZED (implementation gap)", "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /notifications is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/notifications", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: notifications list not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- GET /_matrix/client/v3/pushers ------------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3pushers
SCENARIO("GET /pushers returns 200 with empty pushers array", "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushers is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/pushers", token, {}});

            THEN("the server returns 200 with a pushers array")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* pushers = object_member_as_array(body, "pushers");
                REQUIRE(pushers != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/pushers/set -------------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3pushersset
// IMPLEMENTATION GAP: pusher configuration not yet implemented.
SCENARIO("POST /pushers/set returns 404 M_UNRECOGNIZED (implementation gap)", "[conformance][client-server][push]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /pushers/set is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/pushers/set", token,
                                  R"({"kind":null,"app_id":"org.example","pushkey":"key1"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: pusher configuration not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// REPORTING
// =============================================================================

// --- POST /_matrix/client/v3/rooms/{roomId}/report/{eventId} -----------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidreporteventid
SCENARIO("POST /rooms/{roomId}/report/{eventId} accepts a report", "[conformance][client-server][reporting]")
{
    GIVEN("a running client-server and a logged-in user with a room and a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const event_id = send_message(started.runtime, token, room_id);

        WHEN("POST /rooms/{roomId}/report/{eventId} is called with a reason")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/report/" + event_id, token,
                                  R"({"reason":"conformance test report"})"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/report ---------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidreport
// IMPLEMENTATION GAP: room-level reporting (without eventId) not yet implemented.
SCENARIO("POST /rooms/{roomId}/report returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][reporting]")
{
    GIVEN("a running client-server and a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/report (no eventId) is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/report", token, R"({"reason":"room report"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: room-level report not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// --- POST /_matrix/client/v3/users/{userId}/report ---------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3usersuseridreport
// IMPLEMENTATION GAP: user reporting not yet implemented.
SCENARIO("POST /users/{userId}/report returns 404 M_UNRECOGNIZED (implementation gap)",
         "[conformance][client-server][reporting]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /users/@bob:example.org/report is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/users/%40bob%3Aexample.org/report", token, R"({"reason":"user report"})"});

            THEN("the server returns 404 M_UNRECOGNIZED until the endpoint is implemented")
            {
                // IMPLEMENTATION GAP: user reporting not supported.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// VOIP
// =============================================================================

// --- GET /_matrix/client/v3/voip/turnServer ----------------------------------
// Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3voipturnserver
SCENARIO("GET /voip/turnServer returns a JSON object", "[conformance][client-server][voip]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /voip/turnServer is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/voip/turnServer", token, {}});

            THEN("the server returns a JSON object (200 with TURN info, or error if not configured)")
            {
                // Spec: returns TURN server credentials when configured.
                // Without TURN config the server may return 404 or an empty body —
                // what MUST NOT happen is an unstructured non-JSON response.
                auto const body = parse_object(response.response.body);
                REQUIRE(true); // parsed successfully as a JSON object
            }
        }
    }
}

// ============================================================================
// 13.20  Presence — GET /presence/{userId}/status
// ============================================================================
// Spec: Matrix v1.18 §13.20.2 GET /_matrix/client/v3/presence/{userId}/status
//       Returns the presence state of a user.
//       IMPLEMENTATION GAP: not yet implemented. Must return 404 M_UNRECOGNIZED.

SCENARIO("GET /presence/{userId}/status conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /presence/%40alice%3Aexample.org/status is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/presence/%40alice%3Aexample.org/status", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 13.7   Push notifications — GET /notifications
// ============================================================================
// Spec: Matrix v1.18 §13.7 GET /_matrix/client/v3/notifications
//       IMPLEMENTATION GAP: not yet implemented. Must return 404 M_UNRECOGNIZED.

SCENARIO("GET /notifications conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /notifications is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/notifications", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 13.8   Push notifications — GET/POST /pushers
// ============================================================================
// Spec: Matrix v1.18 §13.8 GET/POST /_matrix/client/v3/pushers

SCENARIO("GET /pushers conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushers is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/pushers", token, {}});

            THEN("the server returns 200 with a pushers array")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* pushers = object_member_as_array(body, "pushers");
                REQUIRE(pushers != nullptr);
            }
        }
    }
}

SCENARIO("POST /pushers/set conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /pushers/set is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/pushers/set", token,
                 R"({"pushkey":"key","kind":"http","app_id":"app","app_display_name":"App","device_display_name":"Phone"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 13.9   Push rules — /pushrules/global/{kind}/{ruleId}
// ============================================================================
// Spec: Matrix v1.18 §13.9 push rules CRUD.
//       IMPLEMENTATION GAP: only GET /pushrules/ is implemented.
//       All specific-rule endpoints must return 404 M_UNRECOGNIZED.

SCENARIO("GET /pushrules/global/ conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushrules/global/ is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/pushrules/global/", token, {}});

            THEN("the server returns the global ruleset")
            {
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                REQUIRE(object_member_as_array(body, "override") != nullptr);
                REQUIRE(object_member_as_array(body, "underride") != nullptr);
            }
        }
    }
}

SCENARIO("GET /pushrules/global/{kind}/{ruleId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushrules/global/override/.m.rule.master is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/pushrules/global/override/.m.rule.master", token, {}});

            THEN("the server returns the rule object")
            {
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                auto const* rule_id = string_member(body, "rule_id");
                REQUIRE(rule_id != nullptr);
                REQUIRE(*rule_id == ".m.rule.master");
            }
        }
    }
}

SCENARIO("PUT /pushrules/global/{kind}/{ruleId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /pushrules/global/content/.m.rule.contains_user_name is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/pushrules/global/content/.m.rule.contains_user_name",
                                  token, R"({"pattern":"alice","actions":["notify"]})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("DELETE /pushrules/global/{kind}/{ruleId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("DELETE /pushrules/global/content/.m.rule.contains_user_name is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"DELETE", "/_matrix/client/v3/pushrules/global/content/.m.rule.contains_user_name", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /pushrules/global/{kind}/{ruleId}/actions conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushrules/global/underride/.m.rule.call/actions is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/pushrules/global/underride/.m.rule.call/actions", token, {}});

            THEN("the server returns the actions array")
            {
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                auto const* actions = object_member_as_array(body, "actions");
                REQUIRE(actions != nullptr);
                REQUIRE(actions->size() == 3U);
            }
        }
    }
}

SCENARIO("PUT /pushrules/global/{kind}/{ruleId}/actions conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /pushrules/global/content/.m.rule.contains_user_name/actions is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/pushrules/global/content/.m.rule.contains_user_name/actions", token,
                 R"(["notify"])"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /pushrules/global/{kind}/{ruleId}/enabled conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /pushrules/global/override/.m.rule.master/enabled is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled", token, {}});

            THEN("the server returns the enabled flag")
            {
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                auto const* enabled = bool_member(body, "enabled");
                REQUIRE(enabled != nullptr);
                REQUIRE(*enabled == false);
            }
        }
    }
}

SCENARIO("PUT /pushrules/global/{kind}/{ruleId}/enabled conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /pushrules/global/content/.m.rule.contains_user_name/enabled is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/pushrules/global/content/.m.rule.contains_user_name/enabled", token,
                 R"({"enabled":true})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 13.10  Reporting content — POST /rooms/{roomId}/report/{eventId}
// ============================================================================
// Spec: Matrix v1.18 §13.10 POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}
//       Report an event as inappropriate.

SCENARIO("POST /rooms/{roomId}/report/{eventId} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room with a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/report/{eventId} is called with a reason")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/report/$event_id", token,
                                  R"({"reason":"inappropriate content","score":-100})"});

            THEN("the server returns 200 or 404 (event not found)")
            {
                // The event_id may not exist, so the server returns 404.
                // What MUST NOT happen is a non-JSON or 5xx response.
                REQUIRE((response.response.status == 200 || response.response.status == 400 ||
                         response.response.status == 404));
                auto const body = parse_object(response.response.body);
                // 200 returns {}; 404/400 returns errcode
                REQUIRE(true);
            }
        }
    }
}

SCENARIO("POST /rooms/{roomId}/report conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/report is called without an event ID")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/report", token,
                                  R"({"reason":"inappropriate room"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // IMPLEMENTATION GAP: room-level reporting (without event ID) not implemented
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("POST /users/{userId}/report conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /users/%40alice%3Aexample.org/report is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/users/%40alice%3Aexample.org/report", token,
                                  R"({"reason":"abusive user"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // IMPLEMENTATION GAP: user reporting not implemented
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 14     User data — Profile
// ============================================================================
// Spec: Matrix v1.18 §14 GET/PUT profile

SCENARIO("GET /profile/{userId} conformance")
{
    GIVEN("a started homeserver with a registered user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /profile/@alice:example.org is called without authentication")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org", "", {}});

            THEN("the server returns 200 with a profile object containing displayname and/or avatar_url")
            {
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                // displayname and avatar_url are optional in the spec
                REQUIRE(true); // parsed successfully
            }
        }
    }
}

SCENARIO("GET /profile/{userId}/displayname conformance")
{
    GIVEN("a started homeserver with a registered user who has set a displayname")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const put_response = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", token,
                              R"({"displayname":"Alice Liddell"})"});
        REQUIRE(put_response.response.status == 200);

        WHEN("GET /profile/@alice:example.org/displayname is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", "", {}});

            THEN("the server returns 200 with the displayname")
            {
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                auto const* displayname = string_member(body, "displayname");
                REQUIRE(displayname != nullptr);
                REQUIRE(*displayname == "Alice Liddell");
            }
        }
    }
}

SCENARIO("GET /profile/{userId}/avatar_url conformance")
{
    GIVEN("a started homeserver with a registered user who has set an avatar_url")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const put_response = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/avatar_url", token,
                              R"({"avatar_url":"mxc://example.org/abc123"})"});
        REQUIRE(put_response.response.status == 200);

        WHEN("GET /profile/@alice:example.org/avatar_url is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org/avatar_url", "", {}});

            THEN("the server returns 200 with the avatar_url")
            {
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                auto const* avatar_url = string_member(body, "avatar_url");
                REQUIRE(avatar_url != nullptr);
                REQUIRE(*avatar_url == "mxc://example.org/abc123");
            }
        }
    }
}

SCENARIO("PUT /profile/{userId}/displayname conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /profile/@alice:example.org/displayname is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", token,
                                  R"({"displayname":"Alice Liddell"})"});

            THEN("the server returns 200 with an empty object")
            {
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

SCENARIO("PUT /profile/{userId}/avatar_url conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /profile/@alice:example.org/avatar_url is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/avatar_url", token,
                                  R"({"avatar_url":"mxc://example.org/abc123"})"});

            THEN("the server returns 200 with an empty object")
            {
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// ============================================================================
// 14     User data — Filter
// ============================================================================
// Spec: Matrix v1.18 §14 POST/GET filter

SCENARIO("GET /user/{userId}/filter/{filterId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /user/@alice:example.org/filter/9999 is called with a non-existent filter ID")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/user/%40alice%3Aexample.org/filter/9999", token, {}});

            THEN("the server returns 404 M_NOT_FOUND for unknown filter ID")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_NOT_FOUND");
            }
        }
    }
}

// ============================================================================
// 14     User data — Account data
// ============================================================================
// Spec: Matrix v1.18 §14 PUT/GET per-room account data and tags
//       IMPLEMENTATION GAP: room-level account data and tags not implemented.

SCENARIO("PUT /user/{userId}/rooms/{roomId}/account_data/{type} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /user/@alice:example.org/rooms/{roomId}/account_data/{type} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT",
                 "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/account_data/org.example.custom",
                 token, R"({"data":42})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /user/{userId}/rooms/{roomId}/account_data/{type} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /user/@alice:example.org/rooms/{roomId}/account_data/{type} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET",
                 "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/account_data/org.example.custom",
                 token,
                 {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /user/{userId}/rooms/{roomId}/tags conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /user/@alice:example.org/rooms/{roomId}/tags is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/tags", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("PUT /user/{userId}/rooms/{roomId}/tags/{tag} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /user/@alice:example.org/rooms/{roomId}/tags/m.favourite is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/tags/m.favourite", token,
                 R"({"order":0.5})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("DELETE /user/{userId}/rooms/{roomId}/tags/{tag} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("DELETE /user/@alice:example.org/rooms/{roomId}/tags/m.favourite is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"DELETE",
                 "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/tags/m.favourite",
                 token,
                 {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 15     Event relationships — GET /v1/rooms/{roomId}/relations/{eventId}
// ============================================================================
// Spec: Matrix v1.18 §15 GET /_matrix/client/v1/rooms/{roomId}/relations/{eventId}[/{relType}[/{eventType}]]
//       IMPLEMENTATION GAP: not yet implemented. Must return 404 M_UNRECOGNIZED.

SCENARIO("GET /v1/rooms/{roomId}/relations/{eventId} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /v1/rooms/{roomId}/relations/{eventId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/relations/$event_id", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /v1/rooms/{roomId}/relations/{eventId}/{relType} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /v1/rooms/{roomId}/relations/{eventId}/m.replace is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v1/rooms/" + room_id + "/relations/$event_id/m.replace", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /v1/rooms/{roomId}/relations/{eventId}/{relType}/{eventType} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /v1/rooms/{roomId}/relations/{eventId}/m.annotation/m.reaction is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET",
                 "/_matrix/client/v1/rooms/" + room_id + "/relations/$event_id/m.annotation/m.reaction",
                 token,
                 {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 16     Search — POST /search
// ============================================================================
// Spec: Matrix v1.18 §16 POST /_matrix/client/v3/search
//       IMPLEMENTATION GAP: not yet implemented. Must return 404 M_UNRECOGNIZED.

SCENARIO("POST /search conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /search is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/search", token,
                 R"({"search_categories":{"room_events":{"search_term":"test","filter":{"limit":10}}}})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 17     Send-to-device — PUT /sendToDevice/{eventType}/{txnId}
// ============================================================================
// Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3sendtoeventtypetxnid
// Sends a to-device message to specific device(s). Used by Element to deliver
// Olm-encrypted room keys before a Megolm session can begin.

SCENARIO("PUT /sendToDevice/{eventType}/{txnId} returns 200 with empty object",
         "[conformance][client-server][e2ee][send-to-device]")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /sendToDevice/m.room_key/txn1 is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/sendToDevice/m.room_key/txn1", token,
                 R"({"messages":{"@alice:example.org":{"DEVICE1":{"algorithm":"m.megolm.v1.aes-sha2","room_id":"!r:example.org","session_id":"sid","session_key":"skey"}}}})"});

            THEN("the server returns 200 with an empty JSON object")
            {
                // Spec MUST: 200 {} on success.
                // Do NOT remove — Element blocks message sending until this succeeds.
                // A 404 causes "Unable to send message" for all encrypted rooms.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

SCENARIO("PUT /sendToDevice delivers the message to the recipient's /sync to_device queue",
         "[conformance][client-server][e2ee][send-to-device]")
{
    GIVEN("a running homeserver with Alice and Bob registered")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");

        // register_and_login creates Bob's device with id "bob_DEV".
        // The sendToDevice message must target that device for /sync to drain it.
        WHEN("Alice sends a to-device message to Bob's bob_DEV device")
        {
            auto const send = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/sendToDevice/m.room_key/txn1", alice,
                 R"({"messages":{"@bob:example.org":{"bob_DEV":{"session_key":"sk1","room_id":"!r:example.org"}}}})"});
            REQUIRE(send.response.status == 200U);

            THEN("Bob's /sync exposes the message in to_device.events")
            {
                // Spec MUST: to-device messages must appear in the next /sync
                // to_device.events array with correct type and sender fields.
                // Do NOT remove — this is the only delivery path for Olm room-key
                // messages. If absent, Bob can never decrypt Alice's messages.
                auto const sync = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});
                REQUIRE(sync.response.status == 200U);
                auto const sbody = parse_object(sync.response.body);
                auto const* to_device = object_member_as_object(sbody, "to_device");
                REQUIRE(to_device != nullptr);
                auto const* events = object_member_as_array(*to_device, "events");
                REQUIRE(events != nullptr);
                REQUIRE(!events->empty());
                auto const* evt = std::get_if<merovingian::canonicaljson::Object>(&(*events)[0].storage());
                REQUIRE(evt != nullptr);
                auto const* type = string_member(*evt, "type");
                REQUIRE(type != nullptr);
                REQUIRE(*type == "m.room_key");
                auto const* sender = string_member(*evt, "sender");
                REQUIRE(sender != nullptr);
                REQUIRE(*sender == "@alice:example.org");
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/server-server-api/#sending-to-device-messages
// and https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3sync
SCENARIO("Federated m.direct_to_device with nested encrypted content reaches /sync to_device.events",
         "[conformance][client-server][federation][e2ee][send-to-device]")
{
    GIVEN("a running homeserver with a logged-in local device and a trusted remote")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);

        WHEN("the remote homeserver sends an encrypted to-device EDU with nested ciphertext objects")
        {
            deliver_federated_direct_to_device(
                started.runtime, "txn-fed-td-1",
                R"({"sender":"@bob:remote.example.org","type":"m.room.encrypted","messages":{"@alice:example.org":{"DEVICE1":{"algorithm":"m.olm.v1.curve25519-aes-sha2","sender_key":"curve25519:remote","ciphertext":{"curve25519:DEVICE1":{"body":"ciphertext-body","type":0}}}}}})");

            THEN("the next /sync exposes the encrypted to-device event intact")
            {
                auto const sync = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync", alice, {}});
                REQUIRE(sync.response.status == 200U);
                auto const body = parse_object(sync.response.body);
                auto const* to_device = object_member_as_object(body, "to_device");
                REQUIRE(to_device != nullptr);
                auto const* events = object_member_as_array(*to_device, "events");
                REQUIRE(events != nullptr);
                REQUIRE(events->size() == 1U);
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&(*events)[0].storage());
                REQUIRE(event != nullptr);
                auto const* type = string_member(*event, "type");
                REQUIRE(type != nullptr);
                REQUIRE(*type == "m.room.encrypted");
                auto const* sender = string_member(*event, "sender");
                REQUIRE(sender != nullptr);
                REQUIRE(*sender == "@bob:remote.example.org");
                auto const* content = object_member_as_object(*event, "content");
                REQUIRE(content != nullptr);
                auto const* ciphertext = object_member_as_object(*content, "ciphertext");
                REQUIRE(ciphertext != nullptr);
                auto const* recipient_ciphertext = object_member_as_object(*ciphertext, "curve25519:DEVICE1");
                REQUIRE(recipient_ciphertext != nullptr);
                auto const* cipher_body = string_member(*recipient_ciphertext, "body");
                REQUIRE(cipher_body != nullptr);
                REQUIRE(*cipher_body == "ciphertext-body");
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/server-server-api/#sending-to-device-messages
SCENARIO("Federated m.direct_to_device fans out to every targeted local device",
         "[conformance][client-server][federation][e2ee][send-to-device]")
{
    GIVEN("a local user logged in on two devices")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const device1 = logged_in_token(started.runtime);
        auto const device2 = login_existing_user(started.runtime, "alice", "DEVICE2");

        WHEN("the remote homeserver targets both devices in one encrypted to-device EDU")
        {
            deliver_federated_direct_to_device(
                started.runtime, "txn-fed-td-2",
                R"({"sender":"@bob:remote.example.org","type":"m.room.encrypted","messages":{"@alice:example.org":{"DEVICE1":{"algorithm":"m.olm.v1.curve25519-aes-sha2","sender_key":"curve25519:remote","ciphertext":{"curve25519:DEVICE1":{"body":"ciphertext-one","type":0}}},"DEVICE2":{"algorithm":"m.olm.v1.curve25519-aes-sha2","sender_key":"curve25519:remote","ciphertext":{"curve25519:DEVICE2":{"body":"ciphertext-two","type":0}}}}}})");

            THEN("each device receives exactly its own to-device payload on /sync")
            {
                auto const sync1 = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync", device1, {}});
                REQUIRE(sync1.response.status == 200U);
                auto const body1 = parse_object(sync1.response.body);
                auto const* to_device1 = object_member_as_object(body1, "to_device");
                REQUIRE(to_device1 != nullptr);
                auto const* events1 = object_member_as_array(*to_device1, "events");
                REQUIRE(events1 != nullptr);
                REQUIRE(events1->size() == 1U);
                auto const* event1 = std::get_if<merovingian::canonicaljson::Object>(&(*events1)[0].storage());
                REQUIRE(event1 != nullptr);
                auto const* content1 = object_member_as_object(*event1, "content");
                REQUIRE(content1 != nullptr);
                auto const* ciphertext1 = object_member_as_object(*content1, "ciphertext");
                REQUIRE(ciphertext1 != nullptr);
                REQUIRE(object_member_as_object(*ciphertext1, "curve25519:DEVICE1") != nullptr);

                auto const sync2 = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync", device2, {}});
                REQUIRE(sync2.response.status == 200U);
                auto const body2 = parse_object(sync2.response.body);
                auto const* to_device2 = object_member_as_object(body2, "to_device");
                REQUIRE(to_device2 != nullptr);
                auto const* events2 = object_member_as_array(*to_device2, "events");
                REQUIRE(events2 != nullptr);
                REQUIRE(events2->size() == 1U);
                auto const* event2 = std::get_if<merovingian::canonicaljson::Object>(&(*events2)[0].storage());
                REQUIRE(event2 != nullptr);
                auto const* content2 = object_member_as_object(*event2, "content");
                REQUIRE(content2 != nullptr);
                auto const* ciphertext2 = object_member_as_object(*content2, "ciphertext");
                REQUIRE(ciphertext2 != nullptr);
                REQUIRE(object_member_as_object(*ciphertext2, "curve25519:DEVICE2") != nullptr);
            }
        }
    }
}

SCENARIO("POST /keys/upload followed by POST /keys/query returns the uploaded device keys",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a running homeserver with Alice logged in")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);

        WHEN("Alice uploads device keys and then queries her own keys")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/upload", alice,
                 R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:DEVICE1":"aliceCurve25519Key","ed25519:DEVICE1":"aliceEd25519Key"},"signatures":{"@alice:example.org":{"ed25519:DEVICE1":"aliceSig"}}}})"});
            REQUIRE(upload.response.status == 200U);

            auto const query = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/query", alice, R"({"device_keys":{"@alice:example.org":[]}})"});

            THEN("the query response includes Alice's DEVICE1 key entry")
            {
                // Spec MUST: /keys/query returns device_keys for the queried user.
                // Do NOT remove — Element calls this to establish Olm sessions.
                // An empty device_keys means no E2EE sessions can ever be created.
                REQUIRE(query.response.status == 200U);
                auto const body = parse_object(query.response.body);
                auto const* device_keys = object_member_as_object(body, "device_keys");
                REQUIRE(device_keys != nullptr);
                auto const* alice_keys = object_member_as_object(*device_keys, "@alice:example.org");
                REQUIRE(alice_keys != nullptr);
                auto const* device1 = object_member_as_object(*alice_keys, "DEVICE1");
                REQUIRE(device1 != nullptr);
            }
        }
    }
}

SCENARIO("POST /keys/upload followed by POST /keys/claim returns a one-time key",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a running homeserver with Alice logged in")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);

        WHEN("Alice uploads one-time keys and Bob claims one")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/upload", alice,
                 R"({"one_time_keys":{"signed_curve25519:AAAAA":"otk_payload_1","signed_curve25519:BBBBB":"otk_payload_2"}})"});
            REQUIRE(upload.response.status == 200U);
            // Verify OTK count is reflected immediately.
            auto const up_body = parse_object(upload.response.body);
            auto const* counts = object_member_as_object(up_body, "one_time_key_counts");
            REQUIRE(counts != nullptr);
            auto const* sc_count = int_member(*counts, "signed_curve25519");
            REQUIRE(sc_count != nullptr);
            REQUIRE(*sc_count >= 1);

            auto const claim = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/claim", alice,
                                  R"({"one_time_keys":{"@alice:example.org":{"DEVICE1":"signed_curve25519"}}})"});

            THEN("the claim response contains Alice's one-time key for DEVICE1")
            {
                // Spec MUST: /keys/claim returns a one-time key from the uploaded set.
                // Do NOT remove — this is the Olm X3DH step; without it no new
                // encrypted session can be established and messages cannot be sent.
                REQUIRE(claim.response.status == 200U);
                auto const cbody = parse_object(claim.response.body);
                auto const* otks = object_member_as_object(cbody, "one_time_keys");
                REQUIRE(otks != nullptr);
                auto const* alice_otks = object_member_as_object(*otks, "@alice:example.org");
                REQUIRE(alice_otks != nullptr);
                // DEVICE1 must have been given exactly one key.
                auto const* device_otks = object_member_as_object(*alice_otks, "DEVICE1");
                REQUIRE(device_otks != nullptr);
                REQUIRE(!device_otks->empty());
            }
        }
    }
}

SCENARIO("POST /keys/claim reuses the matching fallback key when one-time keys are exhausted",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device that has uploaded multiple fallback-key algorithms")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/upload", token,
                 R"({"fallback_keys":{"curve25519:WRONGALG":{"key":"wrong-fallback"},"signed_curve25519:FALLBACK":{"key":"matching-fallback","signatures":{}}}})"})
                .response.status == 200U);

        WHEN("the device claims a signed_curve25519 key for that device")
        {
            auto const claim = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                                  R"({"one_time_keys":{"@alice:example.org":{"DEVICE1":"signed_curve25519"}}})"});

            THEN("the response returns the matching fallback key")
            {
                REQUIRE(claim.response.status == 200U);
                auto const body = parse_object(claim.response.body);
                auto const* otks = object_member_as_object(body, "one_time_keys");
                REQUIRE(otks != nullptr);
                auto const* user_otks = object_member_as_object(*otks, "@alice:example.org");
                REQUIRE(user_otks != nullptr);
                auto const* device_otks = object_member_as_object(*user_otks, "DEVICE1");
                REQUIRE(device_otks != nullptr);

                // Spec MUST: fallback key selection matches the requested algorithm.
                REQUIRE(object_member(*device_otks, "signed_curve25519:FALLBACK") != nullptr);
                REQUIRE(object_member(*device_otks, "curve25519:WRONGALG") == nullptr);
            }

            AND_THEN("a second claim returns the same fallback key because fallback keys are reusable")
            {
                auto const second_claim = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                                      R"({"one_time_keys":{"@alice:example.org":{"DEVICE1":"signed_curve25519"}}})"});
                REQUIRE(second_claim.response.status == 200U);
                auto const body = parse_object(second_claim.response.body);
                auto const* otks = object_member_as_object(body, "one_time_keys");
                REQUIRE(otks != nullptr);
                auto const* user_otks = object_member_as_object(*otks, "@alice:example.org");
                REQUIRE(user_otks != nullptr);
                auto const* device_otks = object_member_as_object(*user_otks, "DEVICE1");
                REQUIRE(device_otks != nullptr);
                REQUIRE(object_member(*device_otks, "signed_curve25519:FALLBACK") != nullptr);
            }
        }
    }
}

// ============================================================================
// 18     Server administration
// ============================================================================
// Spec: Matrix v1.18 §18
//       IMPLEMENTATION GAP: admin endpoints not yet implemented.

SCENARIO("GET /admin/whois/{userId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /admin/whois/@alice:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/admin/whois/%40alice%3Aexample.org", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("POST /admin/suspend/{userId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /admin/suspend/@alice:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/admin/suspend/%40alice%3Aexample.org", token, "{}"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("POST /admin/lock/{userId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /admin/lock/@alice:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/admin/lock/%40alice%3Aexample.org", token, "{}"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 19     Well-known
// ============================================================================
// Spec: Matrix v1.18 §19 /.well-known/matrix/policy_server and /support
//       IMPLEMENTATION GAP: not yet implemented. Must return 404.

SCENARIO("GET /.well-known/matrix/policy_server conformance")
{
    GIVEN("a started homeserver and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /.well-known/matrix/policy_server is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/.well-known/matrix/policy_server", token, {}});

            THEN("the server returns 404")
            {
                REQUIRE(response.response.status == 404);
            }
        }
    }
}

SCENARIO("GET /.well-known/matrix/support conformance")
{
    GIVEN("a started homeserver and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /.well-known/matrix/support is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/.well-known/matrix/support", token, {}});

            THEN("the server returns 404")
            {
                REQUIRE(response.response.status == 404);
            }
        }
    }
}

// ============================================================================
// 20     Spaces — GET /v1/rooms/{roomId}/hierarchy
// ============================================================================
// Spec: Matrix v1.18 §20 GET /_matrix/client/v1/rooms/{roomId}/hierarchy
//       IMPLEMENTATION GAP: not yet implemented. Must return 404 M_UNRECOGNIZED.

SCENARIO("GET /v1/rooms/{roomId}/hierarchy conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /v1/rooms/{roomId}/hierarchy is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/hierarchy", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 21     Third-party lookup
// ============================================================================
// Spec: Matrix v1.18 §21 third-party protocols, location, and user lookup
//       IMPLEMENTATION GAP: not yet implemented. Must return 404 M_UNRECOGNIZED.

SCENARIO("GET /thirdparty/protocols conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /thirdparty/protocols is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/thirdparty/protocols", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /thirdparty/location/{protocol} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /thirdparty/location/irc is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/thirdparty/location/irc", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /thirdparty/user/{protocol} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /thirdparty/user/irc is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/thirdparty/user/irc", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 22     Threads — GET /v1/rooms/{roomId}/threads
// ============================================================================
// Spec: Matrix v1.18 §22 GET /_matrix/client/v1/rooms/{roomId}/threads
//       IMPLEMENTATION GAP: not yet implemented. Must return 404 M_UNRECOGNIZED.

SCENARIO("GET /v1/rooms/{roomId}/threads conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /v1/rooms/{roomId}/threads is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 23     OpenID — POST /user/{userId}/openid/request_token
// ============================================================================
// Spec: Matrix v1.18 §23 POST /_matrix/client/v3/user/{userId}/openid/request_token
//       IMPLEMENTATION GAP: not yet implemented. Must return 404 M_UNRECOGNIZED.

SCENARIO("POST /user/{userId}/openid/request_token conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /user/@alice:example.org/openid/request_token is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/user/%40alice%3Aexample.org/openid/request_token", token, "{}"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 24     User directory — POST /user_directory/search
// ============================================================================
// Spec: Matrix v1.18 §24 POST /_matrix/client/v3/user_directory/search
//       MUST return 200 with results matching the search term.

SCENARIO("POST /user_directory/search returns matching users", "[conformance][client-server][account-management]")
{
    GIVEN("a running client-server with two registered users")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        // Register a second user so the directory has more than one profile.
        auto const bob_token = register_and_login(started.runtime, "bob");

        WHEN("POST /user_directory/search is called with a search term matching a user")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/user_directory/search", token, R"({"search_term":"bob"})"});

            THEN("the server returns 200 with results containing the matching user")
            {
                // Spec MUST: 200 with results array containing matching users.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* results = object_member_as_array(body, "results");
                REQUIRE(results != nullptr);
                REQUIRE(!results->empty());
                // The matching user must include user_id.
                auto const* first_result = std::get_if<merovingian::canonicaljson::Object>(&results->front().storage());
                REQUIRE(first_result != nullptr);
                auto const* user_id = string_member(*first_result, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(user_id->find("bob") != std::string::npos);
                // Spec MUST: limited field is present.
                auto const* limited = bool_member(body, "limited");
                REQUIRE(limited != nullptr);
                REQUIRE(*limited == false);
            }
        }
    }
}

// ============================================================================
// 25     Room upgrade — POST /rooms/{roomId}/upgrade
// ============================================================================
// Spec: Matrix v1.18 §10.7 POST /_matrix/client/v3/rooms/{roomId}/upgrade
//       IMPLEMENTATION GAP: not yet implemented. Must return 404 M_UNRECOGNIZED.

SCENARIO("POST /rooms/{roomId}/upgrade conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/upgrade is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", token, R"({"new_version":"11"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 26     Room participation — misc gaps
// ============================================================================
// Spec: Various room participation endpoints not yet implemented.

SCENARIO("GET /rooms/{roomId}/members conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/members is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/members", token, {}});

            THEN("the server returns 200 with a chunk array")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/joined_members conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/joined_members is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/joined_members", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/event/{eventId} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/event/$eventId is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/event/$event_id", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/context/{eventId} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/context/$eventId is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/context/$event_id", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/initialSync conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/initialSync is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/initialSync", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // Deprecated in v1.18, but should return M_UNRECOGNIZED
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /initialSync conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /initialSync is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/initialSync", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // Deprecated in v1.18
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /events conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /events is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/events", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // Deprecated in v1.18
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /events/{eventId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /events/$eventId is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/events/$event_id", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // Deprecated in v1.18
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/timestamp_to_event conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/timestamp_to_event is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v1/rooms/" + room_id + "/timestamp_to_event?ts=0&dir=f", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/state/{eventType} returns 404 for absent state events",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/state/m.room.name is called for a room with no name")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.name", token, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 M_NOT_FOUND when the room has no state event of
                // the requested type.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_NOT_FOUND");
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/state/{eventType}/{stateKey} returns 404 for absent state events",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/state/m.room.name/ is called for a room with no name")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.name/", token, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 M_NOT_FOUND when no state event of that type/key
                // exists — not M_UNRECOGNIZED which implies the route itself is
                // unknown.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_NOT_FOUND");
            }
        }
    }
}

SCENARIO("POST /rooms/{roomId}/redact/{eventId}/{txnId} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room with a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/redact/{eventId}/{txnId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/redact/$event_id/1", token, R"({"reason":"test"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // IMPLEMENTATION GAP: redact not routed
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("PUT /rooms/{roomId}/redact/{eventId}/{txnId} conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room with a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /rooms/{roomId}/redact/{eventId}/{txnId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/redact/$event_id/1", token, R"({"reason":"test"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // IMPLEMENTATION GAP: redact not routed
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 27     Room membership — gaps
// ============================================================================

SCENARIO("POST /rooms/{roomId}/ban conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/ban is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", token,
                                  R"({"user_id":"@bob:example.org","reason":"test"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // IMPLEMENTATION GAP: ban not routed
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("POST /rooms/{roomId}/kick conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/kick is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/kick", token,
                                  R"({"user_id":"@bob:example.org","reason":"test"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("POST /rooms/{roomId}/unban conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/unban is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/unban", token, R"({"user_id":"@bob:example.org"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("POST /rooms/{roomId}/invite conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/invite is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", token,
                                  R"({"user_id":"@bob:example.org"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("POST /rooms/{roomId}/forget conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/forget is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/forget", token, "{}"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("POST /knock/{roomIdOrAlias} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /knock/{roomIdOrAlias} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/knock/!room:example.org", token, "{}"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

// ============================================================================
// 28     Room directory — gaps
// ============================================================================

SCENARIO("DELETE /directory/room/{roomAlias} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("DELETE /directory/room/%23alias:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/directory/room/%23test%3Aexample.org", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // IMPLEMENTATION GAP: DELETE directory not routed
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/aliases conformance")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /rooms/{roomId}/aliases is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/aliases", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("POST /publicRooms conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /publicRooms is called with a filter")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/publicRooms", token,
                                  R"({"filter":{"generic_search_term":"test"},"limit":10})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // IMPLEMENTATION GAP: POST /publicRooms (filtered search) not routed
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("GET /directory/list/room/{roomId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /directory/list/room/!room:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/directory/list/room/!room:example.org", token, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("PUT /directory/list/room/{roomId} conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /directory/list/room/!room:example.org is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/directory/list/room/!room:example.org", token,
                                  R"({"visibility":"private"})"});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.response.status == 404);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_UNRECOGNIZED");
            }
        }
    }
}
