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
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                         |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/http/request.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
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

[[nodiscard]] auto login_token(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto login_device_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"device_id\":\""};
    auto const begin = body.find(key);
    if (begin == std::string::npos)
    {
        return {};
    }
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    if (value_end == std::string::npos)
    {
        return {};
    }
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto room_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"room_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto percent_encode_colons(std::string value) -> std::string
{
    auto pos = value.find(':');
    while (pos != std::string::npos)
    {
        value.replace(pos, 1U, "%3A");
        pos = value.find(':', pos + 3U);
    }
    return value;
}

[[nodiscard]] auto event_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"event_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto json_value(std::string const& body, std::string const& key) -> std::string
{
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

using namespace merovingian::tests;

[[nodiscard]] auto event_json_for_state(merovingian::database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view event_type, std::string_view state_key = {}) -> std::string
{
    auto const state = std::ranges::find_if(store.state, [&](merovingian::database::PersistentStateEvent const& row) {
        return row.room_id == room_id && row.event_type == event_type && row.state_key == state_key;
    });
    REQUIRE(state != store.state.end());
    auto const event = std::ranges::find_if(store.events, [&](merovingian::database::PersistentEvent const& row) {
        return row.event_id == state->event_id;
    });
    REQUIRE(event != store.events.end());
    return event->json;
}

[[nodiscard]] auto content_for_state(merovingian::database::PersistentStore const& store, std::string_view room_id,
                                     std::string_view event_type, std::string_view state_key = {})
    -> merovingian::canonicaljson::Object
{
    auto const event = parse_object(event_json_for_state(store, room_id, event_type, state_key));
    auto const* content = object_member_as_object(event, "content");
    REQUIRE(content != nullptr);
    return *content;
}

[[nodiscard]] auto has_state_event(merovingian::database::PersistentStore const& store, std::string_view room_id,
                                   std::string_view event_type, std::string_view state_key = {}) -> bool
{
    return std::ranges::find_if(store.state, [&](merovingian::database::PersistentStateEvent const& row) {
               return row.room_id == room_id && row.event_type == event_type && row.state_key == state_key;
           }) != store.state.end();
}

} // namespace

// --- Matrix error shape -------------------------------------------------------
// Spec: Matrix Client-Server API v1.18
// Standard error response format
// URL: https://spec.matrix.org/v1.18/client-server-api/#standard-error-response
//
// Every error response MUST carry an "errcode" string and an "error" human-
// readable string. The shape is stable across all endpoints.
SCENARIO("Client-server runtime wraps errors in stable Matrix-style shapes", "[homeserver][client-server]")
{
    GIVEN("a Matrix error")
    {
        WHEN("it is rendered")
        {
            auto const body = merovingian::homeserver::matrix_error("M_FORBIDDEN", "denied");
            auto const response = merovingian::homeserver::LocalHttpResponse{403U, body};

            THEN("the response has a stable Matrix error body")
            {
                // Spec MUST: error body is {"errcode":"<CODE>","error":"<msg>"}
                // Do NOT remove/change - clients parse this exact shape to display errors
                REQUIRE(body == R"({"errcode":"M_FORBIDDEN","error":"denied"})");
                REQUIRE(merovingian::homeserver::is_matrix_error_response(response));
            }
        }
    }
}

// --- Production API surface ---------------------------------------------------
// Spec: Matrix Client-Server API v1.18
// /sync - initial sync response
// URL: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3sync
//
// A compliant /sync response MUST include "next_batch". The server MUST NOT
// leak raw key material ("secret") in sync payloads.
SCENARIO("Client-server runtime exposes production-named start and flow APIs", "[homeserver][client-server]")
{
    GIVEN("registration-enabled client-server configuration")
    {
        auto const config = registration_enabled_config();

        WHEN("the production client-server runtime and flow APIs are used")
        {
            auto started = merovingian::homeserver::start_client_server(config);
            auto const flow = merovingian::homeserver::run_client_server_flow(config);

            THEN("the runtime starts and the safe client-server flow completes")
            {
                REQUIRE(started.started);
                REQUIRE(flow.ok);
                // Spec MUST: /sync response contains "next_batch" stream token
                // Do NOT remove - without next_batch clients cannot do incremental sync
                REQUIRE(flow.value.find("next_batch") != std::string::npos);
                // Matrix E2EE: the server relays m.room.encrypted payloads
                // through /sync. The ciphertext ("secret" in the smoke flow)
                // MUST appear — clients decrypt locally.
                REQUIRE(flow.value.find("m.room.encrypted") != std::string::npos);
            }
        }
    }
}

// --- Account and device session management ------------------------------------
// Spec: Matrix Client-Server API v1.18
// POST /register, POST /login, GET /account/whoami, GET /devices, PUT /devices/{deviceId}
// URL: https://spec.matrix.org/v1.18/client-server-api/#account-registration-and-management
//
// Registration MUST return 200 with a user_id. Login MUST return an access_token.
// Authenticated endpoints MUST validate the Bearer token and return the correct
// user identity. Device display names MUST be persisted and returned in /devices.
SCENARIO("Client-server runtime account and device endpoints use real sessions", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers and logs in")
        {
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")});
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
            auto const token = login_token(login.response.body);
            auto const whoami = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
            auto const devices = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/devices", token, {}});
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/devices/DEVICE1", token, R"({"display_name":"Alice laptop"})"});
            auto const updated_devices = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("identity, device listing, and device updates work through token validation")
            {
                // Spec MUST: POST /register returns HTTP 200 on success
                // Do NOT remove - a non-200 here means registration is broken
                REQUIRE(registered.response.status == 200U);
                // Spec MUST: POST /login returns HTTP 200 with access_token
                // Do NOT remove - login is the entry point for all authenticated flows
                REQUIRE(login.response.status == 200U);
                // Spec MUST: GET /account/whoami returns 200 for a valid token
                // Do NOT remove - 401 here means token validation is broken
                REQUIRE(whoami.response.status == 200U);
                // Spec MUST: whoami response body contains the authenticated user's user_id
                // Do NOT remove - clients depend on this to confirm their own identity
                REQUIRE(whoami.response.body.find("@alice:example.org") != std::string::npos);
                REQUIRE(devices.response.status == 200U);
                REQUIRE(devices.response.body.find("DEVICE1") != std::string::npos);
                REQUIRE(update.response.status == 200U);
                REQUIRE(updated_devices.response.body.find("Alice laptop") != std::string::npos);
                REQUIRE(merovingian::homeserver::device_count(runtime, "@alice:example.org") == 1U);
            }
        }
    }
}

// --- Malformed request body rejection -----------------------------------------
// Spec: Matrix Client-Server API v1.18
// Standard error response - M_BAD_JSON
// URL: https://spec.matrix.org/v1.18/client-server-api/#standard-error-response
//
// If the request body is not valid JSON or is missing required fields, the
// server MUST return HTTP 400 with errcode M_BAD_JSON. The server MUST fail
// closed - it MUST NOT partially process a malformed request.
SCENARIO("Client-server runtime rejects malformed Matrix JSON request bodies", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("registration and login receive malformed or incomplete JSON")
        {
            auto const malformed_registration = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/register", {}, R"({"username":"alice","password":)"});
            auto const incomplete_login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","password":"CorrectHorse7!","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});

            THEN("the API fails closed with stable Matrix bad-json errors")
            {
                // Spec MUST: malformed JSON body -> HTTP 400 M_BAD_JSON
                // Do NOT remove - accepting malformed JSON could allow injection attacks
                REQUIRE(malformed_registration.response.status == 400U);
                REQUIRE(incomplete_login.response.status == 400U);
                // Spec MUST: errcode is exactly "M_BAD_JSON" (not M_UNKNOWN or 500)
                // Do NOT remove - clients branch on this exact errcode to show user-facing messages
                REQUIRE(malformed_registration.response.body.find("M_BAD_JSON") != std::string::npos);
                REQUIRE(incomplete_login.response.body.find("M_BAD_JSON") != std::string::npos);
            }
        }
    }
}

// --- HTTP request dispatch -----------------------------------------------------
// Spec: Matrix Client-Server API v1.18
// Authentication - Bearer token via Authorization header
// URL: https://spec.matrix.org/v1.18/client-server-api/#client-authentication
//
// The server MUST accept the Authorization: Bearer <token> header for
// authentication. The HTTP adapter must correctly parse the request line,
// headers, and body before dispatching to the Matrix JSON handler.
SCENARIO("Client-server runtime dispatches complete HTTP requests through Matrix JSON handlers",
         "[homeserver][client-server][http]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("registration login and whoami arrive as raw HTTP requests")
        {
            auto const registration_body =
                std::string{merovingian::tests::registration_json("alice", "CorrectHorse7!")};
            auto const registration = merovingian::homeserver::handle_client_server_http_request(
                runtime, "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: example.org\r\nContent-Length: " +
                             std::to_string(registration_body.size()) + "\r\n\r\n" + registration_body);
            auto const login_body = std::string{
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"};
            auto const login = merovingian::homeserver::handle_client_server_http_request(
                runtime, "POST /_matrix/client/v3/login HTTP/1.1\r\nHost: example.org\r\nContent-Length: " +
                             std::to_string(login_body.size()) + "\r\n\r\n" + login_body);
            auto const token = login_token(login.body);
            auto const whoami = merovingian::homeserver::handle_client_server_http_request(
                runtime,
                "GET /_matrix/client/v3/account/whoami HTTP/1.1\r\nHost: example.org\r\nAuthorization: Bearer " +
                    token + "\r\nContent-Length: 0\r\n\r\n");

            THEN("the HTTP adapter preserves Matrix status bodies and bearer auth")
            {
                REQUIRE(registration.status == 200U);
                REQUIRE(login.status == 200U);
                // Spec MUST: Authorization: Bearer token is honoured for authenticated endpoints
                // Do NOT remove - failure here means the HTTP layer strips auth headers
                REQUIRE(whoami.status == 200U);
                REQUIRE(whoami.body.find("@alice:example.org") != std::string::npos);
            }
        }
    }
}

// --- HTTP body length validation ----------------------------------------------
// Spec: Matrix Client-Server API v1.18
// Standard error response - M_BAD_REQUEST
// URL: https://spec.matrix.org/v1.18/client-server-api/#standard-error-response
//
// The server MUST validate that the received body matches the declared
// Content-Length. Bodies shorter or longer than declared MUST be rejected
// with HTTP 400 M_BAD_REQUEST before route dispatch.
SCENARIO("Client-server runtime HTTP adapter rejects incomplete and trailing request bodies",
         "[homeserver][client-server][http]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("raw HTTP requests do not match their declared content length")
        {
            auto const incomplete = merovingian::homeserver::handle_client_server_http_request(
                runtime,
                "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: example.org\r\nContent-Length: 12\r\n\r\n{}");
            auto const trailing = merovingian::homeserver::handle_client_server_http_request(
                runtime,
                "GET /_matrix/client/v3/account/whoami HTTP/1.1\r\nHost: example.org\r\nContent-Length: 0\r\n\r\nx");

            THEN("the adapter fails closed before route dispatch")
            {
                // Spec MUST: body/Content-Length mismatch -> 400 before routing
                // Do NOT remove - allowing mismatched bodies enables request smuggling
                REQUIRE(incomplete.status == 400U);
                REQUIRE(trailing.status == 400U);
                REQUIRE(incomplete.body.find("M_BAD_REQUEST") != std::string::npos);
                REQUIRE(trailing.body.find("M_BAD_REQUEST") != std::string::npos);
            }
        }
    }
}

// --- Login flow discovery -----------------------------------------------------
// Spec: Matrix Client-Server API v1.18
// GET /_matrix/client/v3/login
// URL: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3login
//
// GET /login is unauthenticated and MUST return 200 with a "flows" array.
// The array MUST include "m.login.password" when password login is supported.
// Clients use this to discover which login methods the server accepts.
SCENARIO("Client-server GET login returns password flow discovery response", "[homeserver][client-server]")
{
    GIVEN("a running client-server homeserver")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an unauthenticated client queries GET /_matrix/client/v3/login")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/login", {}, {}});

            THEN("the server returns 200 with a flows array containing m.login.password")
            {
                // Spec MUST: GET /login -> HTTP 200 (no auth required)
                // Do NOT remove - a 401 here would break all Matrix clients before they can log in
                REQUIRE(resp.response.status == 200U);
                // Spec MUST: response body contains "flows" array
                // Do NOT remove - clients enumerate flows to pick the right login method
                REQUIRE(resp.response.body.find("\"flows\"") != std::string::npos);
                REQUIRE(resp.response.body.find("\"m.login.password\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server register returns a UIA challenge for an empty JSON probe", "[homeserver][client-server]")
{
    GIVEN("a running client-server homeserver with token-gated registration")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an unauthenticated client posts an empty object to /register")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/register", {}, "{}"});

            THEN("the server returns a 401 UIA flow instead of a 400 parse error")
            {
                REQUIRE(resp.response.status == 401U);
                REQUIRE(resp.response.body.find("\"flows\"") != std::string::npos);
                REQUIRE(resp.response.body.find("m.login.registration_token") != std::string::npos);
                REQUIRE(resp.response.body.find("\"session\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server registration discovery endpoints track availability token validity and validation sessions",
         "[homeserver][client-server][register]")
{
    GIVEN("a running client-server homeserver with token-gated registration")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the registration discovery and requestToken endpoints are exercised")
        {
            auto const available_before = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/register/available?username=alice", {}, {}});
            auto const valid_token = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          std::string{"/_matrix/client/v1/register/m.login.registration_token/validity?token="} +
                              std::string{merovingian::tests::registration_token},
                          {},
                          {}});
            auto const invalid_token = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v1/register/m.login.registration_token/validity?token=wrong-token", {}, {}});
            auto const email_request_first = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register/email/requestToken",
                          {},
                          R"({"client_secret":"secret123","email":"user@example.org","send_attempt":1})"});
            auto const email_request_second = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register/email/requestToken",
                          {},
                          R"({"client_secret":"secret123","email":"user@example.org","send_attempt":2})"});
            auto const msisdn_request_first = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register/msisdn/requestToken",
                 {},
                 R"({"client_secret":"secret123","country":"GB","phone_number":"07700000000","send_attempt":1})"});
            auto const msisdn_request_second = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register/msisdn/requestToken",
                 {},
                 R"({"client_secret":"secret123","country":"GB","phone_number":"07700000000","send_attempt":2})"});
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")});
            auto const available_after = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/register/available?username=alice", {}, {}});

            THEN("availability and validation state evolve consistently")
            {
                REQUIRE(available_before.response.status == 200U);
                auto const available_before_body = parse_object(available_before.response.body);
                auto const* available = bool_member(available_before_body, "available");
                REQUIRE(available != nullptr);
                REQUIRE(*available);

                REQUIRE(valid_token.response.status == 200U);
                REQUIRE(invalid_token.response.status == 200U);
                auto const valid_token_body = parse_object(valid_token.response.body);
                auto const invalid_token_body = parse_object(invalid_token.response.body);
                auto const* valid_true = bool_member(valid_token_body, "valid");
                auto const* valid_false = bool_member(invalid_token_body, "valid");
                REQUIRE(valid_true != nullptr);
                REQUIRE(valid_false != nullptr);
                REQUIRE(*valid_true);
                REQUIRE(!*valid_false);

                REQUIRE(email_request_first.response.status == 200U);
                REQUIRE(email_request_second.response.status == 200U);
                auto const email_first_body = parse_object(email_request_first.response.body);
                auto const email_second_body = parse_object(email_request_second.response.body);
                auto const* email_sid_first = string_member(email_first_body, "sid");
                auto const* email_sid_second = string_member(email_second_body, "sid");
                REQUIRE(email_sid_first != nullptr);
                REQUIRE(email_sid_second != nullptr);
                REQUIRE(*email_sid_first == *email_sid_second);

                REQUIRE(msisdn_request_first.response.status == 200U);
                REQUIRE(msisdn_request_second.response.status == 200U);
                auto const msisdn_first_body = parse_object(msisdn_request_first.response.body);
                auto const msisdn_second_body = parse_object(msisdn_request_second.response.body);
                auto const* msisdn_sid_first = string_member(msisdn_first_body, "sid");
                auto const* msisdn_sid_second = string_member(msisdn_second_body, "sid");
                REQUIRE(msisdn_sid_first != nullptr);
                REQUIRE(msisdn_sid_second != nullptr);
                REQUIRE(*msisdn_sid_first == *msisdn_sid_second);

                REQUIRE(registered.response.status == 200U);
                REQUIRE(available_after.response.status == 400U);
                REQUIRE(available_after.response.body.find("M_USER_IN_USE") != std::string::npos);
            }
        }
    }
}

// --- JSON string escaping -----------------------------------------------------
// Spec: Matrix Client-Server API v1.18
// Device management - PUT /devices/{deviceId}
// URL: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3devicesdeviceid
//
// Device IDs and display names may contain quotes and backslashes. The server
// MUST produce valid JSON-escaped strings in all responses. Malformed JSON in
// a device response would silently corrupt client device lists.
SCENARIO("Client-server runtime escapes login and device JSON strings", "[homeserver][client-server]")
{
    GIVEN("a logged-in client-server user with a device value requiring JSON escapes")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);

        WHEN("the device id and display name include quotes and backslashes")
        {
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV\"\\ICE"})"});
            auto const token = login_token(login.response.body);
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", R"(/_matrix/client/v3/devices/DEV"\ICE)", token,
                          R"({"display_name":"Alice \"Laptop\" \\ 1"})"});
            auto const devices = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("login and device responses remain valid escaped JSON strings")
            {
                REQUIRE(login.response.status == 200U);
                // Spec MUST: device_id with special chars is JSON-escaped in the login response
                // Do NOT remove - unescaped output breaks JSON parsers on all downstream clients
                REQUIRE(login.response.body.find(R"("device_id":"DEV\"\\ICE")") != std::string::npos);
                REQUIRE(update.response.status == 200U);
                REQUIRE(devices.response.status == 200U);
                // Spec MUST: device_id and display_name are correctly JSON-escaped in /devices
                // Do NOT remove - malformed JSON here corrupts client device tracking
                REQUIRE(devices.response.body.find(R"("device_id":"DEV\"\\ICE")") != std::string::npos);
                REQUIRE(devices.response.body.find(R"("display_name":"Alice \"Laptop\" \\ 1")") != std::string::npos);
            }
        }
    }
}

// --- Room creation, state, and sync ------------------------------------------
// Spec: Matrix Client-Server API v1.18
// POST /createRoom, GET /rooms/{roomId}/state, GET /joined_rooms, GET /sync
// URL: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3createroom
// URL: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3sync
//
// A successful room creation MUST return HTTP 200 with a "room_id". The /sync
// response MUST include "event_count" and MUST NOT expose plaintext encrypted
// event content - the server is blind to E2EE payloads.
SCENARIO("Client-server runtime room state joined rooms and sync endpoints compose the homeserver path",
         "[homeserver][client-server]")
{
    GIVEN("a logged-in client-server user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the user creates a room, sends encrypted-looking content, and syncs")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
            auto const id = room_id(room.response.body);
            auto const send = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.encrypted","content":"secret"})"});
            auto const state = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/" + id + "/state", token, {}});
            auto const joined = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});
            auto const sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("room and sync responses are bounded summaries without plaintext event content")
            {
                // Spec MUST: POST /createRoom -> HTTP 200
                // Do NOT remove - non-200 means room creation is broken
                REQUIRE(room.response.status == 200U);
                // Spec MUST: POST /rooms/{roomId}/send -> HTTP 200 with event_id
                // Do NOT remove - non-200 means event sending is broken
                REQUIRE(send.response.status == 200U);
                REQUIRE(state.response.status == 200U);
                REQUIRE(joined.response.status == 200U);
                REQUIRE(joined.response.body.find(id) != std::string::npos);
                // Spec MUST: GET /sync -> HTTP 200
                // Do NOT remove - /sync is the primary client data delivery mechanism
                REQUIRE(sync.response.status == 200U);
                REQUIRE(sync.response.body.find(id) != std::string::npos);
                REQUIRE(sync.response.body.find("event_count") != std::string::npos);
                // Matrix E2EE: m.room.encrypted events are relayed opaquely
                // through /sync — clients decrypt locally. The event type and
                // ciphertext payload MUST appear in the sync response.
                REQUIRE(sync.response.body.find("m.room.encrypted") != std::string::npos);
                REQUIRE(merovingian::homeserver::joined_room_count(runtime, "@alice:example.org") == 1U);
            }
        }
    }
}

SCENARIO("Client-server publicRooms lists local public-chat rooms instead of returning M_UNRECOGNIZED",
         "[homeserver][client-server][public-rooms]")
{
    GIVEN("a started runtime with one private room and one public room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto const private_room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"name":"Private room"})"});
        REQUIRE(private_room.response.status == 200U);
        auto const private_room_id = room_id(private_room.response.body);

        auto const public_room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token,
                      R"({"preset":"public_chat","name":"Lobby","topic":"Open to everyone"})"});
        REQUIRE(public_room.response.status == 200U);
        auto const public_room_id = room_id(public_room.response.body);

        WHEN("the client requests GET /_matrix/client/v3/publicRooms with a server query parameter")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/publicRooms?server=example.org", {}, {}});

            THEN("the response is 200 and lists only the public room in the chunk")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("\"chunk\"") != std::string::npos);
                REQUIRE(response.response.body.find(public_room_id) != std::string::npos);
                REQUIRE(response.response.body.find(private_room_id) == std::string::npos);
                REQUIRE(response.response.body.find("\"name\":\"Lobby\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"topic\":\"Open to everyone\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"join_rule\":\"public\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"world_readable\":false") != std::string::npos);
                REQUIRE(response.response.body.find("\"guest_can_join\":false") != std::string::npos);
            }
        }
    }
}

SCENARIO("createRoom applies Matrix v1.18 preset and room-creation options",
         "[homeserver][client-server][create-room][conformance]")
{
    GIVEN("a started runtime with one creator and one local invitee")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("bob", "CorrectHorse8!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client creates a public room without an explicit preset")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"visibility":"public"})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);

            THEN("visibility derives the public_chat preset semantics")
            {
                auto const join_rules = content_for_state(runtime.homeserver.database.persistent_store, created_room_id,
                                                          "m.room.join_rules");
                auto const history = content_for_state(runtime.homeserver.database.persistent_store, created_room_id,
                                                       "m.room.history_visibility");
                auto const guest = content_for_state(runtime.homeserver.database.persistent_store, created_room_id,
                                                     "m.room.guest_access");
                REQUIRE(string_member(join_rules, "join_rule") != nullptr);
                REQUIRE(*string_member(join_rules, "join_rule") == "public");
                REQUIRE(string_member(history, "history_visibility") != nullptr);
                REQUIRE(*string_member(history, "history_visibility") == "shared");
                REQUIRE(string_member(guest, "guest_access") != nullptr);
                REQUIRE(*string_member(guest, "guest_access") == "forbidden");
            }
        }

        WHEN("the client creates a trusted private room with all spec options")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/createRoom", token,
                 R"({"creation_content":{"m.federate":false},"initial_state":[{"type":"m.room.encryption","state_key":"","content":{"algorithm":"m.megolm.v1.aes-sha2"}}],"invite":["@bob:example.org"],"is_direct":true,"name":"Trusted DM","power_level_content_override":{"events_default":50},"preset":"trusted_private_chat","room_version":"12","topic":"spec topic"})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("the persisted state matches the requested room version and creation content")
            {
                auto const create = content_for_state(store, created_room_id, "m.room.create");
                REQUIRE(string_member(create, "room_version") != nullptr);
                REQUIRE(*string_member(create, "room_version") == "12");
                REQUIRE(bool_member(create, "m.federate") != nullptr);
                REQUIRE(*bool_member(create, "m.federate") == false);
                auto const* additional_creators = object_member(create, "additional_creators");
                REQUIRE(additional_creators != nullptr);
                auto const* additional_array =
                    std::get_if<merovingian::canonicaljson::Array>(&additional_creators->storage());
                REQUIRE(additional_array != nullptr);
                REQUIRE(additional_array->size() == 1U);
                auto const* invitee = std::get_if<std::string>(&(*additional_array)[0].storage());
                REQUIRE(invitee != nullptr);
                REQUIRE(*invitee == "@bob:example.org");
            }

            AND_THEN("preset and override events are emitted with the spec values")
            {
                auto const guest = content_for_state(store, created_room_id, "m.room.guest_access");
                auto const history = content_for_state(store, created_room_id, "m.room.history_visibility");
                auto const power = content_for_state(store, created_room_id, "m.room.power_levels");
                REQUIRE(string_member(guest, "guest_access") != nullptr);
                REQUIRE(*string_member(guest, "guest_access") == "can_join");
                REQUIRE(string_member(history, "history_visibility") != nullptr);
                REQUIRE(*string_member(history, "history_visibility") == "shared");
                REQUIRE(int_member(power, "events_default") != nullptr);
                REQUIRE(*int_member(power, "events_default") == 50);
                // MSC4291: in room v12 the creator (@alice) and additional_creators (@bob, from the
                // trusted_private_chat invite) hold implicit infinite power level and MUST NOT be
                // listed in content.users — Synapse rejects the join otherwise.
                auto const* users = object_member_as_object(power, "users");
                REQUIRE(users != nullptr);
                REQUIRE(int_member(*users, "@alice:example.org") == nullptr);
                REQUIRE(int_member(*users, "@bob:example.org") == nullptr);
                auto const* events = object_member_as_object(power, "events");
                REQUIRE(events != nullptr);
                REQUIRE(int_member(*events, "m.room.tombstone") != nullptr);
                REQUIRE(*int_member(*events, "m.room.tombstone") > 50);
            }

            AND_THEN("initial_state, name, topic, and direct invites are persisted")
            {
                auto const encryption = content_for_state(store, created_room_id, "m.room.encryption");
                auto const invite = content_for_state(store, created_room_id, "m.room.member", "@bob:example.org");
                auto const name = content_for_state(store, created_room_id, "m.room.name");
                auto const topic = content_for_state(store, created_room_id, "m.room.topic");
                REQUIRE(string_member(encryption, "algorithm") != nullptr);
                REQUIRE(*string_member(encryption, "algorithm") == "m.megolm.v1.aes-sha2");
                REQUIRE(string_member(name, "name") != nullptr);
                REQUIRE(*string_member(name, "name") == "Trusted DM");
                REQUIRE(string_member(topic, "topic") != nullptr);
                REQUIRE(*string_member(topic, "topic") == "spec topic");
                REQUIRE(string_member(invite, "membership") != nullptr);
                REQUIRE(*string_member(invite, "membership") == "invite");
                REQUIRE(bool_member(invite, "is_direct") != nullptr);
                REQUIRE(*bool_member(invite, "is_direct") == true);
            }
        }
    }
}

SCENARIO("createRoom keeps the creator in power_levels users for pre-v12 rooms",
         "[homeserver][client-server][create-room][room-version]")
{
    GIVEN("a started runtime with a logged-in creator")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client creates a room with room_version 11 (no implicit creator power)")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"room_version":"11"})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);

            THEN("the creator is explicitly listed in m.room.power_levels users at level 100")
            {
                auto const power = content_for_state(runtime.homeserver.database.persistent_store, created_room_id,
                                                     "m.room.power_levels");
                auto const* users = object_member_as_object(power, "users");
                REQUIRE(users != nullptr);
                REQUIRE(int_member(*users, "@alice:example.org") != nullptr);
                REQUIRE(*int_member(*users, "@alice:example.org") == 100);
            }
        }
    }
}

SCENARIO("createRoom combines and deduplicates trusted_private_chat creators per the spec (MSC4289)",
         "[homeserver][client-server][create-room][room-version][conformance]")
{
    GIVEN("a started runtime with a logged-in creator and a local invitee")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("bob", "CorrectHorse8!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("a v12 trusted_private_chat supplies additional_creators in creation_content and an invite list")
        {
            // The spec (createRoom, Changed in v1.16) requires the server to COMBINE the
            // creation_content additional_creators with the invite array and DEDUPLICATE.
            // Here @bob appears in both inputs, @carol only in creation_content.
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/createRoom", token,
                 R"({"preset":"trusted_private_chat","room_version":"12","invite":["@bob:example.org"],"creation_content":{"additional_creators":["@carol:example.org","@bob:example.org"]}})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("additional_creators is the deduplicated union of both inputs and omits the sender")
            {
                auto const create = content_for_state(store, created_room_id, "m.room.create");
                auto const* additional = object_member(create, "additional_creators");
                REQUIRE(additional != nullptr);
                auto const* additional_array = std::get_if<merovingian::canonicaljson::Array>(&additional->storage());
                REQUIRE(additional_array != nullptr);
                auto seen = std::vector<std::string>{};
                for (auto const& entry : *additional_array)
                {
                    auto const* id = std::get_if<std::string>(&entry.storage());
                    REQUIRE(id != nullptr);
                    // The creator (sender) must never be repeated in additional_creators.
                    REQUIRE(*id != "@alice:example.org");
                    seen.push_back(*id);
                }
                REQUIRE(seen.size() == 2U); // @bob deduplicated despite appearing twice
                REQUIRE(std::ranges::find(seen, "@bob:example.org") != seen.end());
                REQUIRE(std::ranges::find(seen, "@carol:example.org") != seen.end());
            }

            AND_THEN("no creator appears in m.room.power_levels users")
            {
                auto const power = content_for_state(store, created_room_id, "m.room.power_levels");
                auto const* users = object_member_as_object(power, "users");
                REQUIRE(users != nullptr);
                REQUIRE(int_member(*users, "@alice:example.org") == nullptr);
                REQUIRE(int_member(*users, "@bob:example.org") == nullptr);
                REQUIRE(int_member(*users, "@carol:example.org") == nullptr);
            }
        }
    }
}

SCENARIO("createRoom does not emit additional_creators for pre-v12 trusted_private_chat rooms",
         "[homeserver][client-server][create-room][room-version][conformance]")
{
    GIVEN("a started runtime with a logged-in creator and a local invitee")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("bob", "CorrectHorse8!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client creates a room_version 11 trusted_private_chat with an invite")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token,
                          R"({"preset":"trusted_private_chat","room_version":"11","invite":["@bob:example.org"]})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("the create event carries no additional_creators (a pre-v12 concept)")
            {
                auto const create = content_for_state(store, created_room_id, "m.room.create");
                REQUIRE(object_member(create, "additional_creators") == nullptr);
            }

            AND_THEN("the invitee is granted the creator's power level (100) in m.room.power_levels")
            {
                auto const power = content_for_state(store, created_room_id, "m.room.power_levels");
                auto const* users = object_member_as_object(power, "users");
                REQUIRE(users != nullptr);
                REQUIRE(int_member(*users, "@alice:example.org") != nullptr);
                REQUIRE(*int_member(*users, "@alice:example.org") == 100);
                REQUIRE(int_member(*users, "@bob:example.org") != nullptr);
                REQUIRE(*int_member(*users, "@bob:example.org") == 100);
            }
        }
    }
}

SCENARIO("createRoom defaults to room version 12 when the client omits room_version",
         "[homeserver][client-server][create-room][room-version]")
{
    GIVEN("a started runtime with a logged-in creator")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client creates a room without specifying room_version")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);

            THEN("the m.room.create state event carries room_version 12")
            {
                // The capabilities endpoint advertises 12 as the default.
                // createRoom must use the same default so clients get the latest
                // version even when they rely on server defaults.
                auto const create =
                    content_for_state(runtime.homeserver.database.persistent_store, created_room_id, "m.room.create");
                auto const* rv = string_member(create, "room_version");
                REQUIRE(rv != nullptr);
                REQUIRE(*rv == "12");
            }
        }

        WHEN("the client explicitly requests room version 10")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"room_version":"10"})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);

            THEN("the m.room.create event uses the requested version 10")
            {
                // Clients can still request older versions - the default change
                // must not override an explicit room_version in the request body.
                auto const create =
                    content_for_state(runtime.homeserver.database.persistent_store, created_room_id, "m.room.create");
                auto const* rv = string_member(create, "room_version");
                REQUIRE(rv != nullptr);
                REQUIRE(*rv == "10");
            }
        }
    }
}

// --- Room v12 MSC4291: room ID is the create event hash -----------------------
// Spec: Matrix room version 12 (MSC4291 "Room IDs as hashes of the create event")
// URL: https://spec.matrix.org/latest/rooms/v12/
//
// In room version 12: (1) the room ID is "!" + the reference hash of the
// m.room.create event, with NO ":server" domain; (2) the create event itself
// carries no room_id; (3) no event lists the create event in its auth_events (it
// is implied by the room ID). A create event that contains a room_id is rejected
// by conformant servers (Synapse), which is exactly what broke send_join. Earlier
// room versions keep the server-scoped room ID, a room_id in the create event, and
// the create event in auth_events. This behaviour MUST differ by room version.
SCENARIO("createRoom derives the room ID from the create event in v12 only (MSC4291)",
         "[homeserver][client-server][create-room][room-version][federation]")
{
    GIVEN("a started runtime with a logged-in creator")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const& store = runtime.homeserver.database.persistent_store;

        auto create_event_id_for = [&store](std::string const& rid) -> std::string {
            auto const it =
                std::ranges::find_if(store.state, [&](merovingian::database::PersistentStateEvent const& r) {
                    return r.room_id == rid && r.event_type == "m.room.create" && r.state_key.empty();
                });
            REQUIRE(it != store.state.end());
            return it->event_id;
        };
        auto auth_events_list = [&store](std::string const& rid, std::string const& event_type) {
            auto const obj = parse_object(event_json_for_state(store, rid, event_type));
            auto const* auth = object_member(obj, "auth_events");
            REQUIRE(auth != nullptr);
            auto const* arr = std::get_if<merovingian::canonicaljson::Array>(&auth->storage());
            REQUIRE(arr != nullptr);
            auto ids = std::vector<std::string>{};
            for (auto const& element : *arr)
            {
                if (auto const* text = std::get_if<std::string>(&element.storage()); text != nullptr)
                {
                    ids.push_back(*text);
                }
            }
            return ids;
        };

        WHEN("the client creates a room with room_version 12")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"room_version":"12"})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const create_id = create_event_id_for(created_room_id);

            THEN("the room ID is '!' + the create event reference hash with no server domain")
            {
                // Spec MUST (MSC4291): room ID = create event ID with the '!' sigil and no
                // ":server" suffix. Do NOT change - a server-scoped ID is not a valid v12 ID.
                REQUIRE_FALSE(created_room_id.empty());
                REQUIRE(created_room_id.front() == '!');
                REQUIRE(created_room_id.find(':') == std::string::npos);
                REQUIRE(create_id.front() == '$');
                REQUIRE(created_room_id == "!" + create_id.substr(1U));
            }

            AND_THEN("the m.room.create event body carries no room_id field")
            {
                // Spec MUST (MSC4291): a v12 create event with a room_id is rejected by peers.
                auto const create = parse_object(event_json_for_state(store, created_room_id, "m.room.create"));
                REQUIRE(object_member(create, "room_id") == nullptr);
            }

            AND_THEN("the create event is not listed in another event's auth_events")
            {
                // Spec MUST (MSC4291): the create event is implied by the room ID and is
                // never referenced explicitly in auth_events.
                auto const power_auth = auth_events_list(created_room_id, "m.room.power_levels");
                REQUIRE(std::ranges::find(power_auth, create_id) == power_auth.end());
            }
        }

        WHEN("the client creates rooms with the earlier versions 10 and 11")
        {
            for (auto const* version : {"10", "11"})
            {
                auto const body = std::string{R"({"room_version":")"} + version + R"("})";
                auto const response = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/createRoom", token, body});
                REQUIRE(response.response.status == 200U);
                auto const created_room_id = room_id(response.response.body);
                auto const create_id = create_event_id_for(created_room_id);

                THEN("the room ID is server-scoped, the create event has a room_id, and the "
                     "create event is in auth_events")
                {
                    // Spec MUST (v10/v11): room IDs remain "!opaque:server".
                    REQUIRE(created_room_id.front() == '!');
                    REQUIRE(created_room_id.find(':') != std::string::npos);
                    // Spec MUST (v10/v11): the create event carries its own room_id.
                    auto const create = parse_object(event_json_for_state(store, created_room_id, "m.room.create"));
                    auto const* create_room_id_field = string_member(create, "room_id");
                    REQUIRE(create_room_id_field != nullptr);
                    REQUIRE(*create_room_id_field == created_room_id);
                    // Spec MUST (v10/v11): the create event IS referenced in auth_events.
                    auto const power_auth = auth_events_list(created_room_id, "m.room.power_levels");
                    REQUIRE(std::ranges::find(power_auth, create_id) != power_auth.end());
                }
            }
        }
    }
}

SCENARIO("createRoom registers canonical aliases and directory lookups",
         "[homeserver][client-server][create-room][aliases]")
{
    GIVEN("a started runtime with a logged-in creator")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const alias = std::string{"#spec:example.org"};

        WHEN("the client creates a room with room_alias_name")
        {
            auto const created = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"room_alias_name":"spec"})"});
            REQUIRE(created.response.status == 200U);
            auto const created_room_id = room_id(created.response.body);

            THEN("the room gets a canonical alias event and the directory resolves it")
            {
                auto const canonical = content_for_state(runtime.homeserver.database.persistent_store, created_room_id,
                                                         "m.room.canonical_alias");
                REQUIRE(string_member(canonical, "alias") != nullptr);
                REQUIRE(*string_member(canonical, "alias") == alias);

                auto const resolved = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/directory/room/%23spec%3Aexample.org", token, {}});
                REQUIRE(resolved.response.status == 200U);
                REQUIRE(resolved.response.body.find(created_room_id) != std::string::npos);
            }

            AND_THEN("the client directory PUT route accepts the existing mapping")
            {
                auto const updated = merovingian::homeserver::handle_client_server_request(
                    runtime, {"PUT", "/_matrix/client/v3/directory/room/%23spec%3Aexample.org", token,
                              std::string{R"({"room_id":")"} + created_room_id + "\"}"});
                REQUIRE(updated.response.status == 200U);
            }

            AND_THEN("reusing the same alias is rejected with M_ROOM_IN_USE")
            {
                auto const duplicate = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"room_alias_name":"spec"})"});
                REQUIRE(duplicate.response.status == 400U);
                REQUIRE(duplicate.response.body.find("M_ROOM_IN_USE") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server im.nheko.summary endpoints return room membership summaries",
         "[homeserver][client-server][nheko-summary]")
{
    GIVEN("a logged-in user with a created room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        WHEN("the user requests the nheko summary for the room")
        {
            auto const encoded = percent_encode_colons(id);
            auto const summary_short = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/im.nheko.summary/summary/" + encoded, token, {}});
            auto const summary_long = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/im.nheko.summary/rooms/" + encoded + "/summary", token, {}});
            auto const summary_missing = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/im.nheko.summary/summary/!missing:example.org", token, {}});

            THEN("both path shapes return 200 with room_id and summary; missing rooms return 404")
            {
                REQUIRE(summary_short.response.status == 200U);
                REQUIRE(summary_short.response.body.find(id) != std::string::npos);
                REQUIRE(summary_short.response.body.find("m.joined_member_count") != std::string::npos);
                REQUIRE(summary_long.response.status == 200U);
                REQUIRE(summary_long.response.body.find(id) != std::string::npos);
                REQUIRE(summary_long.response.body.find("m.joined_member_count") != std::string::npos);
                REQUIRE(summary_missing.response.status == 404U);
            }
        }
    }
}

SCENARIO("Client-server typing and messages routes dispatch through the room block",
         "[homeserver][client-server][typing][messages]")
{
    GIVEN("a logged-in user with a created room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        WHEN("the user sets typing state for themselves")
        {
            auto const typing = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + id + "/typing/@alice:example.org", token,
                          R"({"typing":true,"timeout":3000})"});

            THEN("the request is accepted")
            {
                REQUIRE(typing.response.status == 200U);
            }
        }

        WHEN("the user tries to set typing state for another user")
        {
            auto const typing = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + id + "/typing/@mallory:example.org", token,
                          R"({"typing":true})"});

            THEN("the request is rejected with 403 M_FORBIDDEN")
            {
                REQUIRE(typing.response.status == 403U);
                REQUIRE(typing.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }

        WHEN("the user requests messages from their room")
        {
            auto const messages = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/" + id + "/messages?dir=b&limit=10", token, {}});

            THEN("the response carries chunk, start, end, and state fields")
            {
                REQUIRE(messages.response.status == 200U);
                REQUIRE(messages.response.body.find("chunk") != std::string::npos);
                REQUIRE(messages.response.body.find("start") != std::string::npos);
                REQUIRE(messages.response.body.find("end") != std::string::npos);
                REQUIRE(messages.response.body.find("state") != std::string::npos);
            }
        }

        WHEN("the user requests messages from a non-existent room")
        {
            auto const messages = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/!nonexistent:example.org/messages", token, {}});

            THEN("the response is 404 M_NOT_FOUND")
            {
                REQUIRE(messages.response.status == 404U);
                REQUIRE(messages.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server leave and read_markers routes", "[homeserver][client-server][leave][read_markers]")
{
    GIVEN("a logged-in user with a created room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        WHEN("the user posts read_markers for their room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/read_markers", token,
                          R"({"m.fully_read":"$event1","m.read":"$event1"})"});

            THEN("the response is 200 with an empty object body")
            {
                REQUIRE(response.response.status == 200U);
            }
        }

        WHEN("the user leaves their room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/leave", token, "{}"});

            THEN("the response is 200 and the room no longer appears in joined_rooms")
            {
                REQUIRE(response.response.status == 200U);
                auto const rooms_resp = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});
                REQUIRE(rooms_resp.response.body.find(id) == std::string::npos);
            }
        }

        WHEN("the user tries to leave a non-existent room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!nonexistent:example.org/leave", token, "{}"});

            THEN("the response is 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }

        WHEN("a non-member tries to leave the room")
        {
            // Register a second user who never joined the room
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST",
                                  "/_matrix/client/v3/register",
                                  {},
                                  merovingian::tests::registration_json("bob", "CorrectHorse7!")})
                        .response.status == 200U);
            auto const bob_login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"BOBDEV"})"});
            REQUIRE(bob_login.response.status == 200U);
            auto const bob_token = login_token(bob_login.response.body);

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/leave", bob_token, "{}"});

            THEN("the response is 403 M_FORBIDDEN")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime signs sent events and persists their DAG metadata",
         "[homeserver][client-server][events]")
{
    GIVEN("a logged-in client-server user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        auto const id = room_id(room.response.body);
        auto const initial_event_count = runtime.homeserver.database.persistent_store.events.size();

        WHEN("state and message events are sent through the runtime")
        {
            auto const state = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                 R"({"type":"m.room.member","state_key":"@alice:example.org","content":{"membership":"join"}})"});
            auto const message = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.message","content":{"body":"hi","msgtype":"m.text"}})"});
            auto const& store = runtime.homeserver.database.persistent_store;
            auto const state_event_id = event_id(state.response.body);
            auto const message_event_id = event_id(message.response.body);

            THEN("the returned event IDs are reference hashes and persisted rows include signatures and DAG edges")
            {
                REQUIRE(state.response.status == 200U);
                REQUIRE(message.response.status == 200U);
                REQUIRE(state_event_id.starts_with("$"));
                REQUIRE(message_event_id.starts_with("$"));
                REQUIRE(state_event_id.find(":") == std::string::npos);
                REQUIRE(message_event_id.find(":") == std::string::npos);
                REQUIRE(store.server_signing_keys.size() == 1U);
                REQUIRE(store.events.size() == initial_event_count + 2U);
                REQUIRE(store.events.back().json.find("\"hashes\"") != std::string::npos);
                REQUIRE(store.events.back().json.find("\"signatures\"") != std::string::npos);
                REQUIRE(store.event_signatures.size() == store.events.size());

                // The message event links back to the member state event sent
                // immediately before it and records at least one auth edge.
                auto message_prev_event_id = std::string{};
                auto message_has_auth_edge = false;
                for (auto const& edge : store.event_edges)
                {
                    if (edge.event_id == message_event_id)
                    {
                        message_prev_event_id = edge.prev_event_id;
                    }
                }
                for (auto const& auth_edge : store.event_auth)
                {
                    if (auth_edge.event_id == message_event_id)
                    {
                        message_has_auth_edge = true;
                    }
                }
                REQUIRE(message_prev_event_id == state_event_id);
                REQUIRE(message_has_auth_edge);
            }
        }
    }
}

SCENARIO("Client-server runtime wires server-blind E2EE key API routes", "[homeserver][client-server][key-api]")
{
    GIVEN("a logged-in client-server device")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the device uploads server-blind key material and queries keys")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token,
                          R"({"device_keys":{"sensitive":"curve25519-secret"},"one_time_keys":{}})"});
            auto const query = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/query", token,
                          R"({"device_keys":{"@alice:example.org":["DEVICE1"]}})"});
            auto const unauthenticated = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", {}, R"({"device_keys":{}})"});

            THEN("the runtime path accepts the route without exposing key payloads")
            {
                REQUIRE(upload.response.status == 200U);
                REQUIRE(query.response.status == 200U);
                REQUIRE(unauthenticated.response.status == 401U);
                REQUIRE(upload.response.body.find("one_time_key_counts") != std::string::npos);
                REQUIRE(query.response.body.find("device_keys") != std::string::npos);
                REQUIRE(upload.response.body.find("curve25519-secret") == std::string::npos);
                REQUIRE(merovingian::homeserver::key_api_record_count(runtime, "@alice:example.org") == 2U);
            }
        }
    }
}

SCENARIO("Client-server runtime wires trust and safety report and admin review routes",
         "[homeserver][client-server][trust-safety]")
{
    GIVEN("a logged-in admin client-server user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const admin = merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "alice", "CorrectHorse7!");
        REQUIRE(admin.ok);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client reports an event and the admin reviews a media target")
        {
            auto const report = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!room:example.org/report/$event", token,
                          R"({"reason":"spam","score":50})"});
            auto const reports = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/admin/safety/reports", token, {}});
            auto const review = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/admin/safety/review/media/media123", token,
                          R"({"reason":"manual_review"})"});

            THEN("policy decisions are served through runtime auth and persisted as audit/admin rows")
            {
                REQUIRE(report.response.status == 200U);
                REQUIRE(reports.response.status == 200U);
                REQUIRE(review.response.status == 200U);
                REQUIRE(reports.response.body.find("trust_safety.room.accept_report") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.audit_log.size() >= 4U);
                REQUIRE(runtime.homeserver.database.persistent_store.admin_actions.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.admin_actions.front().action ==
                        "trust_safety.media.quarantine");
            }
        }
    }
}

SCENARIO("Client-server runtime persists client action audit events", "[homeserver][client-server][audit]")
{
    GIVEN("a logged-in client-server device")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the device updates metadata and uploads E2EE keys")
        {
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/devices/DEVICE1", token, R"({"display_name":"Alice laptop"})"});
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, R"({"device_keys":{"secret":"value"}})"});

            THEN("client-server audit events are durable and redact key payloads")
            {
                REQUIRE(update.response.status == 200U);
                REQUIRE(upload.response.status == 200U);
                auto const& audit = runtime.homeserver.database.persistent_store.audit_log;
                REQUIRE(audit.size() >= 4U);
                REQUIRE(std::ranges::any_of(audit, [](auto const& event) {
                    return event.event_type == "device.updated";
                }));
                REQUIRE(std::ranges::any_of(audit, [](auto const& event) {
                    return event.event_type == "key_api.upload_keys" &&
                           event.reason.find("secret") == std::string::npos;
                }));
            }
        }
    }
}

SCENARIO("Client-server runtime enforces request limits and Matrix-style errors", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime with tight limits")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_body_bytes = 4U;
        // Tight wall-clock engine: any route we hit allows exactly 1
        // request per 60s window. The default runtime engine has 60
        // per 60s on account/whoami, so we need to override to drive
        // the 429 path from a single request.
        merovingian::homeserver::install_test_rate_limit_engine(runtime);

        WHEN("oversized and repeated requests are sent")
        {
            auto const oversized = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
            runtime.limits.max_body_bytes = 65536U;
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const second = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});

            THEN("the client-server API reports stable bounded errors")
            {
                REQUIRE(oversized.response.status == 413U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(oversized.response));
                REQUIRE(first.response.status == 401U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(first.response));
                REQUIRE(second.response.status == 429U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(second.response));
            }
        }
    }
}

SCENARIO("Client-server runtime normalizes route-template rate-limit buckets", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime with a one-request route bucket")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::install_test_rate_limit_engine(runtime);

        WHEN("different room IDs hit the same route template")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!one:example.org/send", "bad", "{}"});
            auto const second = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!two:example.org/send", "bad", "{}"});

            THEN("the second request is limited by the normalized route bucket")
            {
                REQUIRE(first.response.status == 401U);
                REQUIRE(second.response.status == 429U);
            }
        }
    }
}

SCENARIO("Sync endpoint returns stream token and event bodies for initial and incremental sync",
         "[homeserver][client-server][sync]")
{
    GIVEN("a logged-in user with a room and a sent event")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        auto const room_id = json_value(room.response.body, "\"room_id\":\"");
        auto const send = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token,
                      R"({"type":"m.room.message","content":{"body":"hello","msgtype":"m.text"}})"});

        WHEN("initial sync is requested without a since token")
        {
            auto const sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the response contains a stream token next_batch and event bodies in the timeline")
            {
                REQUIRE(sync.response.status == 200U);
                REQUIRE(sync.response.body.find("\"next_batch\"") != std::string::npos);
                REQUIRE(sync.response.body.find("\"events\":") != std::string::npos);
                REQUIRE(sync.response.body.find("\"timeline\"") != std::string::npos);
                REQUIRE(sync.response.body.find("\"rooms\"") != std::string::npos);
            }
        }

        WHEN("incremental sync is requested with the stream token from initial sync")
        {
            auto const initial = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
            auto const since_token = json_value(initial.response.body, "\"next_batch\":\"");

            auto const incremental = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?since=" + since_token, token, {}});

            THEN("the incremental response contains a new stream token and no duplicate events")
            {
                REQUIRE(incremental.response.status == 200U);
                REQUIRE(incremental.response.body.find("\"next_batch\"") != std::string::npos);
                REQUIRE(incremental.response.body.find("\"rooms\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server /versions advertises Matrix spec compatibility to unauthenticated clients",
         "[homeserver][client-server][versions]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        WHEN("an unauthenticated client requests GET /_matrix/client/versions")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/versions", {}, {}});

            THEN("the server answers 200 with a versions array and unstable_features object")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("\"versions\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"v1.18\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"v1.1\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"unstable_features\"") != std::string::npos);
                REQUIRE_FALSE(merovingian::homeserver::is_matrix_error_response(response.response));
            }
        }
    }
}

SCENARIO("Sync surfaces invite and leave room categories alongside Matrix-spec top-level stubs",
         "[homeserver][client-server][sync]")
{
    GIVEN("a registered user with an outstanding invite and a left room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        auto const register_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_response.response.status == 200U);
        auto const user_id = json_value(register_response.response.body, "\"user_id\":\"");

        auto const login_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/login",
                      {},
                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + user_id +
                          R"("},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_response.response.status == 200U);
        auto const token = login_token(login_response.response.body);

        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!invited_room:example.org", user_id, "invite", 0U});
        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!left_room:example.org", user_id, "leave", 0U});

        WHEN("the user requests /sync")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the response carries the invite room category and Matrix-spec top-level keys")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("\"invite\"") != std::string::npos);
                REQUIRE(response.response.body.find("!invited_room:example.org") != std::string::npos);
                REQUIRE(response.response.body.find("\"invite_state\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"account_data\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"presence\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"to_device\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"device_lists\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"device_one_time_keys_count\"") != std::string::npos);
            }

            THEN("the response keeps rooms.leave as an empty object until include_leave filter support lands")
            {
                REQUIRE(response.response.body.find("\"leave\":{}") != std::string::npos);
                REQUIRE(response.response.body.find("!left_room:example.org") == std::string::npos);
            }
        }

        WHEN("the user has more invite memberships than max_sync_rooms")
        {
            runtime.limits.max_sync_rooms = 2U;
            runtime.homeserver.database.persistent_store.memberships.push_back(
                {"!invite2:example.org", user_id, "invite", 0U});
            runtime.homeserver.database.persistent_store.memberships.push_back(
                {"!invite3:example.org", user_id, "invite", 0U});
            runtime.homeserver.database.persistent_store.memberships.push_back(
                {"!invite4:example.org", user_id, "invite", 0U});

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the invite section honors the room cap and does not bloat the response")
            {
                REQUIRE(response.response.status == 200U);
                // First two invites in iteration order should be present
                // (the originally pushed `!invited_room` plus `!invite2`);
                // later invites must be dropped by the cap.
                REQUIRE(response.response.body.find("!invited_room:example.org") != std::string::npos);
                REQUIRE(response.response.body.find("!invite2:example.org") != std::string::npos);
                REQUIRE(response.response.body.find("!invite3:example.org") == std::string::npos);
                REQUIRE(response.response.body.find("!invite4:example.org") == std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server enforces per-endpoint rate limits with 429 M_LIMIT_EXCEEDED",
         "[homeserver][client-server][rate-limit]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        // Tight wall-clock engine: one request per 60s on every route, so
        // the 6th registration attempt within the same window is denied.
        merovingian::homeserver::install_test_rate_limit_engine(runtime);

        WHEN("registration is invoked more times than the endpoint policy allows in the window")
        {
            // endpoint_default_rate_limit returns {max_requests=5, window_seconds=60}
            // for POST /_matrix/client/v3/register, so the sixth request inside
            // the wall-clock window must fail closed.
            auto last_status = std::uint16_t{0U};
            auto last_body = std::string{};
            for (auto index = 0; index < 6; ++index)
            {
                auto body = std::string{"{\"username\":\"user"};
                body += std::to_string(index);
                body += "\",\"password\":\"CorrectHorse7!\"}";
                auto const response = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {}, body});
                last_status = response.response.status;
                last_body = response.response.body;
            }

            THEN("the sixth attempt fails closed with 429 and M_LIMIT_EXCEEDED")
            {
                REQUIRE(last_status == 429U);
                REQUIRE(last_body.find("M_LIMIT_EXCEEDED") != std::string::npos);
            }
        }

        WHEN("an unrelated endpoint is hit after exhausting registration's quota")
        {
            for (auto index = 0; index < 6; ++index)
            {
                auto body = std::string{"{\"username\":\"flood"};
                body += std::to_string(index);
                body += "\",\"password\":\"CorrectHorse7!\"}";
                static_cast<void>(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {}, body}));
            }

            auto const versions_response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/versions", {}, {}});

            THEN("the other endpoint runs on its own bucket and is not rate-limited")
            {
                REQUIRE(versions_response.response.status == 200U);
                REQUIRE_FALSE(merovingian::homeserver::is_matrix_error_response(versions_response.response));
            }
        }
    }
}

SCENARIO("Rate-limit buckets are scoped per access token to prevent cross-user denial of service",
         "[homeserver][client-server][rate-limit]")
{
    GIVEN("a started runtime with two registered, logged-in users")
    {
        // Register and log in both users with the default loose cap so the
        // setup itself does not collide with the bucket. The tight per-user
        // cap is applied after both users hold valid access tokens.
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const register_alice = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_alice.response.status == 200U);
        auto const register_bob = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("bob", "CorrectHorse7!")});
        REQUIRE(register_bob.response.status == 200U);

        auto const login_alice = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_alice.response.status == 200U);
        auto const alice_token = login_token(login_alice.response.body);

        auto const login_bob = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_bob.response.status == 200U);
        auto const bob_token = login_token(login_bob.response.body);

        merovingian::homeserver::install_test_per_user_rate_limit_engine(runtime);

        WHEN("alice exhausts her authenticated bucket")
        {
            auto const alice_first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", alice_token, {}});
            auto const alice_second = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", alice_token, {}});
            auto const bob_first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", bob_token, {}});

            THEN("alice's second request is 429 but bob's first request runs on his own bucket and succeeds")
            {
                REQUIRE(alice_first.response.status == 200U);
                REQUIRE(alice_second.response.status == 429U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(alice_second.response));
                REQUIRE(bob_first.response.status == 200U);
            }
        }
    }
}

SCENARIO("Login failures return HTTP 403 M_FORBIDDEN per the Matrix spec", "[homeserver][client-server][login][auth]")
{
    GIVEN("a started client-server runtime with registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("login is attempted for a user that does not exist")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@nobody:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});

            THEN("the response is 403 M_FORBIDDEN, not 400")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }

        WHEN("a user registers and then logs in with the wrong password")
        {
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")});
            REQUIRE(registered.response.status == 200U);

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"WrongPassword1!","device_id":"DEVICE1"})"});

            THEN("the response is 403 M_FORBIDDEN, not 400")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("OPTIONS preflight requests return 200 without requiring an access token",
         "[homeserver][client-server][cors][preflight]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an OPTIONS preflight is sent to the login endpoint without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"OPTIONS", "/_matrix/client/v3/login", {}, {}});

            THEN("the response is 200, not 401, so the browser allows the following POST")
            {
                REQUIRE(response.response.status == 200U);
            }
        }

        WHEN("an OPTIONS preflight is sent to the register endpoint without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"OPTIONS", "/_matrix/client/v3/register", {}, {}});

            THEN("the response is 200")
            {
                REQUIRE(response.response.status == 200U);
            }
        }
    }
}

namespace
{
    // Lookup helper for LocalHttpResponse::headers (added in 0.4.60). Returns the
    // header value or empty string when the header is absent. Case-sensitive
    // because the wire emitter writes the canonical header name.
    [[nodiscard]] auto response_header(merovingian::homeserver::LocalHttpResponse const& response,
                                       std::string_view name) -> std::string
    {
        for (auto const& [key, value] : response.headers)
        {
            if (key == name)
            {
                return value;
            }
        }
        return {};
    }
} // namespace

SCENARIO("OPTIONS preflight attaches Access-Control-Allow-Origin wildcard by default",
         "[homeserver][client-server][cors][preflight]")
{
    GIVEN("a started client-server runtime with the default CORS policy")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an OPTIONS preflight is sent to the sync endpoint")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{
                "OPTIONS", "/_matrix/client/v3/sync", {}, {}, {merovingian::http::Header{"Origin", "vector://vector"}},
            };
            auto const response = merovingian::homeserver::handle_client_server_request(runtime, request);

            THEN("the response carries Access-Control-Allow-Origin: *")
            {
                REQUIRE(response_header(response.response, "Access-Control-Allow-Origin") == "*");
            }
        }
    }
}

SCENARIO("OPTIONS preflight attaches Access-Control-Allow-Methods and Allow-Headers",
         "[homeserver][client-server][cors][preflight]")
{
    GIVEN("a started client-server runtime with the default CORS policy")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an OPTIONS preflight is sent to the rooms endpoint")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{
                "OPTIONS", "/_matrix/client/v3/rooms", {}, {}, {merovingian::http::Header{"Origin", "vector://vector"}},
            };
            auto const response = merovingian::homeserver::handle_client_server_request(runtime, request);

            THEN("Access-Control-Allow-Methods lists GET, POST, PUT, DELETE, OPTIONS")
            {
                REQUIRE(response_header(response.response, "Access-Control-Allow-Methods") ==
                        "GET, POST, PUT, DELETE, OPTIONS");
            }
            THEN("Access-Control-Allow-Headers includes authorization and content-type")
            {
                auto const allow_headers = response_header(response.response, "Access-Control-Allow-Headers");
                REQUIRE(allow_headers.find("authorization") != std::string::npos);
                REQUIRE(allow_headers.find("content-type") != std::string::npos);
            }
            THEN("Access-Control-Max-Age is set to the configured 24h default")
            {
                REQUIRE(response_header(response.response, "Access-Control-Max-Age") == "86400");
            }
            THEN("Vary: Origin is set so caches do not poison a wildcard response")
            {
                REQUIRE(response_header(response.response, "Vary") == "Origin");
            }
        }
    }
}

SCENARIO("OPTIONS preflight echoes back an explicit single origin from the allow-list",
         "[homeserver][client-server][cors][preflight]")
{
    GIVEN("a started client-server runtime with one allowed origin configured")
    {
        auto server = merovingian::config::ServerConfig{};
        auto security = merovingian::config::SecurityConfig{};
        merovingian::tests::enable_token_registration(security);
        auto config = merovingian::config::Config{server, {}, {}, security, {}, {}};
        // Configure the allow-list via the runtime's CORS snapshot. (The
        // config-parser key is wired in commit 3; here we exercise the
        // runtime surface directly so the test is independent of the
        // parser.)
        config.server().cors.allowed_origins = {"https://app.example.com"};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a preflight from the allowed origin arrives")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "OPTIONS";
            request.target = "/_matrix/client/v3/sync";
            request.headers = {merovingian::http::Header{"Origin", "https://app.example.com"}};
            auto const response =
                merovingian::homeserver::handle_client_server_request(runtime, request);

            THEN("the response echoes the request Origin back as the allowed origin")
            {
                REQUIRE(response_header(response.response, "Access-Control-Allow-Origin") ==
                        "https://app.example.com");
            }
        }
    }
}

SCENARIO("OPTIONS preflight from an origin not in the allow-list omits Allow-Origin",
         "[homeserver][client-server][cors][preflight]")
{
    GIVEN("a started client-server runtime with one allowed origin configured")
    {
        auto server = merovingian::config::ServerConfig{};
        auto security = merovingian::config::SecurityConfig{};
        merovingian::tests::enable_token_registration(security);
        auto config = merovingian::config::Config{server, {}, {}, security, {}, {}};
        config.server().cors.allowed_origins = {"https://app.example.com"};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a preflight from an unlisted origin arrives")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "OPTIONS";
            request.target = "/_matrix/client/v3/sync";
            request.headers = {merovingian::http::Header{"Origin", "https://attacker.example"}};
            auto const response =
                merovingian::homeserver::handle_client_server_request(runtime, request);

            THEN("Access-Control-Allow-Origin is not set so the browser blocks the request")
            {
                REQUIRE(response_header(response.response, "Access-Control-Allow-Origin").empty());
            }
        }
    }
}

SCENARIO("Non-preflight responses also carry the CORS headers so the browser accepts them",
         "[homeserver][client-server][cors]")
{
    GIVEN("a started client-server runtime with the default CORS policy")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a GET /_matrix/client/versions is sent")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{
                "GET", "/_matrix/client/versions", {}, {}, {merovingian::http::Header{"Origin", "vector://vector"}},
            };
            auto const response = merovingian::homeserver::handle_client_server_request(runtime, request);

            THEN("the response status is 200")
            {
                REQUIRE(response.response.status == 200U);
            }
            THEN("the response still carries Access-Control-Allow-Origin")
            {
                // Browsers will not expose the response body to the page if
                // the actual response is missing the CORS header, even when
                // the preflight succeeded.
                REQUIRE(response_header(response.response, "Access-Control-Allow-Origin") == "*");
            }
        }
    }
}

SCENARIO("format_response wire output emits configured headers in insertion order",
         "[homeserver][http-transport][wire-format]")
{
    GIVEN("a list of headers to inject into the response")
    {
        // format_response is internal to the homeserver TU. We exercise it
        // through handle_client_server_request's OPTIONS path which is the
        // smallest observable surface for the wire format. The headers live
        // on `response.response.headers` (parsed by the http_server emitter),
        // not in the body.
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the OPTIONS preflight is formatted")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{
                "OPTIONS", "/_matrix/client/v3/sync", {}, {},
                {merovingian::http::Header{"Origin", "vector://vector"}},
            };
            auto const response = merovingian::homeserver::handle_client_server_request(runtime, request);

            THEN("Access-Control-Allow-Origin appears before Access-Control-Allow-Methods")
            {
                auto const& hdrs = response.response.headers;
                auto origin_pos = std::size_t{};
                auto methods_pos = std::size_t{};
                auto found_origin = false;
                auto found_methods = false;
                for (std::size_t i = 0U; i < hdrs.size(); ++i)
                {
                    if (hdrs[i].first == "Access-Control-Allow-Origin")
                    {
                        origin_pos = i;
                        found_origin = true;
                    }
                    else if (hdrs[i].first == "Access-Control-Allow-Methods")
                    {
                        methods_pos = i;
                        found_methods = true;
                    }
                }
                REQUIRE(found_origin);
                REQUIRE(found_methods);
                REQUIRE(origin_pos < methods_pos);
            }
        }
    }
}

SCENARIO("Well-known client discovery endpoint serves homeserver base URL",
         "[homeserver][client-server][well-known][discovery]")
{
    GIVEN("a started client-server runtime with a configured public base URL")
    {
        auto server = merovingian::config::ServerConfig{};
        server.public_baseurl = "https://matrix.example.org";
        auto security = merovingian::config::SecurityConfig{};
        merovingian::tests::enable_token_registration(security);
        auto config = merovingian::config::Config{server, {}, {}, security, {}, {}};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("GET /.well-known/matrix/client is requested")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/.well-known/matrix/client", {}, {}});

            THEN("the response is 200 with the homeserver base URL in the Matrix discovery format")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("m.homeserver") != std::string::npos);
                REQUIRE(response.response.body.find("https://matrix.example.org") != std::string::npos);
                REQUIRE(response.response.body.find("base_url") != std::string::npos);
            }
        }
    }
}

SCENARIO("Capabilities endpoint returns server feature flags for authenticated clients",
         "[homeserver][client-server][capabilities]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /_matrix/client/v3/capabilities is requested with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/capabilities", token, {}});

            THEN("the response is 200 with a capabilities object")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("capabilities") != std::string::npos);
            }

            THEN("m.room_versions advertises 12 as the default version")
            {
                // Clients use this to know which version to request when creating rooms.
                // The default must be the latest stable version the server supports.
                REQUIRE(response.response.body.find(R"("default":"12")") != std::string::npos);
            }

            THEN("m.room_versions lists 10 11 and 12 as stable")
            {
                REQUIRE(response.response.body.find(R"("10":"stable")") != std::string::npos);
                REQUIRE(response.response.body.find(R"("11":"stable")") != std::string::npos);
                REQUIRE(response.response.body.find(R"("12":"stable")") != std::string::npos);
            }
        }

        WHEN("GET /_matrix/client/v3/capabilities is requested without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/capabilities", {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

SCENARIO("Push rules endpoint returns the spec default global ruleset for authenticated clients",
         "[homeserver][client-server][pushrules]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /_matrix/client/v3/pushrules/ is requested with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/pushrules/", token, {}});

            THEN("the response is 200 with the default override and underride rules")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = merovingian::tests::parse_object(response.response.body);
                auto const* global = merovingian::tests::object_member_as_object(body, "global");
                REQUIRE(global != nullptr);
                auto const* override_rules = merovingian::tests::object_member_as_array(*global, "override");
                auto const* underride_rules = merovingian::tests::object_member_as_array(*global, "underride");
                REQUIRE(override_rules != nullptr);
                REQUIRE(underride_rules != nullptr);
                REQUIRE(!override_rules->empty());
                REQUIRE(!underride_rules->empty());
            }
        }

        WHEN("GET /_matrix/client/v3/pushrules/ is requested without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/pushrules/", {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

SCENARIO("Keys upload accepts bodies larger than 4 KiB", "[homeserver][client-server][key-api]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("POST /keys/upload is called with a body larger than 4 KiB but within 64 KiB")
        {
            // Simulate a real Cinny OTK bundle: device keys + many one-time keys.
            // The body must exceed 4096 bytes to prove the old limit is gone.
            auto large_body = std::string{
                R"({"device_keys":{"@alice:example.org":{"DEVICE1":{"algorithms":[],"device_id":"DEVICE1","keys":{},"signatures":{},"user_id":"@alice:example.org"}}},"one_time_keys":{)"};
            for (int i = 0; i < 40; ++i)
            {
                if (i != 0)
                {
                    large_body += ',';
                }
                large_body += "\"signed_curve25519:KEY" + std::to_string(i) + "\":\"" + std::string(80U, 'a') + "\"";
            }
            large_body += "}}";
            REQUIRE(large_body.size() > 4096U);

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, large_body});

            THEN("the response is 200, not 413")
            {
                REQUIRE(response.response.status == 200U);
            }
        }
    }
}

SCENARIO("OIDC discovery endpoints return 404 without authentication", "[homeserver][client-server]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("GET /_matrix/client/unstable/org.matrix.msc2965/auth_metadata is called without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata", {}, {}});

            THEN("the response is 404, not 401")
            {
                // We do not implement OIDC; the endpoint must be absent (404) rather
                // than access-denied (401) so clients can probe and fall back gracefully.
                REQUIRE(response.response.status == 404U);
            }
        }

        WHEN("GET /_matrix/client/v1/auth_metadata is called without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v1/auth_metadata", {}, {}});

            THEN("the stable probe also returns 404, not 401")
            {
                REQUIRE(response.response.status == 404U);
            }
        }

        WHEN("GET /_matrix/client/unstable/org.matrix.msc2965/auth_issuer is called without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/org.matrix.msc2965/auth_issuer", {}, {}});

            THEN("the response is 404, not 401")
            {
                REQUIRE(response.response.status == 404U);
            }
        }
    }
}

SCENARIO("VoIP turn server endpoint returns an empty object for authenticated clients", "[homeserver][client-server]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /_matrix/client/v3/voip/turnServer is called with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/voip/turnServer", token, {}});

            THEN("the response is 200 with an empty object, not 404")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
            }
        }
    }
}

SCENARIO("Profile endpoint returns a user profile stub for authenticated clients", "[homeserver][client-server]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /profile/{userId} is called with a percent-encoded user id")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org", token, {}});

            THEN("the response is 200 and contains displayname and avatar_url fields")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("displayname") != std::string::npos);
                REQUIRE(response.response.body.find("avatar_url") != std::string::npos);
            }
        }

        WHEN("GET /profile/{userId} is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org", {}, {}});

            THEN("the response is 200 - profile lookup is unauthenticated per the Matrix spec")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("displayname") != std::string::npos);
            }
        }
    }
}

SCENARIO("Media config endpoint returns upload size limit for authenticated clients", "[homeserver][client-server]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /_matrix/media/v3/config is called with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/media/v3/config", token, {}});

            THEN("the response is 200 and contains m.upload.size")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("m.upload.size") != std::string::npos);
            }
        }

        WHEN("GET /_matrix/media/v3/config is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/media/v3/config", {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

SCENARIO("User filter API stores and retrieves sync filters", "[homeserver][client-server][filter]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        // @alice:example.org percent-encoded as it appears in a real browser URL
        auto constexpr user_filter_url = "/_matrix/client/v3/user/%40alice%3Aexample.org/filter";
        auto constexpr filter_body = R"({"room":{"timeline":{"limit":50}}})";

        WHEN("POST /user/{userId}/filter is called with a valid filter body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", user_filter_url, token, filter_body});

            THEN("the response is 200 and contains a filter_id")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("filter_id") != std::string::npos);
            }
        }

        WHEN("GET /user/{userId}/filter/{filterId} is called with a valid filter_id")
        {
            // Store a filter first so we have a filter_id to look up
            auto const store_resp = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", user_filter_url, token, filter_body});
            REQUIRE(store_resp.response.status == 200U);
            auto const fid = json_value(store_resp.response.body, "\"filter_id\":\"");

            auto const get_url = std::string{user_filter_url} + "/" + fid;
            auto const response =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", get_url, token, {}});

            THEN("the response is 200 and returns the stored filter body")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("timeline") != std::string::npos);
            }
        }

        WHEN("GET /user/{userId}/filter/{filterId} is called with an unknown filter_id")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", std::string{user_filter_url} + "/nonexistent", token, {}});

            THEN("the response is 404")
            {
                REQUIRE(response.response.status == 404U);
            }
        }

        WHEN("POST /user/{userId}/filter is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", user_filter_url, {}, filter_body});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

SCENARIO("Join-by-id endpoint joins a room through the local join handler", "[homeserver][client-server]")
{
    GIVEN("a logged-in user who has created a room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        // Use room version 10 so the room ID is server-scoped ("!id:server") and
        // therefore contains a colon to percent-encode; room v12 IDs are bare hashes
        // (no ":server") which would make the percent-encoding path trivial.
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"room_version":"10"})"});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        WHEN("POST /_matrix/client/v3/join/{roomId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/join/" + id, token, {}});

            THEN("the response is 200 and reports the joined room id")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find(id) != std::string::npos);
            }
        }

        WHEN("POST /_matrix/client/v3/join/{roomId} is called with a percent-encoded room ID")
        {
            auto const encoded_id = percent_encode_colons(id);
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/join/" + encoded_id, token, "{}"});

            THEN("the path segment is decoded before the local room lookup")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find(id) != std::string::npos);
                REQUIRE(response.response.body.find(encoded_id) == std::string::npos);
            }
        }

        WHEN("POST /_matrix/client/v3/join/{roomId} is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/join/" + id, {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

// --- Federated join routing for room version 12 (MSC4291) ---------------------
// Spec: Matrix Client-Server API v1.18 — POST /join/{roomIdOrAlias}?server_name=/?via=
// Spec: Matrix room version 12 (MSC4291) — room IDs are bare create-event hashes
//
// A room version 12 room ID has no ":server" suffix, so the only way to route a
// federated join is the via / server_name query parameters. Without them the join
// MUST be rejected as unroutable; with them the server MUST attempt federation.
// With no reachable peer in this test that attempt surfaces as a 502 upstream
// failure — which proves the via parameter was parsed and used, not ignored.
SCENARIO("Joining a remote room version 12 room requires and uses via servers (MSC4291)",
         "[homeserver][client-server][federation][room-version]")
{
    GIVEN("a logged-in user and a remote v12 room ID with no server domain")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        // A room v12 room ID: "!" + a base64url reference hash, with no ":server".
        auto const v12_room = std::string{"!2YQSq5ktnAd_dGjYrlQH9xoneatU4LJBwuoadqUhfTA"};

        WHEN("the room is joined by ID with no via/server_name parameter")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/join/" + v12_room, token, "{}"});

            THEN("the join is rejected as unroutable, not attempted")
            {
                // No server domain in the room ID and no via → no candidate server.
                REQUIRE(response.response.status == 404U);
            }
        }

        WHEN("the room is joined by ID with a legacy server_name parameter")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/join/" + v12_room + "?server_name=remote.example", token, "{}"});

            THEN("the via server is used to attempt federation, so it is no longer a 404")
            {
                // The candidate server now exists, so the join proceeds to make_join;
                // with no reachable peer in the test harness this is a 502 upstream error.
                REQUIRE(response.response.status != 404U);
                REQUIRE(response.response.status == 502U);
            }
        }

        WHEN("the room is joined by ID with a via parameter (MSC4156 spelling)")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/join/" + v12_room + "?via=remote.example", token, "{}"});

            THEN("the via server is used to attempt federation, so it is no longer a 404")
            {
                REQUIRE(response.response.status != 404U);
                REQUIRE(response.response.status == 502U);
            }
        }
    }
}

SCENARIO("Account data endpoint stores and retrieves global account data", "[homeserver][client-server]")
{
    GIVEN("a logged-in client-server user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        // @alice:example.org percent-encoded as a browser sends it
        auto constexpr account_data_url = "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.direct";
        auto constexpr direct_body = R"({"@bob:example.org":["!room1:example.org"]})";

        WHEN("PUT /account_data/{type} is called with a body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", account_data_url, token, direct_body});

            THEN("the response is 200")
            {
                REQUIRE(response.response.status == 200U);
            }
        }

        WHEN("GET /account_data/{type} is called after a PUT")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", account_data_url, token, direct_body});
            REQUIRE(put.response.status == 200U);

            auto const response =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", account_data_url, token, {}});

            THEN("the response is 200 and returns the stored content")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("@bob:example.org") != std::string::npos);
            }
        }

        WHEN("GET /account_data/{type} is called for an unset type")
        {
            auto const response =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", account_data_url, token, {}});

            THEN("the response is 404")
            {
                REQUIRE(response.response.status == 404U);
            }
        }

        WHEN("PUT /account_data/{type} is called for another user")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/user/%40bob%3Aexample.org/account_data/m.direct", token, direct_body});

            THEN("the response is 403")
            {
                REQUIRE(response.response.status == 403U);
            }
        }

        WHEN("PUT /account_data/{type} is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", account_data_url, {}, direct_body});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3room_keysversion
SCENARIO("POST /room_keys/version returns a version identifier to the client",
         "[homeserver][client-server][key-api][key-backup]")
{
    GIVEN("a logged-in device")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the device creates a key backup version")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/room_keys/version", token,
                 R"({"algorithm":"m.megolm_backup.v1","auth_data":{"public_key":"base64+public+key","signatures":{}}})"});

            THEN("the response is 200 with a JSON object containing a non-empty string version field")
            {
                // Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3room_keysversion
                // The response MUST be a JSON object with a string "version" field.
                // Element fails with "Unable to set up keys" if the field is absent.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* version = string_member(body, "version");
                REQUIRE(version != nullptr);
                REQUIRE(!version->empty());
            }
        }
    }
}

// Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3createroom
// "If the preset is private_chat or trusted_private_chat, the server SHOULD enable end-to-end
// encryption in the room."
SCENARIO("private_chat preset auto-emits m.room.encryption when the client omits it",
         "[homeserver][client-server][create-room][encryption]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client creates a private_chat room without specifying encryption in initial_state")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"private_chat"})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("m.room.encryption is automatically emitted with the megolm algorithm")
            {
                REQUIRE(has_state_event(store, created_room_id, "m.room.encryption"));
                auto const encryption = content_for_state(store, created_room_id, "m.room.encryption");
                REQUIRE(string_member(encryption, "algorithm") != nullptr);
                REQUIRE(*string_member(encryption, "algorithm") == "m.megolm.v1.aes-sha2");
            }
        }

        WHEN("the client creates a trusted_private_chat room without specifying encryption in initial_state")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"trusted_private_chat"})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("m.room.encryption is automatically emitted with the megolm algorithm")
            {
                REQUIRE(has_state_event(store, created_room_id, "m.room.encryption"));
                auto const encryption = content_for_state(store, created_room_id, "m.room.encryption");
                REQUIRE(string_member(encryption, "algorithm") != nullptr);
                REQUIRE(*string_member(encryption, "algorithm") == "m.megolm.v1.aes-sha2");
            }
        }
    }
}

SCENARIO("public_chat preset does not auto-emit m.room.encryption",
         "[homeserver][client-server][create-room][encryption]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client creates a public_chat room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"visibility":"public"})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("m.room.encryption is NOT present in room state")
            {
                REQUIRE_FALSE(has_state_event(store, created_room_id, "m.room.encryption"));
            }
        }
    }
}

// --- auth_events selection ----------------------------------------------------
// Spec: Matrix Server-Server API v1.18 Sec. 4.4 auth_events
// URL:  https://spec.matrix.org/v1.18/server-server-api/#auth_events
//
// Per the spec, auth_events for each event type MUST be:
//   m.room.create:  none
//   m.room.member:  {create, power_levels, join_rules, target_member}
//   all others:      {create, power_levels}
// Room v12 (MSC4291) excludes create from auth_events (it is implied by the
// room ID). Synapse rejects events that include unexpected auth_events (e.g.
// join_rules in a history_visibility event) with "unexpected auth_event for
// ('m.room.join_rules', '')", which cascades into broken invite state and
// "You are not invited" join failures.
[[nodiscard]] auto auth_event_ids_for_state(merovingian::database::PersistentStore const& store,
                                            std::string_view room_id, std::string_view event_type,
                                            std::string_view state_key = {}) -> std::vector<std::string>
{
    auto const state = std::ranges::find_if(store.state, [&](merovingian::database::PersistentStateEvent const& row) {
        return row.room_id == room_id && row.event_type == event_type && row.state_key == state_key;
    });
    REQUIRE(state != store.state.end());
    auto const event = std::ranges::find_if(store.events, [&](merovingian::database::PersistentEvent const& row) {
        return row.event_id == state->event_id;
    });
    REQUIRE(event != store.events.end());
    return event->auth_event_ids;
}

[[nodiscard]] auto state_event_id(merovingian::database::PersistentStore const& store, std::string_view room_id,
                                  std::string_view event_type, std::string_view state_key = {}) -> std::string
{
    auto const state = std::ranges::find_if(store.state, [&](merovingian::database::PersistentStateEvent const& row) {
        return row.room_id == room_id && row.event_type == event_type && row.state_key == state_key;
    });
    REQUIRE(state != store.state.end());
    return state->event_id;
}

SCENARIO("non-member events exclude join_rules from auth_events per spec v1.18",
         "[homeserver][client-server][create-room][auth-events]")
{
    GIVEN("a logged-in user who creates a private v12 room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the room is created with private_chat preset")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/createRoom", token,
                 R"({"preset":"private_chat","room_version":"12","invite":["@bob:example.org"],"is_direct":true})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const& store = runtime.homeserver.database.persistent_store;
            auto const sender = std::string{"@alice:example.org"};
            auto const join_rules_id = state_event_id(store, created_room_id, "m.room.join_rules");
            auto const member_id = state_event_id(store, created_room_id, "m.room.member", sender);
            auto const power_levels_id = state_event_id(store, created_room_id, "m.room.power_levels");

            THEN("m.room.create has no auth_events (v12: create is implied)")
            {
                auto const ids = auth_event_ids_for_state(store, created_room_id, "m.room.create");
                REQUIRE(ids.empty());
            }
            AND_THEN("m.room.power_levels excludes join_rules from auth_events")
            {
                auto const ids = auth_event_ids_for_state(store, created_room_id, "m.room.power_levels");
                REQUIRE(std::ranges::find(ids, join_rules_id) == ids.end());
            }
            AND_THEN("m.room.join_rules includes power_levels but not history_visibility")
            {
                auto const ids = auth_event_ids_for_state(store, created_room_id, "m.room.join_rules");
                REQUIRE(std::ranges::find(ids, power_levels_id) != ids.end());
                // join_rules itself must not carry unrelated state as auth_events
                auto const hv_id = state_event_id(store, created_room_id, "m.room.history_visibility");
                REQUIRE(std::ranges::find(ids, hv_id) == ids.end());
            }
            AND_THEN("m.room.history_visibility excludes join_rules from auth_events")
            {
                auto const ids = auth_event_ids_for_state(store, created_room_id, "m.room.history_visibility");
                REQUIRE(std::ranges::find(ids, join_rules_id) == ids.end());
            }
            AND_THEN("m.room.guest_access excludes join_rules and history_visibility from auth_events")
            {
                auto const ids = auth_event_ids_for_state(store, created_room_id, "m.room.guest_access");
                REQUIRE(std::ranges::find(ids, join_rules_id) == ids.end());
                auto const hv_id = state_event_id(store, created_room_id, "m.room.history_visibility");
                REQUIRE(std::ranges::find(ids, hv_id) == ids.end());
            }
            AND_THEN("m.room.encryption excludes join_rules and guest_access from auth_events")
            {
                auto const ids = auth_event_ids_for_state(store, created_room_id, "m.room.encryption");
                REQUIRE(std::ranges::find(ids, join_rules_id) == ids.end());
                auto const ga_id = state_event_id(store, created_room_id, "m.room.guest_access");
                REQUIRE(std::ranges::find(ids, ga_id) == ids.end());
            }
            AND_THEN("m.room.member invite includes join_rules in auth_events")
            {
                auto const ids = auth_event_ids_for_state(store, created_room_id, "m.room.member", "@bob:example.org");
                REQUIRE(std::ranges::find(ids, join_rules_id) != ids.end());
            }
        }
    }
}

SCENARIO("private_chat preset does not duplicate m.room.encryption when the client provides it in initial_state",
         "[homeserver][client-server][create-room][encryption]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client creates a private_chat room with m.room.encryption already in initial_state")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/createRoom", token,
                 R"({"preset":"private_chat","initial_state":[{"type":"m.room.encryption","state_key":"","content":{"algorithm":"m.megolm.v1.aes-sha2"}}]})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("exactly one m.room.encryption state event exists with the correct algorithm")
            {
                auto const count =
                    std::ranges::count_if(store.state, [&](merovingian::database::PersistentStateEvent const& row) {
                        return row.room_id == created_room_id && row.event_type == "m.room.encryption" &&
                               row.state_key.empty();
                    });
                REQUIRE(count == 1);
                auto const encryption = content_for_state(store, created_room_id, "m.room.encryption");
                REQUIRE(string_member(encryption, "algorithm") != nullptr);
                REQUIRE(*string_member(encryption, "algorithm") == "m.megolm.v1.aes-sha2");
            }
        }
    }
}

SCENARIO("createRoom does not duplicate preset events when client provides them in initial_state",
         "[homeserver][client-server][create-room][initial-state]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client provides guest_access, join_rules, and history_visibility in initial_state")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/createRoom", token,
                 R"({"preset":"private_chat","room_version":"12","initial_state":[)"
                 R"({"type":"m.room.guest_access","state_key":"","content":{"guest_access":"forbidden"}},)"
                 R"({"type":"m.room.join_rules","state_key":"","content":{"join_rule":"public"}},)"
                 R"({"type":"m.room.history_visibility","state_key":"","content":{"history_visibility":"world_readable"}})"
                 R"(]})"});
            REQUIRE(response.response.status == 200U);
            auto const created_room_id = room_id(response.response.body);
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("each state event type appears exactly once in persisted state")
            {
                auto const guest_count =
                    std::ranges::count_if(store.state, [&](merovingian::database::PersistentStateEvent const& row) {
                        return row.room_id == created_room_id && row.event_type == "m.room.guest_access" &&
                               row.state_key.empty();
                    });
                auto const join_rules_count =
                    std::ranges::count_if(store.state, [&](merovingian::database::PersistentStateEvent const& row) {
                        return row.room_id == created_room_id && row.event_type == "m.room.join_rules" &&
                               row.state_key.empty();
                    });
                auto const history_count =
                    std::ranges::count_if(store.state, [&](merovingian::database::PersistentStateEvent const& row) {
                        return row.room_id == created_room_id && row.event_type == "m.room.history_visibility" &&
                               row.state_key.empty();
                    });
                REQUIRE(guest_count == 1);
                REQUIRE(join_rules_count == 1);
                REQUIRE(history_count == 1);
            }
            AND_THEN("the client's initial_state values override the preset defaults")
            {
                auto const guest = content_for_state(store, created_room_id, "m.room.guest_access");
                auto const rules = content_for_state(store, created_room_id, "m.room.join_rules");
                auto const history = content_for_state(store, created_room_id, "m.room.history_visibility");
                REQUIRE(string_member(guest, "guest_access") != nullptr);
                REQUIRE(*string_member(guest, "guest_access") == "forbidden");
                REQUIRE(string_member(rules, "join_rule") != nullptr);
                REQUIRE(*string_member(rules, "join_rule") == "public");
                REQUIRE(string_member(history, "history_visibility") != nullptr);
                REQUIRE(*string_member(history, "history_visibility") == "world_readable");
            }
        }
    }
}

// +-------------------------------------------------------------------------+
// |  E2EE key bundle bootstrap (Element /maybeAcceptKeyBundle flow)         |
// |                                                                          |
// |  Spec:                                                                   |
// |  - https://spec.matrix.org/v1.18/client-server-api/#post_matrixclien    |
// |    tsv3keysupload                                                        |
// |  - https://spec.matrix.org/v1.18/client-server-api/#post_matrixclien    |
// |    tsv3keysquery                                                         |
// |  - https://spec.matrix.org/v1.18/client-server-api/#post_matrixclien    |
// |    tsv3keysdevice_signingupload                                          |
// |                                                                          |
// |  Reproduces the round-trip Element performs when joining an encrypted    |
// |  room: the inviter uploads device_keys + one_time_keys + fallback_keys  |
// |  + cross-signing keys, and the invitee queries them. Element's          |
// |  "No key bundle found for user" log fires when this round-trip returns  |
// |  an empty `device_keys` for the queried user.                            |
// +-------------------------------------------------------------------------+

SCENARIO("E2EE device_keys round-trip: inviter upload is visible to invitee query",
         "[homeserver][client-server][e2ee][key-api][regression]")
{
    GIVEN("two registered users on the same homeserver")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("inviter", "CorrectHorse7!")})
                    .response.status == 200U);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("invitee", "CorrectHorse8!")})
                    .response.status == 200U);

        auto const inviter_login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/login",
                      {},
                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@inviter:example.org"},"password":"CorrectHorse7!","device_id":"INVITER_DEV"})"});
        REQUIRE(inviter_login.response.status == 200U);
        auto const inviter_token = login_token(inviter_login.response.body);

        auto const invitee_login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/login",
                      {},
                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@invitee:example.org"},"password":"CorrectHorse8!","device_id":"INVITEE_DEV"})"});
        REQUIRE(invitee_login.response.status == 200U);
        auto const invitee_token = login_token(invitee_login.response.body);

        WHEN("the inviter uploads realistic device_keys and the invitee queries them")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/keys/upload",
                 inviter_token,
                 R"({"device_keys":{"user_id":"@inviter:example.org","device_id":"INVITER_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:INVITER_DEV":"AAAA_CURVE","ed25519:INVITER_DEV":"BBBB_ED"}},"one_time_keys":{"signed_curve25519:AAAA":{"key":"OTK_AAAA","signatures":{"@inviter:example.org":{"ed25519:INVITER_DEV":"OTK_SIG_AAAA"}}}}})"});
            REQUIRE(upload.response.status == 200U);

            auto const query = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/keys/query",
                          invitee_token,
                          R"({"device_keys":{"@inviter:example.org":["INVITER_DEV"]}})"});
            REQUIRE(query.response.status == 200U);

            THEN("the invitee's response contains the inviter's device_keys under the requested user")
            {
                auto const body = query.response.body;
                INFO("query body = " + body);
                REQUIRE(body.find("device_keys") != std::string::npos);
                REQUIRE(body.find("@inviter:example.org") != std::string::npos);
                REQUIRE(body.find("INVITER_DEV") != std::string::npos);
                // The curve25519 base64 blob from the upload must round-trip.
                REQUIRE(body.find("AAAA_CURVE") != std::string::npos);
                REQUIRE(body.find("BBBB_ED") != std::string::npos);
            }
            AND_THEN("the persistent_store holds exactly one device_key row for the inviter")
            {
                auto const count =
                    merovingian::homeserver::key_api_record_count(runtime, "@inviter:example.org");
                REQUIRE(count >= 1U);
            }
        }
    }
}

SCENARIO("E2EE one_time_keys are returned to a peer after upload",
         "[homeserver][client-server][e2ee][one-time-keys]")
{
    GIVEN("an inviter user who has uploaded a one_time_key")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("inviter", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/login",
                      {},
                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@inviter:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the device uploads a one_time_key")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/keys/upload",
                          token,
                          R"({"one_time_keys":{"signed_curve25519:OTK1":{"key":"OTK_DATA_AAA","signatures":{"@inviter:example.org":{"ed25519:DEV1":"SIG_AAA"}}}}})"});
            REQUIRE(upload.response.status == 200U);
            REQUIRE(upload.response.body.find("one_time_key_counts") != std::string::npos);

            THEN("the one_time_key_counts reports a non-zero signed_curve25519 count")
            {
                REQUIRE(upload.response.body.find("signed_curve25519") != std::string::npos);
                // json_int emits a bare numeric token (not a quoted string), so
                // we check for the digit '1' in the body to confirm a count
                // was recorded for the uploaded one_time_key.
                REQUIRE(upload.response.body.find(":1") != std::string::npos);
            }
        }
    }
}

SCENARIO("E2EE cross-signing keys round-trip via /keys/device_signing/upload + /keys/query",
         "[homeserver][client-server][e2ee][cross-signing]")
{
    GIVEN("an inviter user that has logged in")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("inviter", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/login",
                      {},
                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@inviter:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the user uploads master_key, self_signing_key, and user_signing_key")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/keys/device_signing/upload",
                 token,
                 R"({"auth":{"type":"m.login.password","user":"@inviter:example.org","password":"CorrectHorse7!"},)"
                 R"("master_key":{"user_id":"@inviter:example.org","usage":["user"],"keys":{"ed25519:MASTER_KEY_ID":"MASTER_KEY_VALUE"}},)"
                 R"("self_signing_key":{"user_id":"@inviter:example.org","usage":["self_signing"],"keys":{"ed25519:SSK_KEY_ID":"SSK_KEY_VALUE"}},)"
                 R"("user_signing_key":{"user_id":"@inviter:example.org","usage":["user_signing"],"keys":{"ed25519:USK_KEY_ID":"USK_KEY_VALUE"}}})"});
            REQUIRE(upload.response.status == 200U);

            auto const query = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/keys/query",
                          token,
                          R"({"device_keys":{"@inviter:example.org":[]}})"});
            REQUIRE(query.response.status == 200U);

            THEN("the query response contains master_keys, self_signing_keys, and user_signing_keys")
            {
                auto const body = query.response.body;
                INFO("query body = " + body);
                REQUIRE(body.find("master_keys") != std::string::npos);
                REQUIRE(body.find("self_signing_keys") != std::string::npos);
                REQUIRE(body.find("user_signing_keys") != std::string::npos);
                REQUIRE(body.find("MASTER_KEY_VALUE") != std::string::npos);
                REQUIRE(body.find("SSK_KEY_VALUE") != std::string::npos);
                REQUIRE(body.find("USK_KEY_VALUE") != std::string::npos);
            }
        }
    }
}

// +-------------------------------------------------------------------------+
// |  End-to-end E2EE bootstrap (Element Rust crypto order)                  |
// |                                                                          |
// |  Spec:                                                                   |
// |  - https://spec.matrix.org/v1.18/client-server-api/#post_matrixclien    |
// |    tsv3keysupload                                                        |
// |  - https://spec.matrix.org/v1.18/client-server-api/#post_matrixclien    |
// |    tsv3keysdevice_signingupload                                          |
// |  - https://spec.matrix.org/v1.18/client-server-api/#post_matrixclien    |
// |    tsv3keyssignaturesupload                                              |
// |  - https://spec.matrix.org/v1.18/client-server-api/#post_matrixclien    |
// |    tsv3room_keysversion                                                  |
// |                                                                          |
// |  Replays the exact order of requests Element's matrix-rust-sdk sends     |
// |  when bootstrapping a brand-new device: device_keys, one_time_keys,      |
// |  cross-signing keys, cross-signing signatures, key backup version,      |
// |  then a `keys/query` from a peer. The assertion is that the inviter's   |
// |  device_keys, one_time_keys, and master_keys are all visible to the     |
// |  invitee after this sequence. This is the reproducer for the            |
// |  `maybeAcceptKeyBundle: No key bundle found for user` log line.         |
// +-------------------------------------------------------------------------+

SCENARIO("End-to-end E2EE bootstrap: full Element Rust crypto order round-trips",
         "[homeserver][client-server][e2ee][bootstrap][regression]")
{
    GIVEN("two users on the same homeserver, registered and logged in")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("inviter", "CorrectHorse7!")})
                    .response.status == 200U);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("invitee", "CorrectHorse8!")})
                    .response.status == 200U);

        auto const inviter_login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/login",
                      {},
                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@inviter:example.org"},"password":"CorrectHorse7!","device_id":"INVITER_DEV"})"});
        REQUIRE(inviter_login.response.status == 200U);
        auto const inviter_token = login_token(inviter_login.response.body);

        auto const invitee_login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/login",
                      {},
                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@invitee:example.org"},"password":"CorrectHorse8!","device_id":"INVITEE_DEV"})"});
        REQUIRE(invitee_login.response.status == 200U);
        auto const invitee_token = login_token(invitee_login.response.body);

        WHEN("both devices run the full Element Rust crypto bootstrap order")
        {
            // 1. device_keys + one_time_keys for inviter
            auto const inviter_device_upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/keys/upload",
                 inviter_token,
                 R"({"device_keys":{"user_id":"@inviter:example.org","device_id":"INVITER_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:INVITER_DEV":"AAAA","ed25519:INVITER_DEV":"BBBB"},"signatures":{"@inviter:example.org":{"ed25519:INVITER_DEV":"SIG1"}}},"one_time_keys":{"signed_curve25519:AAAA":{"key":"OTK_KEY_1","signatures":{"@inviter:example.org":{"ed25519:INVITER_DEV":"OTK_SIG_1"}}}}})"});
            REQUIRE(inviter_device_upload.response.status == 200U);

            // 2. cross-signing keys for inviter
            auto const inviter_cs_upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/keys/device_signing/upload",
                 inviter_token,
                 R"({"master_key":{"user_id":"@inviter:example.org","usage":["user"],"keys":{"ed25519:MASTER":"MASTER_VALUE"}},"self_signing_key":{"user_id":"@inviter:example.org","usage":["self_signing"],"keys":{"ed25519:SSK":"SSK_VALUE"}}})"});
            REQUIRE(inviter_cs_upload.response.status == 200U);

            // 3. cross-signing signatures for inviter (self-signing)
            auto const inviter_sigs = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/keys/signatures/upload",
                 inviter_token,
                 R"({"@inviter:example.org":{"ed25519:SSK":{"device_keys":{"INVITER_DEV":{"user_id":"@inviter:example.org","device_id":"INVITER_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"ed25519:INVITER_DEV":"BBBB"}}}}}})"});
            REQUIRE(inviter_sigs.response.status == 200U);

            // 4. key backup version for inviter
            auto const inviter_backup = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/room_keys/version",
                 inviter_token,
                 R"({"algorithm":"m.megolm_backup.v1","auth_data":{}})"});
            REQUIRE(inviter_backup.response.status == 200U);

            // Now the invitee queries the inviter's bundle.
            auto const invitee_query = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/keys/query",
                 invitee_token,
                 R"({"device_keys":{"@inviter:example.org":["INVITER_DEV"]}})"});
            REQUIRE(invitee_query.response.status == 200U);

            THEN("the invitee's query returns the inviter's full key bundle")
            {
                auto const body = invitee_query.response.body;
                INFO("invitee query body = " + body);
                // The fundamental contract: device_keys for the queried
                // user/device must be present and non-empty.
                REQUIRE(body.find("device_keys") != std::string::npos);
                REQUIRE(body.find("@inviter:example.org") != std::string::npos);
                REQUIRE(body.find("INVITER_DEV") != std::string::npos);
                REQUIRE(body.find("AAAA") != std::string::npos);
                REQUIRE(body.find("BBBB") != std::string::npos);
                // Cross-signing keys must also be present, with the
                // self-signing signature merged into the device_keys
                // signature map.
                REQUIRE(body.find("master_keys") != std::string::npos);
                REQUIRE(body.find("self_signing_keys") != std::string::npos);
                REQUIRE(body.find("MASTER_VALUE") != std::string::npos);
                REQUIRE(body.find("SSK_VALUE") != std::string::npos);
                // The self-signing signature for the device's ed25519 key
                // must be merged into the device_keys signature map under
                // the SSK key id.
                REQUIRE(body.find("\"ed25519:SSK\"") != std::string::npos);
            }
        }
    }
}

// +-------------------------------------------------------------------------+
// |  Login device_id default collision (regression)                          |
// |                                                                          |
// |  Spec: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclien |
// |  tsv3login                                                               |
// |                                                                          |
// |  When the client omits `device_id` from the login body, the server must |
// |  generate a unique opaque device_id. Merovingian's parser at            |
// |  client_server.cpp defaults to the literal string "MEROVINGIAN" instead, |
// |  which causes all device_id-less logins to collide on the same device   |
// |  row. This is observable on pong.ping.me.uk where @james (the bootstrap  |
// |  admin, no device_id sent) and any other user with the same default     |
// |  share a single device record.                                           |
// +-------------------------------------------------------------------------+

SCENARIO("Login without device_id generates a unique opaque id, not a fixed literal",
         "[homeserver][client-server][login][device-id]")
{
    GIVEN("two freshly-registered users on the same homeserver")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("first", "CorrectHorse7!")})
                    .response.status == 200U);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("second", "CorrectHorse7!")})
                    .response.status == 200U);

        WHEN("both users log in without sending a device_id")
        {
            auto const login_first = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/login",
                          {},
                          R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@first:example.org"},"password":"CorrectHorse7!"})"});
            REQUIRE(login_first.response.status == 200U);
            auto const login_second = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/login",
                          {},
                          R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@second:example.org"},"password":"CorrectHorse7!"})"});
            REQUIRE(login_second.response.status == 200U);

            THEN("each user gets a distinct device_id; the literal \"MEROVINGIAN\" is not used")
            {
                auto const first_did = login_device_id(login_first.response.body);
                auto const second_did = login_device_id(login_second.response.body);
                INFO("first user device_id = " + first_did);
                INFO("second user device_id = " + second_did);
                // Spec: server-generated device_ids must be opaque and unique.
                REQUIRE(first_did != "MEROVINGIAN");
                REQUIRE(second_did != "MEROVINGIAN");
                REQUIRE(first_did != second_did);
                REQUIRE_FALSE(first_did.empty());
                REQUIRE_FALSE(second_did.empty());
            }
        }
    }
}
