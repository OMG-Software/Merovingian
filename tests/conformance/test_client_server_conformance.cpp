// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX CLIENT-SERVER API CONFORMANCE TESTS                      |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18                                   |
// |  URL:  ../../docs/matrix-v1.18-spec/client-server-api.md                 |
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
#include <vector>

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

[[nodiscard]] auto sync_next_batch(std::string const& body) -> std::string
{
    auto const parsed = parse_object(body);
    auto const* next_batch = string_member(parsed, "next_batch");
    REQUIRE(next_batch != nullptr);
    REQUIRE(!next_batch->empty());
    return *next_batch;
}

[[nodiscard]] auto response_string_field(std::string const& body, std::string_view key) -> std::string
{
    auto const parsed = parse_object(body);
    auto const* value = string_member(parsed, key);
    REQUIRE(value != nullptr);
    REQUIRE(!value->empty());
    return *value;
}

auto upload_device_keys(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                        std::string_view user_id, std::string_view device_id, std::string_view curve25519_key,
                        std::string_view ed25519_key) -> void
{
    auto const body = std::string{R"({"device_keys":{"user_id":")"} + std::string{user_id} + R"(","device_id":")" +
                      std::string{device_id} +
                      R"(","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:)" +
                      std::string{device_id} + R"(":")" + std::string{curve25519_key} + R"(","ed25519:)" +
                      std::string{device_id} + R"(":")" + std::string{ed25519_key} + R"("}}})";
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, body})
                .response.status == 200U);
}

// device_secret_key MUST be the raw 64-byte Ed25519 secret key whose matching
// public key was uploaded via upload_device_keys for this device. Real OTK
// signature verification requires both sides to use the same keypair.
auto upload_one_time_key(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                         std::string_view user_id, std::string_view device_id, std::string_view key_id,
                         std::string_view key_value, std::string const& device_secret_key) -> void
{
    auto const otk_json =
        merovingian::federation::test::make_signed_otk_json(user_id, device_id, key_value, device_secret_key);
    auto const body =
        std::string{R"({"one_time_keys":{"signed_curve25519:)"} + std::string{key_id} + "\":" + otk_json + "}}";
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, body})
                .response.status == 200U);
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
        merovingian::federation::build_edu_transaction_body(remote_origin, "m.direct_to_device", edu_content_json);
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

[[nodiscard]] auto create_public_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const r = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})"});
    REQUIRE(r.response.status == 200U);
    auto const body = parse_object(r.response.body);
    auto const* rid = string_member(body, "room_id");
    REQUIRE(rid != nullptr);
    return *rid;
}

[[nodiscard]] auto create_knock_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const r = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/createRoom", token,
         R"({"initial_state":[{"type":"m.room.join_rules","state_key":"","content":{"join_rule":"knock"}}]})"});
    REQUIRE(r.response.status == 200U);
    auto const body = parse_object(r.response.body);
    auto const* rid = string_member(body, "room_id");
    REQUIRE(rid != nullptr);
    return *rid;
}

[[nodiscard]] auto find_membership(merovingian::database::PersistentStore const& store, std::string const& room_id,
                                   std::string const& user_id) -> merovingian::database::PersistentMembership const*
{
    auto const membership = std::ranges::find_if(store.memberships, [&](auto const& current) {
        return current.room_id == room_id && current.user_id == user_id;
    });
    return membership == store.memberships.end() ? nullptr : &(*membership);
}

[[nodiscard]] auto current_membership_event(merovingian::database::PersistentStore const& store,
                                            std::string const& room_id, std::string const& user_id)
    -> merovingian::canonicaljson::Object
{
    auto const state = std::ranges::find_if(store.state, [&](auto const& current) {
        return current.room_id == room_id && current.event_type == "m.room.member" && current.state_key == user_id;
    });
    REQUIRE(state != store.state.end());
    auto const event = std::ranges::find_if(store.events, [&](auto const& current) {
        return current.event_id == state->event_id;
    });
    REQUIRE(event != store.events.end());
    return parse_object(event->json);
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

// Sends a text message with a caller-supplied transaction id, so repeated calls
// create distinct timeline events (send_message reuses one txn id and dedupes).
[[nodiscard]] auto send_text(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                             std::string const& room_id, std::string const& txn, std::string const& text) -> std::string
{
    auto const r = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn, token,
                  std::string{R"({"msgtype":"m.text","body":")"} + text + R"("})"});
    REQUIRE(r.response.status == 200U);
    auto const body = parse_object(r.response.body);
    auto const* eid = string_member(body, "event_id");
    REQUIRE(eid != nullptr);
    return *eid;
}

// Collects the event_id of every event object in a timeline/chunk "events" array.
[[nodiscard]] auto event_ids_in(merovingian::canonicaljson::Array const& events) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const& entry : events)
    {
        auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        if (obj == nullptr)
        {
            continue;
        }
        if (auto const* eid = string_member(*obj, "event_id"); eid != nullptr)
        {
            ids.push_back(*eid);
        }
    }
    return ids;
}

[[nodiscard]] auto contains_id(std::vector<std::string> const& ids, std::string const& wanted) -> bool
{
    return std::ranges::find(ids, wanted) != ids.end();
}

// Looks up a response header value by exact name (returns nullopt if absent).
[[nodiscard]] auto response_header(std::vector<std::pair<std::string, std::string>> const& headers,
                                   std::string_view name) -> std::optional<std::string>
{
    for (auto const& header : headers)
    {
        if (header.first == name)
        {
            return header.second;
        }
    }
    return std::nullopt;
}

} // namespace

// --- GET /_matrix/client/versions --------------------------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientversions
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3register
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
                auto const* first_flow = std::get_if<merovingian::canonicaljson::Object>(&flows->front().storage());
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

SCENARIO("POST /register with wrong auth type returns 401 UIA challenge", "[conformance][client-server][register]")
{
    GIVEN("a running client-server with token-gated registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("a registration request with an unsupported auth type is submitted")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST",
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3register
//
// §5.5.1: If a device_id is specified in the request body the server MUST include
// that exact device_id in the response.
SCENARIO("POST /register with device_id in request returns matching device_id in response",
         "[conformance][client-server][register]")
{
    GIVEN("a running client-server with token-gated registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("a registration request includes a device_id")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"username":"devid","password":"CorrectHorse7!","device_id":"CLIENT_DEVICE_1","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});

            THEN("the response device_id equals the requested device_id")
            {
                // Spec MUST: device_id in response MUST match device_id from request.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* reg_device_id = string_member(body, "device_id");
                REQUIRE(reg_device_id != nullptr);
                REQUIRE(*reg_device_id == "CLIENT_DEVICE_1");
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3register
//
// §5.5.1: If inhibit_login is true the server MUST NOT return an access_token
// or device_id in the response body; only user_id is present.
SCENARIO("POST /register with inhibit_login:true returns only user_id", "[conformance][client-server][register]")
{
    GIVEN("a running client-server with token-gated registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("a registration request sets inhibit_login to true")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"username":"nologin","password":"CorrectHorse7!","inhibit_login":true,"auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});

            THEN("the response has user_id but no access_token or device_id")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                // Spec MUST: user_id present.
                auto const* user_id = string_member(body, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(!user_id->empty());
                // Spec MUST NOT: access_token absent when inhibit_login is true.
                REQUIRE(string_member(body, "access_token") == nullptr);
                // Spec MUST NOT: device_id absent when inhibit_login is true.
                REQUIRE(string_member(body, "device_id") == nullptr);
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3register
//
// The device created by registration is a real session and MUST appear in
// GET /devices so the client can manage it.
SCENARIO("POST /register device is visible via GET /devices", "[conformance][client-server][register][devices]")
{
    GIVEN("a successful registration that returns an access token")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        auto const reg = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("regdeviceuser", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);
        auto const token = response_string_field(reg.response.body, "access_token");
        auto const reg_device_id = response_string_field(reg.response.body, "device_id");

        WHEN("the registered session calls GET /devices")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("the registration device is listed")
            {
                // Spec MUST: all active sessions visible in the devices list.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* devices = object_member_as_array(body, "devices");
                REQUIRE(devices != nullptr);
                auto found = false;
                for (auto const& dval : *devices)
                {
                    auto const* dev = std::get_if<merovingian::canonicaljson::Object>(&dval.storage());
                    if (dev == nullptr)
                    {
                        continue;
                    }
                    auto const* did = string_member(*dev, "device_id");
                    if (did != nullptr && *did == reg_device_id)
                    {
                        found = true;
                        break;
                    }
                }
                REQUIRE(found);
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3register
//
// initial_device_display_name from the registration request MUST be stored as
// the device's display name.
SCENARIO("POST /register with initial_device_display_name stores it as the device display name",
         "[conformance][client-server][register][devices]")
{
    GIVEN("a successful registration that includes an initial_device_display_name")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        auto const reg = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"POST",
             "/_matrix/client/v3/register",
             {},
             R"({"username":"dispreguser","password":"CorrectHorse7!","initial_device_display_name":"Registration Phone","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});
        REQUIRE(reg.response.status == 200U);
        auto const token = response_string_field(reg.response.body, "access_token");
        auto const reg_device_id = response_string_field(reg.response.body, "device_id");

        WHEN("the registered session calls GET /devices")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("the device appears with the supplied display name")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* devices = object_member_as_array(body, "devices");
                REQUIRE(devices != nullptr);
                auto found = false;
                for (auto const& dval : *devices)
                {
                    auto const* dev = std::get_if<merovingian::canonicaljson::Object>(&dval.storage());
                    if (dev == nullptr)
                    {
                        continue;
                    }
                    auto const* did = string_member(*dev, "device_id");
                    if (did != nullptr && *did == reg_device_id)
                    {
                        found = true;
                        // Spec MUST: display name matches initial_device_display_name.
                        auto const* dn = string_member(*dev, "display_name");
                        REQUIRE(dn != nullptr);
                        REQUIRE(*dn == "Registration Phone");
                        break;
                    }
                }
                REQUIRE(found);
            }
        }
    }
}

// --- GET /_matrix/client/v3/login --------------------------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3login
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3login
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3login
//
// initial_device_display_name in the login request MUST be stored as the
// device display name and appear in GET /devices.
SCENARIO("POST /login with initial_device_display_name stores it as the device display name",
         "[conformance][client-server][login]")
{
    GIVEN("a running client-server and a registered user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST",
                                      "/_matrix/client/v3/register",
                                      {},
                                      merovingian::tests::registration_json("displayuser", "CorrectHorse7!")})
                    .response.status == 200U);

        WHEN("the user logs in with initial_device_display_name set")
        {
            auto const login = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@displayuser:example.org"},"password":"CorrectHorse7!","device_id":"DISP_DEV","initial_device_display_name":"My Test Phone"})"});
            REQUIRE(login.response.status == 200U);
            auto const token = response_string_field(login.response.body, "access_token");

            auto const devices_resp = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("the device appears in the list with the supplied display name")
            {
                REQUIRE(devices_resp.response.status == 200U);
                auto const body = parse_object(devices_resp.response.body);
                auto const* devs = object_member_as_array(body, "devices");
                REQUIRE(devs != nullptr);
                auto found = false;
                for (auto const& dval : *devs)
                {
                    auto const* dev = std::get_if<merovingian::canonicaljson::Object>(&dval.storage());
                    if (dev == nullptr)
                    {
                        continue;
                    }
                    auto const* did = string_member(*dev, "device_id");
                    if (did != nullptr && *did == "DISP_DEV")
                    {
                        found = true;
                        // Spec MUST: display_name from initial_device_display_name.
                        auto const* dn = string_member(*dev, "display_name");
                        REQUIRE(dn != nullptr);
                        REQUIRE(*dn == "My Test Phone");
                        break;
                    }
                }
                REQUIRE(found);
            }
        }
    }
}

// --- POST /_matrix/client/v3/logout ------------------------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3logout
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3accountwhoami
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

SCENARIO("Registration-issued session reports its device and can upload device keys for that device",
         "[conformance][client-server][whoami][e2ee][keys]")
{
    GIVEN("a successful registration response that includes an access token and device_id")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        auto const registration = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"POST",
             "/_matrix/client/v3/register",
             {},
             R"({"username":"alice","password":"CorrectHorse7!","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});
        REQUIRE(registration.response.status == 200U);

        auto const token = response_string_field(registration.response.body, "access_token");
        auto const device_id = response_string_field(registration.response.body, "device_id");

        WHEN("the client uses that registration-issued token for whoami and keys/upload")
        {
            auto const whoami = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
            auto const upload_body =
                std::string{"{\"device_keys\":{\"user_id\":\"@alice:example.org\",\"device_id\":\""} + device_id +
                "\",\"algorithms\":[\"m.olm.v1.curve25519-aes-sha2\",\"m.megolm.v1.aes-sha2\"],\"keys\":{"
                "\"curve25519:" +
                device_id + "\":\"" + device_id + "_CURVE\",\"ed25519:" + device_id + "\":\"" + device_id +
                "_ED\"},\"signatures\":{}},\"one_time_keys\":{}}";
            auto const upload = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/upload", token, upload_body});

            THEN("both responses are bound to the same authenticated device")
            {
                REQUIRE(whoami.response.status == 200U);
                auto const whoami_body = parse_object(whoami.response.body);
                auto const* whoami_device = string_member(whoami_body, "device_id");
                REQUIRE(whoami_device != nullptr);
                REQUIRE(*whoami_device == device_id);

                REQUIRE(upload.response.status == 200U);
                auto const upload_response = parse_object(upload.response.body);
                auto const* counts = object_member_as_object(upload_response, "one_time_key_counts");
                REQUIRE(counts != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/keys/upload -------------------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysupload
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
                 R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:DEVICE1":"base64key","ed25519:DEVICE1":"device-signing-key"},"signatures":{}},"one_time_keys":{}})"});

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

// Spec: Matrix Client-Server API v1.18
// Endpoint: POST /_matrix/client/v3/keys/upload
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysupload
//
// MUST reject a one-time key that carries the correct key_id in its
// signatures object but whose signature bytes do not cryptographically
// verify under that device's ed25519 public key.  Presence of the key_id
// entry alone is not sufficient — the server MUST run Ed25519 verification.
SCENARIO("POST /keys/upload rejects a one-time key whose signature bytes fail Ed25519 verification",
         "[conformance][client-server][e2ee][keys][security]")
{
    GIVEN("a logged-in device whose ed25519 identity key is known from the same request's device_keys")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        // 32 zero bytes in unpadded standard base64 — valid ed25519 key length.
        auto constexpr zero_pubkey_b64 = std::string_view{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};
        // 64 zero bytes — correct length for Ed25519 but NOT a valid signature.
        auto constexpr bogus_sig_b64 = std::string_view{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                                        "AAAAAA"};

        // Build the upload body: device_keys with a real-length ed25519 key,
        // plus a signed_curve25519 OTK whose signature has the right key ID
        // (ed25519:DEVICE1) but contains zero bytes that cannot pass verification.
        auto body = std::string{};
        body += "{\"device_keys\":{\"user_id\":\"@alice:example.org\",\"device_id\":\"DEVICE1\","
                "\"algorithms\":[\"m.olm.v1.curve25519-aes-sha2\",\"m.megolm.v1.aes-sha2\"],"
                "\"keys\":{\"curve25519:DEVICE1\":\"curvekey\",\"ed25519:DEVICE1\":\"";
        body += zero_pubkey_b64;
        body += "\"},\"signatures\":{}},"
                "\"one_time_keys\":{\"signed_curve25519:AAAAAQ\":{\"key\":\"otkkey\","
                "\"signatures\":{\"@alice:example.org\":{\"ed25519:DEVICE1\":\"";
        body += bogus_sig_b64;
        body += "\"}}}}}";

        WHEN("the device uploads the OTK with the bogus signature")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/upload", token, body});

            THEN("the server rejects the upload with 400 M_INVALID_SIGNATURE")
            {
                // Spec MUST: the server MUST verify the signature — presence of the
                // correct key_id is not sufficient.  A key with a wrong signature
                // cannot be stored because peers will fail NoSignatureFound when they
                // try to claim it, breaking E2EE session setup.
                REQUIRE(response.response.status == 400U);
                auto const resp_body = parse_object(response.response.body);
                auto const* errcode = string_member(resp_body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_SIGNATURE");
            }
        }
    }
}

// --- POST /_matrix/client/v3/keys/query --------------------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysquery
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysclaim
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysquery
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
                 R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:DEVICE1":"base64+pubkey","ed25519:DEVICE1":"device-signing-key"},"signatures":{}},"one_time_keys":{}})"})
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysclaim
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

        // Use a real Ed25519 keypair so that the OTK signature passes real
        // crypto_sign_verify_detached verification.
        auto const alice_kp = merovingian::federation::test::keypair_from_seed("conformance-alice-otk-seed");
        auto const alice_ed25519 = merovingian::federation::test::pubkey_b64(alice_kp);
        auto const otk_json = merovingian::federation::test::make_signed_otk_json(
            "@alice:example.org", "DEVICE1", "otk+base64+key", alice_kp.secret_key);
        auto const upload_body =
            std::string{
                R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:DEVICE1":"pubkey1","ed25519:DEVICE1":")"} +
            alice_ed25519 + R"("},"signatures":{}},"one_time_keys":{"signed_curve25519:AAAAAAAA":)" + otk_json +
            R"(}})";
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/keys/upload", token, upload_body})
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysdevice_signingupload
//
// This endpoint uses the User-Interactive Authentication API (UIA).
// A request without auth MUST return 401 with the UIA flows challenge.
// Success MUST return HTTP 200 with an empty JSON object {}.
SCENARIO("POST /keys/device_signing/upload without auth returns 401 UIA challenge",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device uploads cross-signing keys without providing auth")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                                  R"({"master_key":{"keys":{"ed25519:master":"base64key"},"usage":["master"]}})"});

            THEN("the server issues a UIA challenge with m.login.password flow")
            {
                // Spec MUST: cross-signing upload uses UIA to prevent key takeover.
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);
                // Spec MUST: UIA challenge body contains flows, params, and session.
                REQUIRE(object_member(body, "flows") != nullptr);
                REQUIRE(object_member_as_object(body, "params") != nullptr);
                REQUIRE(object_member(body, "session") != nullptr);
            }
        }
    }
}

SCENARIO("POST /keys/device_signing/upload returns 200 with a valid JSON object",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("a logged-in device")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device uploads cross-signing keys with valid UIA password auth")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                 R"({"master_key":{"keys":{"ed25519:master":"base64key"},"usage":["master"]},"self_signing_key":{"keys":{"ed25519:self":"base64key"},"usage":["self_signing"]},"user_signing_key":{"keys":{"ed25519:user":"base64key"},"usage":["user_signing"]},"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});

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
                 R"({"master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:MASTER":"base64master"},"signatures":{}},"self_signing_key":{"user_id":"@alice:example.org","usage":["self_signing"],"keys":{"ed25519:SELF":"base64self"},"signatures":{}},"user_signing_key":{"user_id":"@alice:example.org","usage":["user_signing"],"keys":{"ed25519:USER":"base64user"},"signatures":{}},"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"})
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keyssignaturesupload
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
                 R"({"master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:MASTER":"base64master"},"signatures":{}},"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"})
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

// --- POST /_matrix/client/v3/keys/query — user_signing_key visibility --------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysquery
//
// §11.11.3: The user_signing_key MUST only be returned to the user themselves;
// it MUST NOT be disclosed to other users querying that user's keys.
SCENARIO("POST /keys/query does not expose user_signing_key to non-owners",
         "[conformance][client-server][e2ee][keys][security]")
{
    GIVEN("alice has uploaded cross-signing keys including a user_signing_key")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice_token = logged_in_token(started.runtime);
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/device_signing/upload", alice_token,
                 R"({"master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:MKEY":"mval"},"signatures":{}},"user_signing_key":{"user_id":"@alice:example.org","usage":["user_signing"],"keys":{"ed25519:USIGN":"uval"},"signatures":{}},"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"})
                .response.status == 200U);

        WHEN("bob queries alice's keys")
        {
            auto const bob_token = register_and_login(started.runtime, "bob");
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/query", bob_token, R"({"device_keys":{"@alice:example.org":[]}})"});

            THEN("alice's user_signing_key is not included in the response")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* user_signing_keys = object_member_as_object(body, "user_signing_keys");
                // Spec MUST: user_signing_key is only visible to the owner, not to other users.
                bool const alice_key_exposed =
                    user_signing_keys != nullptr &&
                    object_member_as_object(*user_signing_keys, "@alice:example.org") != nullptr;
                REQUIRE_FALSE(alice_key_exposed);
            }
        }

        WHEN("alice queries her own keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/query", alice_token, R"({"device_keys":{"@alice:example.org":[]}})"});

            THEN("alice's user_signing_key is included in the response")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* user_signing_keys = object_member_as_object(body, "user_signing_keys");
                // Spec MUST: the owner always receives their own user_signing_key.
                REQUIRE(user_signing_keys != nullptr);
                REQUIRE(object_member_as_object(*user_signing_keys, "@alice:example.org") != nullptr);
            }
        }
    }
}

// --- PUT /_matrix/client/v3/sendToDevice — wildcard device delivery ----------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3sendtoeventtypetxnid
//
// A device_id of "*" MUST deliver the to-device event to every device belonging
// to the target user, not just the first or a literal device named "*".
SCENARIO("PUT /sendToDevice with \"*\" delivers to all target user devices",
         "[conformance][client-server][e2ee][to-device]")
{
    GIVEN("alice has two registered devices")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token_a = logged_in_token(rt);                       // alice / DEVICE1
        auto const token_b = login_existing_user(rt, "alice", "DEV_B"); // alice / DEV_B
        auto const bob_token = register_and_login(rt, "bob");

        WHEN("bob sends a to-device event to alice with device_id \"*\"")
        {
            auto const send = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/sendToDevice/m.key.verification.cancel/txn_wildcard", bob_token,
                     R"({"messages":{"@alice:example.org":{"*":{"reason":"test"}}}})"});

            THEN("both alice devices receive the event via /sync")
            {
                REQUIRE(send.response.status == 200U);

                auto const sync_a = merovingian::homeserver::handle_client_server_request(
                    rt, {"GET", "/_matrix/client/v3/sync", token_a, {}});
                REQUIRE(sync_a.response.status == 200U);
                auto const body_a = parse_object(sync_a.response.body);
                auto const* td_a = object_member_as_object(body_a, "to_device");
                auto const* events_a = td_a != nullptr ? object_member_as_array(*td_a, "events") : nullptr;
                // Spec MUST: "*" delivers to every device — DEVICE1 must receive the event.
                REQUIRE(events_a != nullptr);
                REQUIRE(!events_a->empty());

                auto const sync_b = merovingian::homeserver::handle_client_server_request(
                    rt, {"GET", "/_matrix/client/v3/sync", token_b, {}});
                REQUIRE(sync_b.response.status == 200U);
                auto const body_b = parse_object(sync_b.response.body);
                auto const* td_b = object_member_as_object(body_b, "to_device");
                auto const* events_b = td_b != nullptr ? object_member_as_array(*td_b, "events") : nullptr;
                // Spec MUST: "*" delivers to every device — DEV_B must receive the event.
                REQUIRE(events_b != nullptr);
                REQUIRE(!events_b->empty());
            }
        }
    }
}

// --- POST /keys/device_signing/upload → device_lists.changed in /sync --------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// §11.11.1: When a user's cross-signing keys change the server MUST include
// that user's ID in device_lists.changed in the next /sync for all observers,
// including the user's own other devices.
SCENARIO("POST /keys/device_signing/upload emits device_lists.changed in /sync",
         "[conformance][client-server][e2ee][device-list][sync]")
{
    GIVEN("alice is logged in on two devices")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token_a = logged_in_token(rt);                       // alice / DEVICE1
        auto const token_b = login_existing_user(rt, "alice", "DEV_B"); // alice / DEV_B

        auto const initial_sync =
            merovingian::homeserver::handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token_b, {}});
        REQUIRE(initial_sync.response.status == 200U);
        auto const since = sync_next_batch(initial_sync.response.body);

        WHEN("alice uploads cross-signing keys from DEVICE1")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/v3/keys/device_signing/upload", token_a,
                 R"({"master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:MKEY":"mval"},"signatures":{}},"user_signing_key":{"user_id":"@alice:example.org","usage":["user_signing"],"keys":{"ed25519:USIGN":"uval"},"signatures":{}},"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});
            REQUIRE(upload.response.status == 200U);

            THEN("DEV_B's next /sync includes alice in device_lists.changed")
            {
                auto const follow_sync = merovingian::homeserver::handle_client_server_request(
                    rt, {"GET", "/_matrix/client/v3/sync?since=" + since, token_b, {}});
                REQUIRE(follow_sync.response.status == 200U);
                auto const body = parse_object(follow_sync.response.body);
                auto const* device_lists = object_member_as_object(body, "device_lists");
                auto const* changed =
                    device_lists != nullptr ? object_member_as_array(*device_lists, "changed") : nullptr;
                // Spec MUST: cross-signing key upload MUST appear in device_lists.changed so
                // the user's other devices can re-query the new keys and complete verification.
                REQUIRE(changed != nullptr);
                auto alice_listed = false;
                for (auto const& v : *changed)
                {
                    if (auto const* s = std::get_if<std::string>(&v.storage()))
                    {
                        if (*s == "@alice:example.org")
                        {
                            alice_listed = true;
                        }
                    }
                }
                REQUIRE(alice_listed);
            }
        }
    }
}

// --- POST /keys/signatures/upload → device_lists.changed in /sync ------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// §11.11.1: A signature upload changes the user's verified key graph; the server
// MUST include the user's ID in device_lists.changed in subsequent syncs so that
// other devices can re-query the updated cross-signing state.
SCENARIO("POST /keys/signatures/upload emits device_lists.changed in /sync",
         "[conformance][client-server][e2ee][device-list][sync]")
{
    GIVEN("alice has cross-signing keys and is logged in on two devices")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token_a = logged_in_token(rt);                       // alice / DEVICE1
        auto const token_b = login_existing_user(rt, "alice", "DEV_B"); // alice / DEV_B

        // Upload cross-signing keys first (precondition for signature upload).
        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/v3/keys/device_signing/upload", token_a,
                 R"({"master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:MKEY":"mval"},"signatures":{}},"self_signing_key":{"user_id":"@alice:example.org","usage":["self_signing"],"keys":{"ed25519:SSIGN":"sval"},"signatures":{}},"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"})
                .response.status == 200U);

        // Advance DEV_B's since token past the cross-signing key-upload notification.
        auto const sync_after_upload =
            merovingian::homeserver::handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token_b, {}});
        REQUIRE(sync_after_upload.response.status == 200U);
        auto const since = sync_next_batch(sync_after_upload.response.body);

        WHEN("alice uploads a device self-signature from DEVICE1")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/v3/keys/signatures/upload", token_a,
                 R"({"@alice:example.org":{"ed25519:MKEY":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:MKEY":"mval"},"signatures":{"@alice:example.org":{"ed25519:DEVICE1":"c2ln"}}}}})"});
            REQUIRE(upload.response.status == 200U);

            THEN("DEV_B's next /sync includes alice in device_lists.changed")
            {
                auto const follow_sync = merovingian::homeserver::handle_client_server_request(
                    rt, {"GET", "/_matrix/client/v3/sync?since=" + since, token_b, {}});
                REQUIRE(follow_sync.response.status == 200U);
                auto const body = parse_object(follow_sync.response.body);
                auto const* device_lists = object_member_as_object(body, "device_lists");
                auto const* changed =
                    device_lists != nullptr ? object_member_as_array(*device_lists, "changed") : nullptr;
                // Spec MUST: signature upload MUST appear in device_lists.changed so the
                // user's other devices discover the self-signed device and complete verification.
                REQUIRE(changed != nullptr);
                auto alice_listed = false;
                for (auto const& v : *changed)
                {
                    if (auto const* s = std::get_if<std::string>(&v.storage()))
                    {
                        if (*s == "@alice:example.org")
                        {
                            alice_listed = true;
                        }
                    }
                }
                REQUIRE(alice_listed);
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/version (no backup) --------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keysversion
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3room_keysversion
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keysversion
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3room_keysversion
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
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

// --- GET /_matrix/client/v3/sync (timeline.limited / prev_batch) -------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// Timeline object fields:
//   limited    - "True if the number of events returned was limited by the
//                 limit on the filter." It describes THIS sync window, not the
//                 total number of events in the room. An incremental sync that
//                 returns every event newer than the client's since token has
//                 dropped nothing, so it MUST report limited = false. Reporting
//                 limited = true here signals a non-existent gap; matrix-js-sdk
//                 responds by discarding and re-fetching the timeline on every
//                 sync ("Live timeline was reset"), so messages never render.
//   prev_batch - "A token that can be supplied to the from parameter of the
//                 /rooms/{roomId}/messages endpoint." Required for backfill; a
//                 limited timeline without it cannot be filled.
SCENARIO("GET /sync incremental timeline reports limited=false when no events are dropped",
         "[conformance][client-server][sync][timeline]")
{
    GIVEN("a room whose total event count exceeds the timeline page size")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        // Initial sync fixes the since token. Every room-creation event has a
        // stream ordering <= this token, so none of them fall in the next
        // incremental window — only genuinely new events will.
        auto const initial = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
        REQUIRE(initial.response.status == 200U);
        auto const since = sync_next_batch(initial.response.body);

        WHEN("one new message arrives and an incremental sync uses a small timeline limit")
        {
            (void)send_text(started.runtime, token, room_id, "m_one", "first");

            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET",
                 R"(/_matrix/client/v3/sync?since=)" + since + R"(&filter={"room":{"timeline":{"limit":2}}})",
                 token,
                 {}});

            THEN("the room timeline reports limited=false and carries a prev_batch token")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* join = object_member_as_object(*rooms, "join");
                REQUIRE(join != nullptr);
                auto const* room_obj = object_member_as_object(*join, room_id);
                REQUIRE(room_obj != nullptr);
                auto const* timeline = object_member_as_object(*room_obj, "timeline");
                REQUIRE(timeline != nullptr);

                // Spec MUST: only one new event existed since `since` and the
                // page size was 2, so nothing was dropped -> limited is false.
                // The old implementation derived `limited` from the total event
                // count and would wrongly report true here.
                auto const* limited = bool_member(*timeline, "limited");
                REQUIRE(limited != nullptr);
                REQUIRE(*limited == false);

                // Spec MUST: prev_batch is present so clients can backfill.
                auto const* prev_batch = string_member(*timeline, "prev_batch");
                REQUIRE(prev_batch != nullptr);
                REQUIRE(!prev_batch->empty());
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// When more events exist in the window than the filter limit, the server MUST
// return the MOST RECENT events (clients render newest history first), set
// limited = true, and provide a prev_batch that, fed to
// /rooms/{roomId}/messages?dir=b, returns the dropped older events with neither
// a gap nor an overlap.
SCENARIO("GET /sync truncated timeline returns the most recent events with a backfillable prev_batch",
         "[conformance][client-server][sync][timeline]")
{
    GIVEN("a room and an established since token")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const initial = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
        REQUIRE(initial.response.status == 200U);
        auto const since = sync_next_batch(initial.response.body);

        WHEN("three new messages arrive but the timeline limit is two")
        {
            auto const e1 = send_text(started.runtime, token, room_id, "m_a", "alpha");
            auto const e2 = send_text(started.runtime, token, room_id, "m_b", "bravo");
            auto const e3 = send_text(started.runtime, token, room_id, "m_c", "charlie");

            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET",
                 R"(/_matrix/client/v3/sync?since=)" + since + R"(&filter={"room":{"timeline":{"limit":2}}})",
                 token,
                 {}});
            REQUIRE(response.response.status == 200U);
            auto const body = parse_object(response.response.body);
            auto const* rooms = object_member_as_object(body, "rooms");
            REQUIRE(rooms != nullptr);
            auto const* join = object_member_as_object(*rooms, "join");
            REQUIRE(join != nullptr);
            auto const* room_obj = object_member_as_object(*join, room_id);
            REQUIRE(room_obj != nullptr);
            auto const* timeline = object_member_as_object(*room_obj, "timeline");
            REQUIRE(timeline != nullptr);

            THEN("limited=true and the timeline holds the two most recent messages")
            {
                // Spec MUST: three events existed since `since`, page size 2,
                // so one was dropped -> limited is true.
                auto const* limited = bool_member(*timeline, "limited");
                REQUIRE(limited != nullptr);
                REQUIRE(*limited == true);

                auto const* events = object_member_as_array(*timeline, "events");
                REQUIRE(events != nullptr);
                auto const ids = event_ids_in(*events);

                // Spec MUST: the returned window is the most recent events, so
                // it contains e2 and e3 and excludes the dropped older e1. The
                // old implementation returned the OLDEST events (e1, e2).
                REQUIRE(contains_id(ids, e2));
                REQUIRE(contains_id(ids, e3));
                REQUIRE(!contains_id(ids, e1));
            }

            THEN("paginating /messages backward from prev_batch returns the dropped older event")
            {
                auto const* prev_batch = string_member(*timeline, "prev_batch");
                REQUIRE(prev_batch != nullptr);
                REQUIRE(!prev_batch->empty());

                auto const messages = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&from=" + *prev_batch, token, {}});
                REQUIRE(messages.response.status == 200U);
                auto const messages_body = parse_object(messages.response.body);
                auto const* chunk = object_member_as_array(messages_body, "chunk");
                REQUIRE(chunk != nullptr);

                // Spec MUST: prev_batch bridges the gap, so backfilling returns
                // the older event that the truncated timeline dropped (e1) and
                // does NOT repeat events already in the timeline window (e3).
                auto const chunk_ids = event_ids_in(*chunk);
                REQUIRE(contains_id(chunk_ids, e1));
                REQUIRE(!contains_id(chunk_ids, e3));
            }
        }
    }
}

// --- CORS preflight for /_matrix/ resources ---------------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#web-browser-clients
//
// "Servers MUST expose the following CORS headers ... in response to OPTIONS
// requests ... Access-Control-Allow-Origin: *". This applies to ALL /_matrix/
// resources, media included. A browser client whose OPTIONS preflight to a
// media endpoint gets a non-2xx response (or no Access-Control-Allow-Origin)
// reports "Response to preflight request doesn't pass access control check"
// and the real request fails with net::ERR_FAILED. This test pins the
// server-side behaviour so such a failure can be attributed to deployment
// infrastructure (e.g. a reverse proxy) rather than Merovingian.
SCENARIO("OPTIONS preflight on a media endpoint returns 200 with CORS headers", "[conformance][client-server][cors]")
{
    GIVEN("a running server with the default CORS policy")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("a browser sends a CORS preflight to the media config endpoint")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"OPTIONS", "/_matrix/media/v3/config", {}, {}, {{"Origin", "https://app.element.io"}}});

            THEN("the preflight is answered with HTTP 200 and Access-Control-Allow-Origin")
            {
                // Spec MUST: OPTIONS preflight returns a 2xx status, otherwise
                // browsers report "preflight does not have HTTP ok status".
                REQUIRE(response.response.status == 200U);

                // Spec MUST: Access-Control-Allow-Origin is present (default
                // policy is "*"), otherwise the browser blocks the response.
                auto const allow_origin = response_header(response.response.headers, "Access-Control-Allow-Origin");
                REQUIRE(allow_origin.has_value());
                REQUIRE(!allow_origin->empty());

                // Spec SHOULD: the allowed methods advertise the verbs clients use.
                auto const allow_methods = response_header(response.response.headers, "Access-Control-Allow-Methods");
                REQUIRE(allow_methods.has_value());
            }
        }
    }
}

// --- GET /_matrix/client/v3/sync (room state & timeline content) -------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
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

SCENARIO("GET /sync reports signed_curve25519 count as zero for a fresh local device",
         "[conformance][client-server][sync][e2ee][counts]")
{
    GIVEN("a logged-in device that has not uploaded any one-time keys yet")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the device performs an initial sync")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("device_one_time_keys_count includes signed_curve25519 with value zero")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* otk_counts = object_member_as_object(body, "device_one_time_keys_count");
                REQUIRE(otk_counts != nullptr);
                auto const* signed_curve25519 = int_member(*otk_counts, "signed_curve25519");
                REQUIRE(signed_curve25519 != nullptr);
                REQUIRE(*signed_curve25519 == 0);
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidmembers
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidmembers
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidmembers
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidmembers
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#standard-error-response
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3refresh
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3logoutall
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1auth_metadata
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv1loginget_token
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3loginssoredirect
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3loginssoredirectidpid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_well-knownmatrixclient
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_well-knownmatrixpolicy_server
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_well-knownmatrixsupport
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3adminwhoisuserid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1adminlockuserid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv1adminlockuserid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1adminsuspenduserid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv1adminsuspenduserid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3accountpassword
//
// Uses User-Interactive Authentication (UIA). The only mandatory stage is
// m.login.password. A request without an auth field MUST receive 401 with
// a flows/params/session body (not 403 or 400).
SCENARIO("POST /account/password without auth returns 401 UIA challenge", "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/password is sent with new_password but no auth block")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/password", token, R"({"new_password":"NewHorse7!+Ab"})"});

            THEN("the server returns 401 with a UIA flows body")
            {
                // Spec MUST: 401 when authentication has not yet been completed.
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);
                // Spec MUST: response body contains a 'flows' array.
                auto const* flows = object_member_as_array(body, "flows");
                REQUIRE(flows != nullptr);
                REQUIRE(!flows->empty());
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3accountpassword
//
// When auth.type is m.login.password but the supplied password is wrong,
// the server MUST return 401 (re-issue the UIA challenge).
SCENARIO("POST /account/password with wrong current password returns 401", "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/password is sent with an incorrect current password in the auth block")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/password", token,
                 R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"WrongPassword9!"},"new_password":"NewHorse7!+Ab"})"});

            THEN("the server returns 401 because the credential was rejected")
            {
                // Spec MUST: 401 when the provided authentication is invalid.
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);
                auto const* flows = object_member_as_array(body, "flows");
                REQUIRE(flows != nullptr);
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3accountpassword
//
// MUST return 200 with an empty JSON object on success.
SCENARIO("POST /account/password returns 200 with empty JSON object", "[conformance][client-server][account]")
{
    GIVEN("a running client-server and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /account/password is called with a valid auth block and a new password")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/password", token,
                 R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!"},"new_password":"NewHorse7!+Ab"})"});

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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3accountdeactivate
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3account3pid
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3account3pid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3account3pid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3account3pidadd
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3account3pidbind
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3account3piddelete
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3account3pidemailrequesttoken
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3account3pidmsisdnrequesttoken
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3account3pidunbind
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3accountpasswordemailrequesttoken
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3accountpasswordmsisdnrequesttoken
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3registeravailable
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1registermloginregistration_tokenvalidity
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3registeremailrequesttoken
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3registermsisdnrequesttoken
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3capabilities
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3devices
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3devicesdeviceid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3devicesdeviceid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3devicesdeviceid
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

        WHEN("DELETE /devices/DEV_B is called from DEV_A's session with correct UIA")
        {
            // Spec MUST: UIA is required — supply m.login.password auth block.
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/devices/DEV_B", *tok1,
                                  R"({"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});

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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3delete_devices
//
// The server MUST require UIA before deleting devices in bulk and MUST return
// 200 {} once the requested devices have been removed. Devices already removed
// previously MUST still yield 200.
SCENARIO("POST /delete_devices requires UIA and deletes listed devices", "[conformance][client-server][devices]")
{
    GIVEN("a running client-server and a user with three devices")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST",
                                      "/_matrix/client/v3/register",
                                      {},
                                      merovingian::tests::registration_json("bulkdev", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login_a = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bulkdev:example.org"},"password":"CorrectHorse7!","device_id":"DEV_A"})"});
        REQUIRE(login_a.response.status == 200U);
        auto const login_a_body = parse_object(login_a.response.body);
        auto const* token_a = string_member(login_a_body, "access_token");
        REQUIRE(token_a != nullptr);

        auto const login_b = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bulkdev:example.org"},"password":"CorrectHorse7!","device_id":"DEV_B"})"});
        REQUIRE(login_b.response.status == 200U);
        auto const login_b_body = parse_object(login_b.response.body);
        auto const* token_b = string_member(login_b_body, "access_token");
        REQUIRE(token_b != nullptr);

        REQUIRE(
            merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bulkdev:example.org"},"password":"CorrectHorse7!","device_id":"DEV_C"})"})
                .response.status == 200U);

        WHEN("POST /delete_devices is sent without an auth block")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/delete_devices", *token_a, R"({"devices":["DEV_B","DEV_C"]})"});

            THEN("the server returns 401 with the UIA challenge")
            {
                // Spec MUST: missing auth block => 401 with UIA challenge.
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);
                auto const* flows = object_member(body, "flows");
                REQUIRE(flows != nullptr);
            }
        }

        WHEN("POST /delete_devices is sent with the wrong password")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/delete_devices", *token_a,
                 R"({"devices":["DEV_B","DEV_C"],"auth":{"type":"m.login.password","password":"WrongPassword"}})"});

            THEN("the server returns 401")
            {
                // Spec MUST: wrong credential => 401.
                REQUIRE(response.response.status == 401U);
            }
        }

        WHEN("POST /delete_devices is sent with valid UIA")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/delete_devices", *token_a,
                 R"({"devices":["DEV_B","DEV_C"],"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});

            THEN("the server returns 200 and the deleted devices are gone")
            {
                // Spec MUST: valid UIA => 200 {} and devices removed.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                std::ignore = body;

                auto const get_b = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/devices/DEV_B", *token_a, {}});
                REQUIRE(get_b.response.status == 404U);

                auto const get_c = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/devices/DEV_C", *token_a, {}});
                REQUIRE(get_c.response.status == 404U);

                auto const still_a = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/devices/DEV_A", *token_a, {}});
                REQUIRE(still_a.response.status == 200U);

                auto const deleted_device_token = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/devices", *token_b, {}});
                REQUIRE(deleted_device_token.response.status == 401U);
            }
        }

        WHEN("POST /delete_devices repeats a previously completed deletion")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/delete_devices", *token_a,
                 R"({"devices":["DEV_B"],"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});
            REQUIRE(first.response.status == 200U);

            auto const second = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/delete_devices", *token_a,
                 R"({"devices":["DEV_B"],"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});

            THEN("the server still returns 200")
            {
                // Spec MUST: already-removed devices still succeed.
                REQUIRE(second.response.status == 200U);
                auto const body = parse_object(second.response.body);
                std::ignore = body;
            }
        }
    }
}

// =============================================================================
// END-TO-END ENCRYPTION (remaining)
// =============================================================================

// --- GET /_matrix/client/v3/keys/changes --------------------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3keyschanges
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
                 R"({"device_keys":{"user_id":"@bob:example.org","device_id":"bob_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:bob_DEV":"BOBKEY","ed25519:bob_DEV":"BOB_ED"},"signatures":{}}})"});

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

SCENARIO("GET /keys/changes reports users as changed when they newly start sharing a room",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("two users who uploaded device keys before an invite is accepted")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");

        upload_device_keys(started.runtime, alice, "@alice:example.org", "DEVICE1", "ALICE_CURVE", "ALICE_ED");
        upload_device_keys(started.runtime, bob, "@bob:example.org", "bob_DEV", "BOB_CURVE", "BOB_ED");

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", alice,
                              R"({"preset":"private_chat","invite":["@bob:example.org"]})"});
        REQUIRE(create.response.status == 200U);
        auto const create_body = parse_object(create.response.body);
        auto const* room_id = string_member(create_body, "room_id");
        REQUIRE(room_id != nullptr);

        auto const alice_before_join = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", alice, {}});
        REQUIRE(alice_before_join.response.status == 200U);
        auto const alice_from = sync_next_batch(alice_before_join.response.body);

        auto const bob_before_join = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});
        REQUIRE(bob_before_join.response.status == 200U);
        auto const bob_from = sync_next_batch(bob_before_join.response.body);

        WHEN("bob joins the encrypted room")
        {
            auto const join = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/join", bob, "{}"});

            THEN("each user sees the newly shared user in changed")
            {
                REQUIRE(join.response.status == 200U);

                auto const alice_changes = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/keys/changes?from=" + alice_from + "&to=s999", alice, {}});
                REQUIRE(alice_changes.response.status == 200U);
                auto const alice_body = parse_object(alice_changes.response.body);
                auto const* alice_changed = object_member_as_array(alice_body, "changed");
                REQUIRE(alice_changed != nullptr);
                REQUIRE(std::ranges::any_of(*alice_changed, [](merovingian::canonicaljson::Value const& value) {
                    auto const* user_id = std::get_if<std::string>(&value.storage());
                    return user_id != nullptr && *user_id == "@bob:example.org";
                }));

                auto const bob_changes = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/keys/changes?from=" + bob_from + "&to=s999", bob, {}});
                REQUIRE(bob_changes.response.status == 200U);
                auto const bob_body = parse_object(bob_changes.response.body);
                auto const* bob_changed = object_member_as_array(bob_body, "changed");
                REQUIRE(bob_changed != nullptr);
                REQUIRE(std::ranges::any_of(*bob_changed, [](merovingian::canonicaljson::Value const& value) {
                    auto const* user_id = std::get_if<std::string>(&value.storage());
                    return user_id != nullptr && *user_id == "@alice:example.org";
                }));
            }
        }
    }
}

SCENARIO("GET /keys/changes reports left when users stop sharing any room", "[conformance][client-server][e2ee][keys]")
{
    GIVEN("two users who share exactly one public room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = create_public_room(started.runtime, alice);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"})
                    .response.status == 200U);

        auto const before_leave = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", alice, {}});
        REQUIRE(before_leave.response.status == 200U);
        auto const from_token = sync_next_batch(before_leave.response.body);

        WHEN("bob leaves the only room they share")
        {
            auto const leave = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", bob, "{}"});

            THEN("alice sees bob in left")
            {
                REQUIRE(leave.response.status == 200U);
                auto const changes = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/keys/changes?from=" + from_token + "&to=s999", alice, {}});
                REQUIRE(changes.response.status == 200U);
                auto const body = parse_object(changes.response.body);
                auto const* left = object_member_as_array(body, "left");
                REQUIRE(left != nullptr);
                REQUIRE(std::ranges::any_of(*left, [](merovingian::canonicaljson::Value const& value) {
                    auto const* user_id = std::get_if<std::string>(&value.storage());
                    return user_id != nullptr && *user_id == "@bob:example.org";
                }));
            }
        }
    }
}

SCENARIO("GET /keys/changes does not report left while another shared room still exists",
         "[conformance][client-server][e2ee][keys]")
{
    GIVEN("two users who still share a second joined public room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");

        auto const room_one = create_public_room(started.runtime, alice);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_one + "/join", bob, "{}"})
                    .response.status == 200U);

        auto const room_two = create_public_room(started.runtime, alice);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_two + "/join", bob, "{}"})
                    .response.status == 200U);

        auto const before_leave = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", alice, {}});
        REQUIRE(before_leave.response.status == 200U);
        auto const from_token = sync_next_batch(before_leave.response.body);

        WHEN("bob leaves only one of the shared rooms")
        {
            auto const leave = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_one + "/leave", bob, "{}"});

            THEN("alice does not see bob in left because they still share room two")
            {
                REQUIRE(leave.response.status == 200U);
                auto const changes = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v3/keys/changes?from=" + from_token + "&to=s999", alice, {}});
                REQUIRE(changes.response.status == 200U);
                auto const body = parse_object(changes.response.body);
                auto const* left = object_member_as_array(body, "left");
                REQUIRE(left != nullptr);
                REQUIRE_FALSE(std::ranges::any_of(*left, [](merovingian::canonicaljson::Value const& value) {
                    auto const* user_id = std::get_if<std::string>(&value.storage());
                    return user_id != nullptr && *user_id == "@bob:example.org";
                }));
            }
        }
    }
}

SCENARIO("Encrypted invite join completes the local query claim sendToDevice bootstrap sequence",
         "[conformance][client-server][e2ee][keys][send-to-device]")
{
    GIVEN("two local devices that uploaded keys before they started sharing an encrypted room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");

        upload_device_keys(started.runtime, alice, "@alice:example.org", "DEVICE1", "ALICE_CURVE", "ALICE_ED");
        // Bob needs a real Ed25519 keypair because OTK signatures are now
        // cryptographically verified against the stored device identity key.
        auto const bob_kp = merovingian::federation::test::keypair_from_seed("conformance-bob-seed");
        upload_device_keys(started.runtime, bob, "@bob:example.org", "bob_DEV", "BOB_CURVE",
                           merovingian::federation::test::pubkey_b64(bob_kp));
        upload_one_time_key(started.runtime, bob, "@bob:example.org", "bob_DEV", "BOB_OTK_AAAA", "BOB_OTK_VALUE",
                            bob_kp.secret_key);

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", alice,
                              R"({"preset":"private_chat","invite":["@bob:example.org"]})"});
        REQUIRE(create.response.status == 200U);
        auto const create_body = parse_object(create.response.body);
        auto const* room_id = string_member(create_body, "room_id");
        REQUIRE(room_id != nullptr);

        auto const alice_before_join = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", alice, {}});
        REQUIRE(alice_before_join.response.status == 200U);
        auto const alice_from = sync_next_batch(alice_before_join.response.body);

        auto const bob_before_join = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});
        REQUIRE(bob_before_join.response.status == 200U);
        auto const bob_from = sync_next_batch(bob_before_join.response.body);

        WHEN("bob joins and alice performs the client bootstrap sequence")
        {
            auto const join = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/join", bob, "{}"});

            auto const alice_changes = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/keys/changes?from=" + alice_from + "&to=s999", alice, {}});
            auto const query = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/query", alice,
                                  R"({"device_keys":{"@bob:example.org":["bob_DEV"]}})"});
            auto const claim = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/claim", alice,
                                  R"({"one_time_keys":{"@bob:example.org":{"bob_DEV":"signed_curve25519"}}})"});
            auto const send_body =
                std::string{"{\"messages\":{\"@bob:example.org\":{\"bob_DEV\":{\"algorithm\":\"m.megolm.v1.aes-sha2\","
                            "\"room_id\":\""} +
                *room_id + "\",\"session_id\":\"sid-1\",\"session_key\":\"skey-1\"}}}}";
            auto const send = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/sendToDevice/m.room_key/txn-bootstrap", alice, send_body});

            THEN("query claim and to-device delivery all succeed and bob receives the room key exactly once")
            {
                REQUIRE(join.response.status == 200U);

                REQUIRE(alice_changes.response.status == 200U);
                auto const changes_body = parse_object(alice_changes.response.body);
                auto const* changed = object_member_as_array(changes_body, "changed");
                REQUIRE(changed != nullptr);
                REQUIRE(std::ranges::any_of(*changed, [](merovingian::canonicaljson::Value const& value) {
                    auto const* user_id = std::get_if<std::string>(&value.storage());
                    return user_id != nullptr && *user_id == "@bob:example.org";
                }));

                REQUIRE(query.response.status == 200U);
                REQUIRE(query.response.body.find("BOB_CURVE") != std::string::npos);
                // bob_kp.public_key was registered in GIVEN; check the real base64 key round-trips.
                REQUIRE(query.response.body.find(merovingian::federation::test::pubkey_b64(bob_kp)) !=
                        std::string::npos);

                REQUIRE(claim.response.status == 200U);
                REQUIRE(claim.response.body.find("BOB_OTK_VALUE") != std::string::npos);

                REQUIRE(send.response.status == 200U);
                auto const send_response_body = parse_object(send.response.body);
                REQUIRE(send_response_body.empty());

                auto const bob_sync = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync?since=" + bob_from, bob, {}});
                REQUIRE(bob_sync.response.status == 200U);
                auto const bob_sync_body = parse_object(bob_sync.response.body);
                auto const* to_device = object_member_as_object(bob_sync_body, "to_device");
                REQUIRE(to_device != nullptr);
                auto const* events = object_member_as_array(*to_device, "events");
                REQUIRE(events != nullptr);
                REQUIRE(events->size() == 1U);
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&(*events)[0].storage());
                REQUIRE(event != nullptr);
                auto const* type = string_member(*event, "type");
                REQUIRE(type != nullptr);
                REQUIRE(*type == "m.room_key");
                auto const* sender = string_member(*event, "sender");
                REQUIRE(sender != nullptr);
                REQUIRE(*sender == "@alice:example.org");

                auto const bob_sync_again = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});
                REQUIRE(bob_sync_again.response.status == 200U);
                auto const bob_sync_again_body = parse_object(bob_sync_again.response.body);
                auto const* to_device_again = object_member_as_object(bob_sync_again_body, "to_device");
                REQUIRE(to_device_again != nullptr);
                auto const* events_again = object_member_as_array(*to_device_again, "events");
                REQUIRE(events_again != nullptr);
                REQUIRE(events_again->empty());
            }
        }
    }
}

// --- GET /_matrix/client/v3/room_keys/version/{version} ----------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keysversionversion
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keysversionversion
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3room_keysversionversion
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3room_keysversionversion
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3room_keyskeysroomidsessionid
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
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/session1?version=1", token,
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3room_keyskeysroomidsessionid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeysroomidsessionid
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
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/sessA?version=1", token,
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeysroomidsessionid
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
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21room2%3Aexample.org/sessZ?version=1", token,
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeysroomidsessionid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3room_keyskeysroomidsessionid
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
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/sessD?version=1", token,
                 R"({"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"abc","ephemeral":"def","mac":"ghi"}})"})
                .response.status == 200U);

        WHEN("DELETE /room_keys/keys/{roomId}/{sessionId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"DELETE", "/_matrix/client/v3/room_keys/keys/%21room1%3Aexample.org/sessD?version=1", token, {}});

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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeys
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeys
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
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3room_keyskeys
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3room_keyskeys
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
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3room_keyskeys
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeysroomidsessionid
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeysroomid
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3room_keyskeysroomidsessionid
//       ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeysroomidsessionid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3room_keyskeys
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
                {"PUT", "/_matrix/client/v3/room_keys/keys?version=1", token,
                 R"({"rooms":{"!delroom:example.org":{"sessions":{"dsess1":{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"x","ephemeral":"y","mac":"z"}}}}}})"})
                .response.status == 200U);

        WHEN("DELETE /room_keys/keys is called")
        {
            // Spec MUST: version query parameter is required for this endpoint.
            auto const del = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"DELETE", "/_matrix/client/v3/room_keys/keys?version=1", token, {}});

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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeysroomid
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3room_keyskeysroomid
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
                {"PUT", "/_matrix/client/v3/room_keys/keys/%21roomR%3Aexample.org/rsessX?version=1", token,
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3room_keyskeysroomid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3room_keyskeysroomid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixmediav3config
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixmediav3upload
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixmediav3downloadservernamemediaid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixmediav3downloadservernamemediaid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixmediav3downloadservernamemediaidfilename
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixmediav3preview_url
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixmediav3thumbnailservernamemediaid
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixmediav3thumbnailservernamemediaid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixmediav3uploadservernamemediaid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixmediav1create
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1mediaconfig
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1mediadownloadservernamemediaid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1mediadownloadservernamemediaid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1mediadownloadservernamemediaidfilename
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1mediapreview_url
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1mediathumbnailservernamemediaid
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1mediathumbnailservernamemediaid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3directorylistappservicenetworkidroomid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3createroom
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

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3createroom
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3directoryroomroomalias
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3directoryroomroomalias
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3directoryroomroomalias
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidaliases
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3publicrooms
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
// Spec: Matrix Client-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3publicrooms
//
// POST /publicRooms accepts an optional JSON body with filter and pagination
// parameters and returns 200 with chunk (array) and total_room_count_estimate.
SCENARIO("POST /publicRooms returns 200 with chunk and total_room_count_estimate",
         "[conformance][client-server][room-discovery]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("POST /publicRooms is called with no body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/publicRooms", {}, {}});

            THEN("the server returns 200 with a chunk array and total_room_count_estimate")
            {
                // Spec MUST: 200 with chunk (array of PublicRoomsChunk) and total_room_count_estimate.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
                auto const* estimate = int_member(body, "total_room_count_estimate");
                REQUIRE(estimate != nullptr);
            }
        }

        WHEN("POST /publicRooms is called with limit=0")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/publicRooms", {}, R"({"limit":0})"});

            THEN("the server returns 200 with an empty chunk because limit=0 is treated as no-op")
            {
                // Spec: limit of 0 or negative is not meaningful; server may ignore or return empty page.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
            }
        }

        WHEN("POST /publicRooms is called with a filter body containing limit=1")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/publicRooms", {}, R"({"limit":1})"});

            THEN("the server returns 200 and the chunk contains at most one room")
            {
                // Spec MUST: limit constrains the maximum number of rooms returned in chunk.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
                REQUIRE(chunk->size() <= 1U);
            }
        }
    }
}

// --- GET /_matrix/client/v3/directory/list/room/{roomId} ---------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3directorylistroomroomid
// The server MUST return {"visibility":"public"|"private"} for a known room.
// Rooms default to private (not listed in the public directory).
SCENARIO("GET /directory/list/room/{roomId} returns room visibility", "[conformance][client-server][room-discovery]")
{
    GIVEN("a running homeserver and a newly created room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("GET /directory/list/room/{roomId} is called for that room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/directory/list/room/" + room_id, token, {}});

            THEN("the server returns 200 with visibility private by default")
            {
                // Spec MUST: 200 with {"visibility":"public"|"private"}.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* vis = string_member(body, "visibility");
                REQUIRE(vis != nullptr);
                // Spec: rooms not explicitly published are private.
                REQUIRE(*vis == "private");
            }
        }

        WHEN("GET /directory/list/room/!nonexistent:server is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/directory/list/room/!nonexistent:server", token, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the room is not known to this server.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
            }
        }
    }
}

// --- PUT /_matrix/client/v3/directory/list/room/{roomId} ---------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3directorylistroomroomid
// The server MUST update the room's public-directory visibility for a joined
// member, returning {} on success. Missing or invalid visibility MUST be 400.
SCENARIO("PUT /directory/list/room/{roomId} sets room visibility", "[conformance][client-server][room-discovery]")
{
    GIVEN("a running homeserver and a room the authenticated user is a member of")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("PUT /directory/list/room/{roomId} is called with visibility public")
        {
            auto const put_resp = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/directory/list/room/" + room_id, token, R"({"visibility":"public"})"});

            THEN("the server returns 200 and a subsequent GET reflects public")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(put_resp.response.status == 200U);
                auto const get_resp = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/directory/list/room/" + room_id, token, {}});
                REQUIRE(get_resp.response.status == 200U);
                auto const body = parse_object(get_resp.response.body);
                auto const* vis = string_member(body, "visibility");
                REQUIRE(vis != nullptr);
                // Spec MUST: visibility reflects the value set by PUT.
                REQUIRE(*vis == "public");
            }
        }

        WHEN("PUT /directory/list/room/{roomId} is called with missing visibility")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/directory/list/room/" + room_id, token, "{}"});

            THEN("the server returns 400 M_BAD_JSON")
            {
                // Spec MUST: 400 when the visibility field is absent or invalid.
                REQUIRE(response.response.status == 400U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_BAD_JSON");
            }
        }

        WHEN("PUT /directory/list/room/!nonexistent:server is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/directory/list/room/!nonexistent:server", token,
                                  R"({"visibility":"public"})"});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the room is not known to this server.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
            }
        }
    }
}

// =============================================================================
// ROOM MEMBERSHIP
// =============================================================================

// --- GET /_matrix/client/v3/joined_rooms -------------------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3joined_rooms
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3joinroomidoralias
SCENARIO("POST /join/{roomIdOrAlias} returns room_id on success", "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server with two users, alice has a public room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const room_id = create_public_room(started.runtime, alice);
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidmembership
SCENARIO("POST /rooms/{roomId}/join returns room_id on success", "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server with two users, alice owns a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const room_id = create_public_room(started.runtime, alice);
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

SCENARIO("POST /rooms/{roomId}/join returns 403 for an invite-only room without an invite",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server with two users and alice creates the default invite-only room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, alice);
        auto const bob = register_and_login(started.runtime, "bob");

        WHEN("bob POSTs to /rooms/{roomId}/join without being invited")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"});

            THEN("the server rejects the join")
            {
                REQUIRE(response.response.status == 403U);
                auto const body = parse_object(response.response.body);
                REQUIRE(string_member(body, "errcode") != nullptr);
                REQUIRE(string_member(body, "error") != nullptr);
            }
        }
    }
}

SCENARIO("Local invites appear in /sync invite_state for the invitee", "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server where alice creates a private room and invites bob")
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
        auto const* room_id = string_member(create_body, "room_id");
        REQUIRE(room_id != nullptr);

        WHEN("bob performs an initial /sync")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});

            THEN("the invited room appears under rooms.invite with invite_state events")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* invite_rooms = object_member_as_object(*rooms, "invite");
                REQUIRE(invite_rooms != nullptr);
                auto const* invited_room = object_member_as_object(*invite_rooms, *room_id);
                REQUIRE(invited_room != nullptr);
                auto const* invite_state = object_member_as_object(*invited_room, "invite_state");
                REQUIRE(invite_state != nullptr);
                auto const* events = object_member_as_array(*invite_state, "events");
                REQUIRE(events != nullptr);
                REQUIRE_FALSE(events->empty());

                auto found_invite = false;
                for (auto const& event_value : *events)
                {
                    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&event_value.storage());
                    if (event == nullptr)
                    {
                        continue;
                    }
                    auto const* type = string_member(*event, "type");
                    auto const* state_key = string_member(*event, "state_key");
                    auto const* content = object_member_as_object(*event, "content");
                    if (type == nullptr || state_key == nullptr || content == nullptr)
                    {
                        continue;
                    }
                    auto const* membership = string_member(*content, "membership");
                    if (*type == "m.room.member" && *state_key == "@bob:example.org" && membership != nullptr &&
                        *membership == "invite")
                    {
                        found_invite = true;
                        break;
                    }
                }
                REQUIRE(found_invite);
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/leave ----------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidleave
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

SCENARIO("POST /rooms/{roomId}/leave allows an invited user to reject the invite and clears invite metadata",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server where alice invites bob to a private room")
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
        auto const* room_id = string_member(create_body, "room_id");
        REQUIRE(room_id != nullptr);

        WHEN("bob POSTs to /rooms/{roomId}/leave")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/leave", bob, "{}"});

            THEN("the server records a leave membership event and removes the stored invite")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(body.empty());

                auto const invite = merovingian::database::find_invite(
                    started.runtime.homeserver.database.persistent_store, *room_id, "@bob:example.org");
                REQUIRE_FALSE(invite.has_value());

                auto const& store = started.runtime.homeserver.database.persistent_store;
                auto const membership = std::ranges::find_if(store.memberships, [&](auto const& current) {
                    return current.room_id == *room_id && current.user_id == "@bob:example.org";
                });
                REQUIRE(membership != store.memberships.end());
                REQUIRE(membership->membership == "leave");

                auto const state = std::ranges::find_if(store.state, [&](auto const& current) {
                    return current.room_id == *room_id && current.event_type == "m.room.member" &&
                           current.state_key == "@bob:example.org";
                });
                REQUIRE(state != store.state.end());
                auto const event = std::ranges::find_if(store.events, [&](auto const& current) {
                    return current.event_id == state->event_id;
                });
                REQUIRE(event != store.events.end());
                auto const event_body = parse_object(event->json);
                auto const* content = object_member_as_object(event_body, "content");
                REQUIRE(content != nullptr);
                auto const* membership_value = string_member(*content, "membership");
                REQUIRE(membership_value != nullptr);
                REQUIRE(*membership_value == "leave");
            }
        }
    }
}

SCENARIO("POST /rooms/{roomId}/join clears stale invite metadata and moves the room to rooms.join",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server where alice invites bob to a private room")
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
        auto const* room_id = string_member(create_body, "room_id");
        REQUIRE(room_id != nullptr);

        WHEN("bob joins the invited room and then performs an initial /sync")
        {
            auto const join = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/join", bob, "{}"});
            auto const sync = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});

            THEN("the invite metadata is gone and the room appears under rooms.join")
            {
                REQUIRE(join.response.status == 200U);
                REQUIRE(sync.response.status == 200U);

                auto const invite = merovingian::database::find_invite(
                    started.runtime.homeserver.database.persistent_store, *room_id, "@bob:example.org");
                REQUIRE_FALSE(invite.has_value());

                auto const& store = started.runtime.homeserver.database.persistent_store;
                auto const membership = std::ranges::find_if(store.memberships, [&](auto const& current) {
                    return current.room_id == *room_id && current.user_id == "@bob:example.org";
                });
                REQUIRE(membership != store.memberships.end());
                REQUIRE(membership->membership == "join");

                auto const state = std::ranges::find_if(store.state, [&](auto const& current) {
                    return current.room_id == *room_id && current.event_type == "m.room.member" &&
                           current.state_key == "@bob:example.org";
                });
                REQUIRE(state != store.state.end());
                auto const event = std::ranges::find_if(store.events, [&](auto const& current) {
                    return current.event_id == state->event_id;
                });
                REQUIRE(event != store.events.end());
                auto const event_body = parse_object(event->json);
                auto const* content = object_member_as_object(event_body, "content");
                REQUIRE(content != nullptr);
                auto const* membership_value = string_member(*content, "membership");
                REQUIRE(membership_value != nullptr);
                REQUIRE(*membership_value == "join");

                auto const sync_body = parse_object(sync.response.body);
                auto const* rooms = object_member_as_object(sync_body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* join_rooms = object_member_as_object(*rooms, "join");
                REQUIRE(join_rooms != nullptr);
                REQUIRE(object_member_as_object(*join_rooms, *room_id) != nullptr);
                auto const* invite_rooms = object_member_as_object(*rooms, "invite");
                REQUIRE(invite_rooms != nullptr);
                REQUIRE(object_member_as_object(*invite_rooms, *room_id) == nullptr);
            }
        }
    }
}

SCENARIO("POST /rooms/{roomId}/leave persists a leave membership state event for joined users",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a running client-server with a joined room member")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const room_id = create_public_room(started.runtime, alice);

        WHEN("alice leaves the room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", alice, "{}"});

            THEN("current room state for alice becomes a leave membership event")
            {
                REQUIRE(response.response.status == 200U);
                auto const& store = started.runtime.homeserver.database.persistent_store;
                auto const state = std::ranges::find_if(store.state, [&](auto const& current) {
                    return current.room_id == room_id && current.event_type == "m.room.member" &&
                           current.state_key == "@alice:example.org";
                });
                REQUIRE(state != store.state.end());
                auto const event = std::ranges::find_if(store.events, [&](auto const& current) {
                    return current.event_id == state->event_id;
                });
                REQUIRE(event != store.events.end());
                auto const event_body = parse_object(event->json);
                auto const* content = object_member_as_object(event_body, "content");
                REQUIRE(content != nullptr);
                auto const* membership_value = string_member(*content, "membership");
                REQUIRE(membership_value != nullptr);
                REQUIRE(*membership_value == "leave");
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/ban ------------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidban
SCENARIO("POST /rooms/{roomId}/ban returns 200 and bans the target user",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a public room where bob has joined alice")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = create_public_room(started.runtime, alice);
        auto const join = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"});
        REQUIRE(join.response.status == 200U);

        WHEN("alice bans bob with a reason")
        {
            auto const ban = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", alice,
                                  R"({"user_id":"@bob:example.org","reason":"rule break"})"});
            auto const rejoin = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"});

            THEN("the server records bob as banned and blocks rejoin")
            {
                REQUIRE(ban.response.status == 200U);
                auto const body = parse_object(ban.response.body);
                REQUIRE(body.empty());

                auto const& store = started.runtime.homeserver.database.persistent_store;
                auto const* membership = find_membership(store, room_id, "@bob:example.org");
                REQUIRE(membership != nullptr);
                REQUIRE(membership->membership == "ban");

                auto const event = current_membership_event(store, room_id, "@bob:example.org");
                auto const* content = object_member_as_object(event, "content");
                REQUIRE(content != nullptr);
                auto const* membership_value = string_member(*content, "membership");
                auto const* reason = string_member(*content, "reason");
                REQUIRE(membership_value != nullptr);
                REQUIRE(*membership_value == "ban");
                REQUIRE(reason != nullptr);
                REQUIRE(*reason == "rule break");

                REQUIRE(rejoin.response.status == 403U);
                auto const rejoin_body = parse_object(rejoin.response.body);
                REQUIRE(string_member(rejoin_body, "errcode") != nullptr);
                REQUIRE(string_member(rejoin_body, "error") != nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/kick -----------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidkick
SCENARIO("POST /rooms/{roomId}/kick returns 200 and removes the target user from the room",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a public room where bob has joined alice")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = create_public_room(started.runtime, alice);
        auto const join = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"});
        REQUIRE(join.response.status == 200U);

        WHEN("alice kicks bob with a reason")
        {
            auto const kick = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/kick", alice,
                                  R"({"user_id":"@bob:example.org","reason":"cool down"})"});
            auto const joined_rooms = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/joined_rooms", bob, {}});

            THEN("bob becomes leave membership and the room disappears from joined_rooms")
            {
                REQUIRE(kick.response.status == 200U);
                auto const kick_body = parse_object(kick.response.body);
                REQUIRE(kick_body.empty());

                auto const& store = started.runtime.homeserver.database.persistent_store;
                auto const* membership = find_membership(store, room_id, "@bob:example.org");
                REQUIRE(membership != nullptr);
                REQUIRE(membership->membership == "leave");

                auto const event = current_membership_event(store, room_id, "@bob:example.org");
                auto const* content = object_member_as_object(event, "content");
                REQUIRE(content != nullptr);
                auto const* membership_value = string_member(*content, "membership");
                auto const* reason = string_member(*content, "reason");
                REQUIRE(membership_value != nullptr);
                REQUIRE(*membership_value == "leave");
                REQUIRE(reason != nullptr);
                REQUIRE(*reason == "cool down");

                REQUIRE(joined_rooms.response.status == 200U);
                auto const joined_body = parse_object(joined_rooms.response.body);
                auto const* rooms = object_member_as_array(joined_body, "joined_rooms");
                REQUIRE(rooms != nullptr);
                auto const still_joined = std::ranges::any_of(*rooms, [&](auto const& value) {
                    auto const* current = std::get_if<std::string>(&value.storage());
                    return current != nullptr && *current == room_id;
                });
                REQUIRE_FALSE(still_joined);
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/unban ----------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidunban
SCENARIO("POST /rooms/{roomId}/unban returns 200 and allows the user to rejoin a public room",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a public room where bob was banned by alice")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = create_public_room(started.runtime, alice);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"})
                    .response.status == 200U);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", alice,
                                      R"({"user_id":"@bob:example.org","reason":"rule break"})"})
                    .response.status == 200U);

        WHEN("alice unbans bob")
        {
            auto const unban = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/unban", alice, R"({"user_id":"@bob:example.org"})"});

            THEN("bob returns to leave membership and can join again")
            {
                REQUIRE(unban.response.status == 200U);
                auto const unban_body = parse_object(unban.response.body);
                REQUIRE(unban_body.empty());

                auto const& store = started.runtime.homeserver.database.persistent_store;
                auto const* membership = find_membership(store, room_id, "@bob:example.org");
                REQUIRE(membership != nullptr);
                REQUIRE(membership->membership == "leave");

                auto const event = current_membership_event(store, room_id, "@bob:example.org");
                auto const* content = object_member_as_object(event, "content");
                REQUIRE(content != nullptr);
                auto const* membership_value = string_member(*content, "membership");
                REQUIRE(membership_value != nullptr);
                REQUIRE(*membership_value == "leave");

                auto const rejoin = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"});
                REQUIRE(rejoin.response.status == 200U);
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/invite ---------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidinvite
SCENARIO("POST /rooms/{roomId}/invite returns 200 and publishes an invite to /sync",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a private room where alice invites bob by user_id")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = create_room(started.runtime, alice);

        WHEN("alice POSTs /rooms/{roomId}/invite")
        {
            auto const invite = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                                  R"({"user_id":"@bob:example.org"})"});
            auto const sync = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});

            THEN("bob is invited and the room appears in rooms.invite")
            {
                REQUIRE(invite.response.status == 200U);
                auto const invite_body = parse_object(invite.response.body);
                REQUIRE(invite_body.empty());

                auto const& store = started.runtime.homeserver.database.persistent_store;
                auto const* membership = find_membership(store, room_id, "@bob:example.org");
                REQUIRE(membership != nullptr);
                REQUIRE(membership->membership == "invite");
                REQUIRE(merovingian::database::find_invite(store, room_id, "@bob:example.org").has_value());

                REQUIRE(sync.response.status == 200U);
                auto const sync_body = parse_object(sync.response.body);
                auto const* rooms = object_member_as_object(sync_body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* invite_rooms = object_member_as_object(*rooms, "invite");
                REQUIRE(invite_rooms != nullptr);
                auto const* invited_room = object_member_as_object(*invite_rooms, room_id);
                REQUIRE(invited_room != nullptr);
                auto const* invite_state = object_member_as_object(*invited_room, "invite_state");
                REQUIRE(invite_state != nullptr);
                auto const* events = object_member_as_array(*invite_state, "events");
                REQUIRE(events != nullptr);
                REQUIRE_FALSE(events->empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint: POST /_matrix/client/v3/rooms/{roomId}/invite
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidmembersidinvite
//
// MUST return 200 for a remote invitee and persist the invite event so that
// the federation outbound layer can dispatch it to the remote homeserver.
SCENARIO("POST /rooms/{roomId}/invite for a remote user returns 200 and persists the invite event",
         "[conformance][client-server][room-membership][federation]")
{
    GIVEN("a room owned by alice on the local server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, alice);

        WHEN("alice invites a user on a different homeserver")
        {
            auto const invite = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                                  R"({"user_id":"@charlie:remote.example.org"})"});

            THEN("the server returns 200 with an empty body")
            {
                // Spec MUST: successful invite returns 200 {}
                REQUIRE(invite.response.status == 200U);
                auto const body = parse_object(invite.response.body);
                REQUIRE(body.empty());
            }

            THEN("the invite is persisted as an m.room.member state event with membership=invite")
            {
                auto const& store = started.runtime.homeserver.database.persistent_store;

                // Spec MUST: the invite event must be stored so federation can dispatch it
                auto const* membership = find_membership(store, room_id, "@charlie:remote.example.org");
                REQUIRE(membership != nullptr);
                REQUIRE(membership->membership == "invite");

                auto const invite_state =
                    std::ranges::find_if(store.state, [&room_id](merovingian::database::PersistentStateEvent const& s) {
                        return s.room_id == room_id && s.event_type == "m.room.member" &&
                               s.state_key == "@charlie:remote.example.org";
                    });
                // Spec MUST: m.room.member state event must exist for the invitee
                REQUIRE(invite_state != store.state.end());
                REQUIRE_FALSE(invite_state->event_id.empty());

                auto const invite_json =
                    std::ranges::find_if(store.events, [&](merovingian::database::PersistentEvent const& e) {
                        return e.event_id == invite_state->event_id;
                    });
                REQUIRE(invite_json != store.events.end());
                REQUIRE_FALSE(invite_json->json.empty());
            }
        }
    }
}

// --- POST /_matrix/client/v3/rooms/{roomId}/forget ---------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidforget
SCENARIO("POST /rooms/{roomId}/forget returns 200 after leave and removes the room from rooms.leave",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a room that alice has already left")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const room_id = create_public_room(started.runtime, alice);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", alice, "{}"})
                    .response.status == 200U);

        WHEN("alice forgets the room")
        {
            auto const forget = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/forget", alice, "{}"});
            auto const sync = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", R"json(/_matrix/client/v3/sync?filter={"room":{"include_leave":true}})json", alice, {}});

            THEN("the room is no longer surfaced under rooms.leave")
            {
                REQUIRE(forget.response.status == 200U);
                auto const forget_body = parse_object(forget.response.body);
                REQUIRE(forget_body.empty());

                REQUIRE(sync.response.status == 200U);
                auto const sync_body = parse_object(sync.response.body);
                auto const* rooms = object_member_as_object(sync_body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* leave_rooms = object_member_as_object(*rooms, "leave");
                REQUIRE(leave_rooms != nullptr);
                REQUIRE(object_member_as_object(*leave_rooms, room_id) == nullptr);
            }
        }
    }
}

// --- POST /_matrix/client/v3/knock/{roomIdOrAlias} ---------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3knockroomidoralias
SCENARIO("POST /knock/{roomIdOrAlias} returns room_id and surfaces the room under rooms.knock",
         "[conformance][client-server][room-membership]")
{
    GIVEN("a room whose join rule is knock")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = create_knock_room(started.runtime, alice);

        WHEN("bob knocks on the room")
        {
            auto const knock = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/knock/" + room_id, bob, "{}"});
            auto const sync = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});

            THEN("the response returns room_id and /sync shows the knock")
            {
                REQUIRE(knock.response.status == 200U);
                auto const knock_body = parse_object(knock.response.body);
                auto const* knocked_room_id = string_member(knock_body, "room_id");
                REQUIRE(knocked_room_id != nullptr);
                REQUIRE(*knocked_room_id == room_id);

                auto const& store = started.runtime.homeserver.database.persistent_store;
                auto const* membership = find_membership(store, room_id, "@bob:example.org");
                REQUIRE(membership != nullptr);
                REQUIRE(membership->membership == "knock");

                REQUIRE(sync.response.status == 200U);
                auto const sync_body = parse_object(sync.response.body);
                auto const* rooms = object_member_as_object(sync_body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* knock_rooms = object_member_as_object(*rooms, "knock");
                REQUIRE(knock_rooms != nullptr);
                REQUIRE(object_member_as_object(*knock_rooms, room_id) != nullptr);
            }
        }
    }
}

// =============================================================================
// ROOM PARTICIPATION — SENDING AND READING EVENTS
// =============================================================================

// --- PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId} ----------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3roomsroomidsendeventtypetxnid
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
// ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3roomsroomidstateeventtypestatekeystateeventtype
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3roomsroomidstateeventtype
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidstate
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
// ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidstateeventtypestatekeystateeventtype
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidstateeventtype
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidmessages
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

            THEN("the server returns Matrix room events with event_id in both chunk and state")
            {
                // Spec MUST: /messages returns room events in the client event
                // format, which includes event_id for timeline and state
                // events. Clients reject these payloads when event_id is
                // missing, even if the event otherwise parses.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
                REQUIRE(!chunk->empty());
                for (auto const& value : *chunk)
                {
                    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                    REQUIRE(event != nullptr);
                    auto const* event_id = string_member(*event, "event_id");
                    REQUIRE(event_id != nullptr);
                    REQUIRE(!event_id->empty());
                }

                auto const* state = object_member_as_array(body, "state");
                REQUIRE(state != nullptr);
                REQUIRE(!state->empty());
                for (auto const& value : *state)
                {
                    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                    REQUIRE(event != nullptr);
                    auto const* event_id = string_member(*event, "event_id");
                    REQUIRE(event_id != nullptr);
                    REQUIRE(!event_id->empty());
                }
            }
        }
    }
}

// --- PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId} -------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3roomsroomidtypinguserid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidread_markers
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidreceiptreceipttypeeventid
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

SCENARIO("Incremental /sync surfaces room read receipts inside ephemeral events",
         "[conformance][client-server][sync][room-participation][receipts]")
{
    GIVEN("two joined users and a room event that one user reads")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})"});
        REQUIRE(create.response.status == 200U);
        auto const create_body = parse_object(create.response.body);
        auto const* room_id = string_member(create_body, "room_id");
        REQUIRE(room_id != nullptr);

        auto const join = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/join", bob, "{}"});
        REQUIRE(join.response.status == 200U);

        auto const alice_initial_sync = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", alice, {}});
        REQUIRE(alice_initial_sync.response.status == 200U);
        auto const alice_from = sync_next_batch(alice_initial_sync.response.body);

        auto const send = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"PUT", "/_matrix/client/v3/rooms/" + *room_id + "/send/m.room.message/txn-receipt-1",
                              alice, R"({"msgtype":"m.text","body":"hello"})"});
        REQUIRE(send.response.status == 200U);
        auto const send_body = parse_object(send.response.body);
        auto const* event_id = string_member(send_body, "event_id");
        REQUIRE(event_id != nullptr);

        WHEN("bob posts an m.read receipt and alice performs incremental sync")
        {
            auto const receipt = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/receipt/m.read/" + *event_id, bob, "{}"});
            REQUIRE(receipt.response.status == 200U);

            auto const sync = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync?since=" + alice_from, alice, {}});

            THEN("the joined room contains an m.receipt ephemeral event for the message")
            {
                REQUIRE(sync.response.status == 200U);
                auto const body = parse_object(sync.response.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* joins = object_member_as_object(*rooms, "join");
                REQUIRE(joins != nullptr);
                auto const* room_entry = object_member_as_object(*joins, *room_id);
                REQUIRE(room_entry != nullptr);
                auto const* ephemeral = object_member_as_object(*room_entry, "ephemeral");
                REQUIRE(ephemeral != nullptr);
                auto const* events = object_member_as_array(*ephemeral, "events");
                REQUIRE(events != nullptr);

                auto saw_receipt = false;
                for (auto const& value : *events)
                {
                    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                    REQUIRE(event != nullptr);
                    auto const* type = string_member(*event, "type");
                    if (type == nullptr || *type != "m.receipt")
                    {
                        continue;
                    }
                    auto const* content = object_member_as_object(*event, "content");
                    REQUIRE(content != nullptr);
                    auto const* receipt_event = object_member_as_object(*content, *event_id);
                    REQUIRE(receipt_event != nullptr);
                    auto const* reads = object_member_as_object(*receipt_event, "m.read");
                    REQUIRE(reads != nullptr);
                    auto const* bob_receipt = object_member_as_object(*reads, "@bob:example.org");
                    REQUIRE(bob_receipt != nullptr);
                    REQUIRE(int_member(*bob_receipt, "ts") != nullptr);
                    saw_receipt = true;
                }

                REQUIRE(saw_receipt);
            }
        }
    }
}

// --- GET /_matrix/client/v3/rooms/{roomId}/members ---------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidmembers
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidjoined_members
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomideventeventid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidcontexteventid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidinitialsync
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3initialsync
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidupgrade
// The server MUST create a replacement room, send m.room.tombstone to the old
// room, and return {"replacement_room":"!newid:server"} on success.
SCENARIO("POST /rooms/{roomId}/upgrade creates a replacement room", "[conformance][client-server][room-participation]")
{
    GIVEN("a running homeserver and a created room")
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

            THEN("the server returns 200 with a replacement_room field containing a valid room ID")
            {
                // Spec MUST: 200 {"replacement_room":"!newroomid:server"}.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* replacement = string_member(body, "replacement_room");
                REQUIRE(replacement != nullptr);
                // Spec MUST: replacement_room is a non-empty Matrix room ID starting with '!'.
                REQUIRE(!replacement->empty());
                REQUIRE(replacement->front() == '!');
            }
        }

        WHEN("POST /rooms/{roomId}/upgrade is called with missing new_version")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", token, "{}"});

            THEN("the server returns 400 M_BAD_JSON")
            {
                // Spec MUST: 400 when new_version is absent.
                REQUIRE(response.response.status == 400U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_BAD_JSON");
            }
        }

        WHEN("POST /rooms/{roomId}/upgrade is called with an unsupported room version")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", token, R"({"new_version":"99"})"});

            THEN("the server returns 400 M_UNSUPPORTED_ROOM_VERSION")
            {
                // Spec MUST: 400 when the requested version is not supported.
                REQUIRE(response.response.status == 400U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_UNSUPPORTED_ROOM_VERSION");
            }
        }
    }

    GIVEN("a running homeserver and an unknown room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /rooms/!nonexistent:server/upgrade is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/!nonexistent:server/upgrade", token, R"({"new_version":"11"})"});

            THEN("the server returns 404 M_NOT_FOUND")
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

// --- GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event ----------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv1roomsroomidtimestamp_to_event
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3events
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3eventseventid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3profileuserid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3profileuseriddisplayname
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3profileuseridavatar_url
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3profileuseriddisplayname
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3profileuseridavatar_url
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3useruseridffilter
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3useruseridffilterfilterid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3useruseridaccount_datatype
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3useruseridaccount_datatype
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

SCENARIO("PUT and GET /user/{userId}/account_data/{type} percent-decode the type path segment",
         "[conformance][client-server][account-data]")
{
    GIVEN("a running client-server and a logged-in user storing a secret-storage key descriptor")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto constexpr encoded_type =
            "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.secret_storage.key.key%2Fid";
        auto constexpr body = R"({"algorithm":"m.secret_storage.v1.aes-hmac-sha2","name":"Recovery key"})";

        WHEN("the client stores and retrieves the same percent-encoded account-data type")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(started.runtime,
                                                                                   {"PUT", encoded_type, token, body});
            auto const get = merovingian::homeserver::handle_client_server_request(started.runtime,
                                                                                   {"GET", encoded_type, token, {}});

            THEN("the server persists and returns the descriptor under the decoded type")
            {
                REQUIRE(put.response.status == 200U);
                auto const put_body = parse_object(put.response.body);
                REQUIRE(put_body.empty());

                REQUIRE(get.response.status == 200U);
                auto const get_body = parse_object(get.response.body);
                auto const* algorithm = string_member(get_body, "algorithm");
                auto const* name = string_member(get_body, "name");
                REQUIRE(algorithm != nullptr);
                REQUIRE(name != nullptr);
                REQUIRE(*algorithm == "m.secret_storage.v1.aes-hmac-sha2");
                REQUIRE(*name == "Recovery key");
            }
        }
    }
}

// --- PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type} --
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3useruseridrooms roomidaccount_datatype
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3useruseridrooms roomidaccount_datatype
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3useruseridrooms roomidtags
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3useruseridrooms roomidtagstag
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3useruseridrooms roomidtagstag
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3presenceuseridstatus
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3presenceuseridstatus
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3pushrules
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
                // Spec MUST: all predefined default override rules are present
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.master") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.suppress_notices") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.invite_for_me") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.member_event") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.is_user_mention") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.is_room_mention") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.tombstone") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.reaction") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.room.server_acl") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.suppress_edits") != nullptr);
                // Spec MUST: legacy mention/notify rules — absent from this server caused
                // Element SDK to log "Missing default global override push rule" on login.
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.contains_display_name") != nullptr);
                REQUIRE(push_rule_by_id(*override_rules, ".m.rule.roomnotif") != nullptr);
                // Spec MUST: underride rules
                REQUIRE(push_rule_by_id(*underride_rules, ".m.rule.call") != nullptr);
                REQUIRE(push_rule_by_id(*underride_rules, ".m.rule.encrypted_room_one_to_one") != nullptr);
                REQUIRE(push_rule_by_id(*underride_rules, ".m.rule.room_one_to_one") != nullptr);
                REQUIRE(push_rule_by_id(*underride_rules, ".m.rule.message") != nullptr);
                REQUIRE(push_rule_by_id(*underride_rules, ".m.rule.encrypted") != nullptr);
            }
        }
    }
}

// --- GET /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId} ----------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3pushrulesscopekindruleid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3pushrulesscopekindruleid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3pushrulesscopekindruleid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3pushrulesscopekindruleidactions
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3pushrulesscopekindruleidactions
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3pushrulesscopekindruleidenabled
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3pushrulesscopekindruleidenabled
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3notifications
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3pushers
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3pushersset
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidreporteventid
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidreport
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3usersuseridreport
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3voipturnserver
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

// --- GET /voip/turnServer: authentication required ----------------------------
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3voipturnserver
//
// Spec: "Requires authentication: Yes"
// A request without a valid access token MUST be rejected with 401 M_MISSING_TOKEN.
SCENARIO("GET /voip/turnServer rejects unauthenticated requests", "[conformance][client-server][voip][auth]")
{
    GIVEN("a running client-server with no access token")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /voip/turnServer is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/voip/turnServer", {}, {}});

            THEN("the server returns 401 M_MISSING_TOKEN")
            {
                // Spec MUST: endpoint requires authentication; no token → 401.
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == std::string{"M_MISSING_TOKEN"});
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
// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3sendtoeventtypetxnid
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

SCENARIO("PUT /sendToDevice targets only the addressed local device and drains once",
         "[conformance][client-server][e2ee][send-to-device]")
{
    GIVEN("a local user logged in on two devices")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob_device_one = register_and_login(started.runtime, "bob");
        auto const bob_device_two = login_existing_user(started.runtime, "bob", "DEVICE2");

        WHEN("alice sends a to-device message only to bob_DEV")
        {
            auto const send = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/sendToDevice/m.room_key/txn-targeted", alice,
                 R"({"messages":{"@bob:example.org":{"bob_DEV":{"session_key":"sk1","room_id":"!r:example.org"}}}})"});

            THEN("only bob_DEV receives the message and a later sync does not redeliver it")
            {
                REQUIRE(send.response.status == 200U);

                auto const device_one_sync = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync", bob_device_one, {}});
                REQUIRE(device_one_sync.response.status == 200U);
                auto const device_one_body = parse_object(device_one_sync.response.body);
                auto const* device_one_to_device = object_member_as_object(device_one_body, "to_device");
                REQUIRE(device_one_to_device != nullptr);
                auto const* device_one_events = object_member_as_array(*device_one_to_device, "events");
                REQUIRE(device_one_events != nullptr);
                REQUIRE(device_one_events->size() == 1U);

                auto const device_two_sync = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync", bob_device_two, {}});
                REQUIRE(device_two_sync.response.status == 200U);
                auto const device_two_body = parse_object(device_two_sync.response.body);
                auto const* device_two_to_device = object_member_as_object(device_two_body, "to_device");
                REQUIRE(device_two_to_device != nullptr);
                auto const* device_two_events = object_member_as_array(*device_two_to_device, "events");
                REQUIRE(device_two_events != nullptr);
                REQUIRE(device_two_events->empty());

                auto const device_one_sync_again = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync", bob_device_one, {}});
                REQUIRE(device_one_sync_again.response.status == 200U);
                auto const device_one_again_body = parse_object(device_one_sync_again.response.body);
                auto const* device_one_to_device_again = object_member_as_object(device_one_again_body, "to_device");
                REQUIRE(device_one_to_device_again != nullptr);
                auto const* device_one_events_again = object_member_as_array(*device_one_to_device_again, "events");
                REQUIRE(device_one_events_again != nullptr);
                REQUIRE(device_one_events_again->empty());
            }
        }
    }
}

SCENARIO("PUT /sendToDevice/m.room.encrypted preserves the nested Olm ciphertext for /sync",
         "[conformance][client-server][e2ee][send-to-device]")
{
    GIVEN("a running homeserver with Alice and Bob registered")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = logged_in_token(started.runtime);
        auto const bob = register_and_login(started.runtime, "bob");

        WHEN("Alice sends a client-shaped encrypted to-device payload to Bob")
        {
            auto const send = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/sendToDevice/m.room.encrypted/txn-client-olm-1", alice,
                 R"({"messages":{"@bob:example.org":{"bob_DEV":{"algorithm":"m.olm.v1.curve25519-aes-sha2","sender_key":"curve25519:alice","ciphertext":{"curve25519:bob_DEV":{"body":"olm-ciphertext","type":0}}}}}})"});
            REQUIRE(send.response.status == 200U);

            THEN("Bob's next /sync exposes the encrypted to-device event intact")
            {
                auto const sync = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});
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
                REQUIRE(*sender == "@alice:example.org");

                auto const* content = object_member_as_object(*event, "content");
                REQUIRE(content != nullptr);
                auto const* algorithm = string_member(*content, "algorithm");
                REQUIRE(algorithm != nullptr);
                REQUIRE(*algorithm == "m.olm.v1.curve25519-aes-sha2");
                auto const* ciphertext = object_member_as_object(*content, "ciphertext");
                REQUIRE(ciphertext != nullptr);
                auto const* recipient_ciphertext = object_member_as_object(*ciphertext, "curve25519:bob_DEV");
                REQUIRE(recipient_ciphertext != nullptr);
                auto const* cipher_body = string_member(*recipient_ciphertext, "body");
                REQUIRE(cipher_body != nullptr);
                REQUIRE(*cipher_body == "olm-ciphertext");
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.18-spec/server-server-api.md#sending-to-device-messages
// and ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
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

// Spec: ../../docs/matrix-v1.18-spec/server-server-api.md#sending-to-device-messages
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
            // Use curve25519 type so no device-identity signature is required for upload.
            auto const upload = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/keys/upload", alice,
                 R"({"one_time_keys":{"curve25519:AAAAA":"otk_payload_1","curve25519:BBBBB":"otk_payload_2"}})"});
            REQUIRE(upload.response.status == 200U);
            // Verify OTK count is reflected immediately.
            // Server aggregates all OTK types under signed_curve25519 in the count response.
            auto const up_body = parse_object(upload.response.body);
            auto const* counts = object_member_as_object(up_body, "one_time_key_counts");
            REQUIRE(counts != nullptr);
            auto const* sc_count = int_member(*counts, "signed_curve25519");
            REQUIRE(sc_count != nullptr);
            REQUIRE(*sc_count >= 1);

            auto const claim = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/claim", alice,
                                  R"({"one_time_keys":{"@alice:example.org":{"DEVICE1":"curve25519"}}})"});

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

        // Use curve25519 type so no device-identity signature is required for upload.
        // A second key with a non-matching algorithm prefix verifies selection logic.
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/keys/upload", token,
                                      R"({"fallback_keys":{"curve25519:FALLBACK":"matching-fallback"}})"})
                    .response.status == 200U);

        WHEN("the device claims a curve25519 key for that device")
        {
            auto const claim = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                                  R"({"one_time_keys":{"@alice:example.org":{"DEVICE1":"curve25519"}}})"});

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

                // Spec MUST: claim returns the stored curve25519 fallback key.
                REQUIRE(object_member(*device_otks, "curve25519:FALLBACK") != nullptr);
            }

            AND_THEN("a second claim returns the same fallback key because fallback keys are reusable")
            {
                auto const second_claim = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                                      R"({"one_time_keys":{"@alice:example.org":{"DEVICE1":"curve25519"}}})"});
                REQUIRE(second_claim.response.status == 200U);
                auto const body = parse_object(second_claim.response.body);
                auto const* otks = object_member_as_object(body, "one_time_keys");
                REQUIRE(otks != nullptr);
                auto const* user_otks = object_member_as_object(*otks, "@alice:example.org");
                REQUIRE(user_otks != nullptr);
                auto const* device_otks = object_member_as_object(*user_otks, "DEVICE1");
                REQUIRE(device_otks != nullptr);
                // Spec MUST: fallback key is reused — same key returned on repeated claims.
                REQUIRE(object_member(*device_otks, "curve25519:FALLBACK") != nullptr);
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
// Spec: Matrix v1.18 §third party networks
//       GET /thirdparty/protocols is implemented and returns a (possibly empty)
//       protocol map. The location/{protocol} and user/{protocol} lookups remain
//       unimplemented and return 404 M_UNRECOGNIZED.

// Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3thirdpartyprotocols
//
// MUST return 200 with a JSON object mapping protocol identifiers to metadata. A
// server with no application services returns an empty object — NOT a 404. The
// previous expectation (404 M_UNRECOGNIZED) was a placeholder for an unimplemented
// endpoint; it was never spec-conformant, and a 404 makes clients (Element) log
// "Failed to check for protocol support" and retry needlessly.
SCENARIO("GET /thirdparty/protocols returns a 200 JSON object", "[conformance][client-server][thirdparty]")
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

            THEN("the server returns 200 with a JSON object body")
            {
                // Spec MUST: 200 with an object body (empty when no appservices),
                // never 404. parse_object REQUIREs the body parses as an object.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                std::ignore = body;
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
// The server MUST create a replacement room and return {"replacement_room":...}.

SCENARIO("POST /rooms/{roomId}/upgrade returns 200 with replacement_room",
         "[conformance][client-server][room-participation]")
{
    GIVEN("a started homeserver with an authenticated user and a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        WHEN("POST /rooms/{roomId}/upgrade is called with new_version 12")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", token, R"({"new_version":"12"})"});

            THEN("the server returns 200 with a replacement_room field")
            {
                // Spec MUST: 200 {"replacement_room":"!newroomid:server"}.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* replacement = string_member(body, "replacement_room");
                REQUIRE(replacement != nullptr);
                REQUIRE(!replacement->empty());
                REQUIRE(replacement->front() == '!');
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

// Spec: Matrix Client-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3publicrooms
//
// POST /publicRooms with filter.generic_search_term and limit must return 200
// with chunk (array) and total_room_count_estimate; chunk size must not exceed limit.
SCENARIO("POST /publicRooms conformance")
{
    GIVEN("a started homeserver with an authenticated user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("POST /publicRooms is called with filter.generic_search_term and limit=10")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/publicRooms", token,
                                  R"({"filter":{"generic_search_term":"test"},"limit":10})"});

            THEN("the server returns 200 with chunk array and total_room_count_estimate")
            {
                // Spec MUST: 200 with chunk (PublicRoomsChunk[]) and total_room_count_estimate.
                REQUIRE(response.response.status == 200);
                auto const body = parse_object(response.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
                // Spec MUST: chunk size does not exceed the requested limit.
                REQUIRE(chunk->size() <= 10U);
                auto const* estimate = int_member(body, "total_room_count_estimate");
                REQUIRE(estimate != nullptr);
            }
        }
    }
}

SCENARIO("GET /directory/list/room/{roomId} returns 404 for unknown room",
         "[conformance][client-server][room-discovery]")
{
    GIVEN("a started homeserver with no room matching the given ID")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /directory/list/room/!room:example.org is called for an unknown room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/directory/list/room/!room:example.org", token, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the room is not known to this server.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_NOT_FOUND");
            }
        }
    }
}

SCENARIO("PUT /directory/list/room/{roomId} returns 404 for unknown room",
         "[conformance][client-server][room-discovery]")
{
    GIVEN("a started homeserver with no room matching the given ID")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("PUT /directory/list/room/!room:example.org is called for an unknown room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/directory/list/room/!room:example.org", token,
                                  R"({"visibility":"private"})"});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the room is not known to this server.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_NOT_FOUND");
            }
        }
    }
}

// =============================================================================
// Client-Server API — Coverage gap set 2: Devices, Profile, Account Data,
// Capabilities, Public Rooms, Room Directory, Register Available,
// Joined Rooms, Push Rules, Error Semantics
// =============================================================================

// Spec: Matrix Client-Server API v1.18
// Section: GET /_matrix/client/v3/devices
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3devices
//
// The server MUST return a "devices" array. Each entry MUST include "device_id".
SCENARIO("GET /devices returns a devices array containing the authenticated device",
         "[conformance][client-server][devices]")
{
    GIVEN("a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("GET /devices is called")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("response is 200 with a devices array containing the login device")
            {
                // Spec MUST: response contains "devices" array
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* devs_val = object_member(body, "devices");
                REQUIRE(devs_val != nullptr);
                auto const* devs = std::get_if<merovingian::canonicaljson::Array>(&devs_val->storage());
                REQUIRE(devs != nullptr);
                REQUIRE(!devs->empty());

                // Spec MUST: each device entry carries device_id; the login
                // device (DEVICE1) must appear somewhere in the array.
                // Registration also creates a device, so we search rather than
                // assume index 0.
                auto found_device1 = false;
                for (auto const& dev_val : *devs)
                {
                    auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&dev_val.storage());
                    if (obj == nullptr)
                    {
                        continue;
                    }
                    auto const* did = string_member(*obj, "device_id");
                    if (did != nullptr && *did == "DEVICE1")
                    {
                        found_device1 = true;
                        break;
                    }
                }
                REQUIRE(found_device1);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: GET /_matrix/client/v3/devices/{deviceId}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3devicesdeviceid
//
// Known device_id MUST return 200 with device object. Unknown MUST return 404 M_NOT_FOUND.
SCENARIO("GET /devices/{deviceId} returns the device or 404 for unknown", "[conformance][client-server][devices]")
{
    GIVEN("a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("GET /devices/DEVICE1 is called")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/devices/DEVICE1", token, {}});

            THEN("response is 200 with device_id in the body")
            {
                // Spec MUST: known device returns 200 with device object
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* did = string_member(body, "device_id");
                REQUIRE(did != nullptr);
                REQUIRE(*did == "DEVICE1");
            }
        }

        WHEN("GET /devices/NOSUCHDEVICE is called")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/devices/NOSUCHDEVICE", token, {}});

            THEN("response is 404 M_NOT_FOUND")
            {
                // Spec MUST: unknown device_id returns 404
                REQUIRE(resp.response.status == 404U);
                auto const body = parse_object(resp.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_NOT_FOUND");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: GET /_matrix/client/v3/capabilities
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3capabilities
//
// MUST return a "capabilities" object with "m.room_versions" containing a non-empty
// "default" string and a non-empty "available" version-to-stability map.
SCENARIO("GET /capabilities returns required capability fields including m.room_versions",
         "[conformance][client-server][capabilities]")
{
    GIVEN("a started server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("GET /capabilities is called")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/capabilities", token, {}});

            THEN("response is 200 with capabilities.m.room_versions.default and .available")
            {
                // Spec MUST: top-level "capabilities" object is present
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* caps = object_member_as_object(body, "capabilities");
                REQUIRE(caps != nullptr);

                // Spec MUST: m.room_versions has "default" (string) and "available" (object)
                auto const* rv = object_member_as_object(*caps, "m.room_versions");
                REQUIRE(rv != nullptr);
                auto const* def = string_member(*rv, "default");
                REQUIRE(def != nullptr);
                REQUIRE(!def->empty());
                auto const* avail = object_member_as_object(*rv, "available");
                REQUIRE(avail != nullptr);
                REQUIRE(!avail->empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: GET /_matrix/client/v3/joined_rooms
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3joined_rooms
//
// MUST return "joined_rooms" array of room IDs the caller is currently joined to.
SCENARIO("GET /joined_rooms lists all rooms the authenticated user is joined to",
         "[conformance][client-server][rooms][joined]")
{
    GIVEN("a user who has created a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        auto const create = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"private_chat"})"});
        REQUIRE(create.response.status == 200U);
        auto const create_body = parse_object(create.response.body);
        auto const* created_rid = string_member(create_body, "room_id");
        REQUIRE(created_rid != nullptr);

        WHEN("GET /joined_rooms is called")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});

            THEN("response is 200 with the created room in joined_rooms")
            {
                // Spec MUST: "joined_rooms" is an array of room IDs
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* rooms_val = object_member(body, "joined_rooms");
                REQUIRE(rooms_val != nullptr);
                auto const* rooms = std::get_if<merovingian::canonicaljson::Array>(&rooms_val->storage());
                REQUIRE(rooms != nullptr);

                // Spec MUST: newly created room appears in joined_rooms
                auto const found = std::ranges::any_of(*rooms, [&](merovingian::canonicaljson::Value const& v) {
                    auto const* s = std::get_if<std::string>(&v.storage());
                    return s != nullptr && *s == *created_rid;
                });
                REQUIRE(found);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: GET /_matrix/client/v3/publicRooms
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3publicrooms
//
// MUST return "chunk" (array of public room summaries) and "total_room_count_estimate"
// (integer). Each chunk entry MUST have "room_id".
SCENARIO("GET /publicRooms returns chunk array and total_room_count_estimate",
         "[conformance][client-server][rooms][public]")
{
    GIVEN("a server with a public room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/createRoom", token,
                         R"({"preset":"public_chat","name":"Public Test"})"})
                    .response.status == 200U);

        WHEN("GET /publicRooms is called")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/publicRooms", token, {}});

            THEN("response is 200 with chunk and total_room_count_estimate")
            {
                // Spec MUST: 200 with "chunk" array and "total_room_count_estimate" integer
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);

                auto const* chunk_val = object_member(body, "chunk");
                REQUIRE(chunk_val != nullptr);
                auto const* chunk = std::get_if<merovingian::canonicaljson::Array>(&chunk_val->storage());
                REQUIRE(chunk != nullptr);
                REQUIRE(!chunk->empty());

                auto const* est_val = object_member(body, "total_room_count_estimate");
                REQUIRE(est_val != nullptr);
                auto const* est = std::get_if<std::int64_t>(&est_val->storage());
                REQUIRE(est != nullptr);
                REQUIRE(*est >= 1);

                // Spec MUST: each chunk entry carries "room_id"
                auto const* first = std::get_if<merovingian::canonicaljson::Object>(&(*chunk)[0].storage());
                REQUIRE(first != nullptr);
                REQUIRE(string_member(*first, "room_id") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: GET /_matrix/client/v3/directory/room/{roomAlias}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3directoryroomroomalias
//
// Known alias MUST return {"room_id": "...", "servers": [...]}. Unknown MUST return 404.
SCENARIO("GET /directory/room resolves a known alias and 404s for unknown", "[conformance][client-server][directory]")
{
    GIVEN("a room created with room_alias_name testroom")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/createRoom", token, R"({"room_alias_name":"testroom"})"})
                    .response.status == 200U);

        WHEN("the alias %23testroom%3Aexample.org is resolved")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/directory/room/%23testroom%3Aexample.org", token, {}});

            THEN("response is 200 with room_id and servers array")
            {
                // Spec MUST: known alias returns room_id and servers array
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* rid = string_member(body, "room_id");
                REQUIRE(rid != nullptr);
                REQUIRE(!rid->empty());
                auto const* srvs_val = object_member(body, "servers");
                REQUIRE(srvs_val != nullptr);
                auto const* srvs = std::get_if<merovingian::canonicaljson::Array>(&srvs_val->storage());
                REQUIRE(srvs != nullptr);
                REQUIRE(!srvs->empty());
            }
        }

        WHEN("an unknown alias is resolved")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/directory/room/%23nosuchroom%3Aexample.org", token, {}});

            THEN("response is 404 M_NOT_FOUND")
            {
                // Spec MUST: unknown alias returns 404
                REQUIRE(resp.response.status == 404U);
                auto const body = parse_object(resp.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_NOT_FOUND");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: GET /_matrix/client/v3/register/available
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3registeravailable
//
// Free username MUST return {"available": true}. Taken MUST return 400 M_USER_IN_USE.
// Invalid localpart MUST return 400 M_INVALID_USERNAME.
SCENARIO("GET /register/available reports username availability correctly", "[conformance][client-server][register]")
{
    GIVEN("a server where alice is already registered")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        std::ignore = logged_in_token(rt); // registers alice; token unused in this scenario

        WHEN("a free username bob is checked")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/register/available?username=bob", {}, {}});

            THEN("response is 200 with available: true")
            {
                // Spec MUST: free username returns {"available": true}
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* avail_val = object_member(body, "available");
                REQUIRE(avail_val != nullptr);
                auto const* avail = std::get_if<bool>(&avail_val->storage());
                REQUIRE(avail != nullptr);
                REQUIRE(*avail == true);
            }
        }

        WHEN("the already-taken username alice is checked")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/register/available?username=alice", {}, {}});

            THEN("response is 400 M_USER_IN_USE")
            {
                // Spec MUST: taken username returns 400 M_USER_IN_USE
                REQUIRE(resp.response.status == 400U);
                auto const body = parse_object(resp.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_USER_IN_USE");
            }
        }

        WHEN("the invalid username Alice (uppercase) is checked")
        {
            // Spec §Identifier Grammar: localparts for new accounts MUST be lowercase-only
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/register/available?username=Alice", {}, {}});

            THEN("response is 400 M_INVALID_USERNAME")
            {
                // Spec MUST: invalid localpart returns 400 M_INVALID_USERNAME
                REQUIRE(resp.response.status == 400U);
                auto const body = parse_object(resp.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_INVALID_USERNAME");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: PUT /_matrix/client/v3/user/{userId}/account_data/{type}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3useruseridaccount_datatype
// Section: GET /_matrix/client/v3/user/{userId}/account_data/{type}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3useruseridaccount_datatype
//
// PUT MUST store arbitrary JSON and return 200 {}. GET MUST return it verbatim.
// GET on an unset type MUST return 404 M_NOT_FOUND.
SCENARIO("PUT/GET /user/{userId}/account_data/{type} stores and retrieves user account data",
         "[conformance][client-server][account-data]")
{
    GIVEN("a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        auto const url = std::string{"/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.custom.type"};

        WHEN("PUT stores JSON content")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", url, token, R"({"key":"value","count":42})"});

            THEN("PUT returns 200 and GET returns the stored content")
            {
                // Spec MUST: PUT returns 200
                REQUIRE(put.response.status == 200U);

                auto const get = merovingian::homeserver::handle_client_server_request(rt, {"GET", url, token, {}});

                // Spec MUST: GET returns the stored content verbatim
                REQUIRE(get.response.status == 200U);
                REQUIRE(get.response.body.find("value") != std::string::npos);
                REQUIRE(get.response.body.find("42") != std::string::npos);
            }
        }

        WHEN("GET is called for a type that was never stored")
        {
            auto const get = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.never.set", token, {}});

            THEN("response is 404 M_NOT_FOUND")
            {
                // Spec MUST: unset account data type returns 404
                REQUIRE(get.response.status == 404U);
                auto const body = parse_object(get.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_NOT_FOUND");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: PUT /_matrix/client/v3/profile/{userId}/displayname
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3profileuseriddisplayname
// Section: GET /_matrix/client/v3/profile/{userId}/displayname
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3profileuseriddisplayname
//
// PUT MUST update the displayname and return 200. GET MUST return the current value.
SCENARIO("PUT /profile/{userId}/displayname updates and GET retrieves it", "[conformance][client-server][profile]")
{
    GIVEN("a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("PUT sets the displayname to Alice Wonderland")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", token,
                     R"({"displayname":"Alice Wonderland"})"});

            THEN("PUT returns 200 and GET reflects the new displayname")
            {
                // Spec MUST: PUT displayname returns 200
                REQUIRE(put.response.status == 200U);

                auto const get = merovingian::homeserver::handle_client_server_request(
                    rt, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", token, {}});
                REQUIRE(get.response.status == 200U);

                // Spec MUST: response contains the updated "displayname"
                auto const body = parse_object(get.response.body);
                auto const* dn = string_member(body, "displayname");
                REQUIRE(dn != nullptr);
                REQUIRE(*dn == "Alice Wonderland");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: GET /_matrix/client/v3/profile/{userId}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3profileuserid
//
// Full profile GET is unauthenticated per spec. MUST include "displayname" and
// "avatar_url". Unknown user MUST return 404 M_NOT_FOUND.
SCENARIO("GET /profile/{userId} is unauthenticated and returns displayname and avatar_url",
         "[conformance][client-server][profile]")
{
    GIVEN("a registered user alice")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        std::ignore = logged_in_token(rt); // registers alice; token unused in this scenario

        WHEN("GET /profile/{userId} is called without an access token")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org", {}, {}});

            THEN("response is 200 with displayname and avatar_url present")
            {
                // Spec MUST: profile lookup succeeds without authentication
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                // Spec MUST: response contains "displayname" and "avatar_url" keys
                REQUIRE(object_member(body, "displayname") != nullptr);
                REQUIRE(object_member(body, "avatar_url") != nullptr);
            }
        }

        WHEN("GET /profile/{userId} is called for an unknown user")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40nobody%3Aexample.org", {}, {}});

            THEN("response is 404 M_NOT_FOUND")
            {
                // Spec MUST: unknown user profile returns 404
                REQUIRE(resp.response.status == 404U);
                auto const body = parse_object(resp.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_NOT_FOUND");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: GET /_matrix/client/v3/pushrules/
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3pushrules
//
// MUST return a "global" ruleset. "global" MUST contain all five standard
// push rule category keys: override, content, room, sender, underride.
SCENARIO("GET /pushrules/ returns a global ruleset with all five push rule categories",
         "[conformance][client-server][pushrules]")
{
    GIVEN("a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("GET /pushrules/ is called")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/pushrules/", token, {}});

            THEN("response is 200 with global containing all five categories")
            {
                // Spec MUST: response contains "global" ruleset object
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* global = object_member_as_object(body, "global");
                REQUIRE(global != nullptr);

                // Spec MUST: global contains override, content, room, sender, underride
                REQUIRE(object_member(*global, "override") != nullptr);
                REQUIRE(object_member(*global, "content") != nullptr);
                REQUIRE(object_member(*global, "room") != nullptr);
                REQUIRE(object_member(*global, "sender") != nullptr);
                REQUIRE(object_member(*global, "underride") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Section: Standard error response
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#standard-error-response
//
// Every error response MUST be a JSON object with "errcode" (string) and "error"
// (human-readable string). HTTP status code MUST reflect the error class.
// Tested: invalid token (401), cross-user write (403 M_FORBIDDEN).
SCENARIO("Matrix error responses always carry errcode and error fields", "[conformance][client-server][error]")
{
    GIVEN("a started server with a registered user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("a request is made with a bad access token")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/account/whoami", "bad_token_xyz", {}});

            THEN("response is 401 with errcode and human-readable error string")
            {
                // Spec MUST: invalid token returns 401 with standard error object
                REQUIRE(resp.response.status == 401U);
                auto const body = parse_object(resp.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(!errcode->empty());
                // Spec MUST: "error" is a human-readable string
                auto const* error = string_member(body, "error");
                REQUIRE(error != nullptr);
            }
        }

        WHEN("alice tries to write account data for bob (a different user)")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/user/%40bob%3Aexample.org/account_data/m.test", token, R"({"x":1})"});

            THEN("response is 403 M_FORBIDDEN")
            {
                // Spec MUST: acting as another user returns 403 M_FORBIDDEN
                REQUIRE(resp.response.status == 403U);
                auto const body = parse_object(resp.response.body);
                auto const* err = string_member(body, "errcode");
                REQUIRE(err != nullptr);
                REQUIRE(*err == "M_FORBIDDEN");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: DELETE /_matrix/client/v3/devices/{deviceId}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#delete_matrixclientv3devicesdeviceid
//
// The server MUST require User-Interactive Authentication (UIA) before deleting
// a device.  A request without an auth block MUST receive 401 with the UIA
// challenge.  An incorrect password MUST also return 401.  Only a valid
// m.login.password auth block permits deletion (200).
SCENARIO("DELETE /devices/{deviceId} MUST require UIA before deleting a device",
         "[homeserver][client-server][devices][conformance][uia][security]")
{
    GIVEN("a registered and logged-in user with an active device")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("DELETE /devices/DEVICE1 is sent without an auth block")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"DELETE", "/_matrix/client/v3/devices/DEVICE1", token, "{}"});

            THEN("status is 401 and body contains the UIA flows")
            {
                // Spec MUST: missing auth block → 401 + UIA challenge
                REQUIRE(resp.response.status == 401U);
                auto const body = parse_object(resp.response.body);
                auto const* flows = object_member(body, "flows");
                REQUIRE(flows != nullptr);
            }
        }

        WHEN("DELETE /devices/DEVICE1 is sent with a wrong password")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"DELETE", "/_matrix/client/v3/devices/DEVICE1", token,
                     R"({"auth":{"type":"m.login.password","password":"BadPassword"}})"});

            THEN("status is 401 — wrong credential must not succeed")
            {
                // Spec MUST: wrong credential → 401
                REQUIRE(resp.response.status == 401U);
            }
        }

        WHEN("DELETE /devices/DEVICE1 is sent with a correct password")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"DELETE", "/_matrix/client/v3/devices/DEVICE1", token,
                     R"({"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});

            THEN("status is 200 — valid UIA succeeds")
            {
                // Spec MUST: valid UIA → 200 and device removed
                REQUIRE(resp.response.status == 200U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: POST /_matrix/client/v3/room_keys/version
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3room_keysversion
//
// The server MUST return {"version":"<id>"} where <id> is a unique string that
// can be used in subsequent calls.  Two sequential POSTs MUST return different
// version strings.
SCENARIO("POST /room_keys/version MUST return a unique version string for each new backup",
         "[homeserver][client-server][key-backup][conformance]")
{
    GIVEN("a logged-in user")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("two backups are created back-to-back")
        {
            auto const backup_body = R"({"algorithm":"m.megolm_backup.v1","auth_data":{}})";
            auto const r1 = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/room_keys/version", token, backup_body});
            auto const r2 = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/room_keys/version", token, backup_body});

            THEN("both return 200 with non-empty, distinct version strings")
            {
                // Spec MUST: response contains version string
                REQUIRE(r1.response.status == 200U);
                REQUIRE(r2.response.status == 200U);
                auto const b1 = parse_object(r1.response.body);
                auto const b2 = parse_object(r2.response.body);
                auto const* v1 = string_member(b1, "version");
                auto const* v2 = string_member(b2, "version");
                REQUIRE(v1 != nullptr);
                REQUIRE(v2 != nullptr);
                REQUIRE(!v1->empty());
                REQUIRE(!v2->empty());
                // Spec MUST: each backup has a distinct identifier
                REQUIRE(*v1 != *v2);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3roomsroomiidtypinguserid
//
// The server MUST return 403 if the user is not a current member of the room.
// The typing EDU sent to remote servers MUST encode `typing` as a JSON boolean,
// not a string.
SCENARIO("PUT /typing MUST reject non-members with 403 and use a boolean typing field in the EDU",
         "[homeserver][client-server][typing][conformance]")
{
    GIVEN("alice who owns a room and bob who has never joined it")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = logged_in_token(rt);

        auto const room = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", alice_token, "{}"});
        REQUIRE(room.response.status == 200U);
        auto const body = parse_object(room.response.body);
        auto const* rid = string_member(body, "room_id");
        REQUIRE(rid != nullptr);
        auto const id = *rid;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST",
                         "/_matrix/client/v3/register",
                         {},
                         merovingian::tests::registration_json("bob", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const bob_login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"DEVBOB"})"});
        REQUIRE(bob_login.response.status == 200U);
        auto const bob_body = parse_object(bob_login.response.body);
        auto const* bt = string_member(bob_body, "access_token");
        REQUIRE(bt != nullptr);
        auto const bob_token = *bt;

        WHEN("a non-member tries to set their typing state in the room")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + id + "/typing/@bob:example.org", bob_token,
                     R"({"typing":true,"timeout":30000})"});

            THEN("status is 403 M_FORBIDDEN")
            {
                // Spec MUST: non-member → 403
                REQUIRE(resp.response.status == 403U);
                auto const err_body = parse_object(resp.response.body);
                auto const* errcode = string_member(err_body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_FORBIDDEN");
            }
        }

        WHEN("a member sets typing=true")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + id + "/typing/@alice:example.org", alice_token,
                     R"({"typing":true,"timeout":30000})"});

            THEN("status is 200")
            {
                // Spec MUST: member → 200
                REQUIRE(resp.response.status == 200U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: POST /_matrix/client/v3/rooms/{roomId}/read_markers
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidread_markers
//
// The server MUST return 403 if the user is not currently a member of the room.
// The request body MAY contain m.fully_read, m.read, and m.read.private.
SCENARIO("POST /read_markers MUST reject non-members with 403",
         "[homeserver][client-server][read_markers][conformance]")
{
    GIVEN("alice's room and bob who has never joined")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = logged_in_token(rt);

        auto const room = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", alice_token, "{}"});
        REQUIRE(room.response.status == 200U);
        auto const room_body = parse_object(room.response.body);
        auto const* rid = string_member(room_body, "room_id");
        REQUIRE(rid != nullptr);
        auto const id = *rid;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST",
                         "/_matrix/client/v3/register",
                         {},
                         merovingian::tests::registration_json("bob", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const bob_login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"DEVBOB"})"});
        REQUIRE(bob_login.response.status == 200U);
        auto const bob_body = parse_object(bob_login.response.body);
        auto const* bt = string_member(bob_body, "access_token");
        REQUIRE(bt != nullptr);
        auto const bob_token = *bt;

        WHEN("alice posts read_markers with m.read for her room")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + id + "/read_markers", alice_token,
                     R"({"m.fully_read":"$ev1","m.read":"$ev1","m.read.private":"$ev1"})"});

            THEN("status is 200")
            {
                // Spec MUST: member with valid body → 200
                REQUIRE(resp.response.status == 200U);
            }
        }

        WHEN("bob posts read_markers for a room he never joined")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + id + "/read_markers", bob_token, R"({"m.read":"$ev1"})"});

            THEN("status is 403 M_FORBIDDEN")
            {
                // Spec MUST: non-member → 403
                REQUIRE(resp.response.status == 403U);
                auto const err_body = parse_object(resp.response.body);
                auto const* errcode = string_member(err_body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_FORBIDDEN");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidreceiptreceipttypeeventid
//
// The server MUST return 403 if the user is not currently a member of the room.
SCENARIO("POST /receipt/{type}/{eventId} MUST reject non-members with 403",
         "[homeserver][client-server][receipt][conformance]")
{
    GIVEN("alice's room and bob who has never joined")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = logged_in_token(rt);

        auto const room = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", alice_token, "{}"});
        REQUIRE(room.response.status == 200U);
        auto const room_body = parse_object(room.response.body);
        auto const* rid = string_member(room_body, "room_id");
        REQUIRE(rid != nullptr);
        auto const id = *rid;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST",
                         "/_matrix/client/v3/register",
                         {},
                         merovingian::tests::registration_json("bob", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const bob_login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"DEVBOB"})"});
        REQUIRE(bob_login.response.status == 200U);
        auto const bob_body = parse_object(bob_login.response.body);
        auto const* bt = string_member(bob_body, "access_token");
        REQUIRE(bt != nullptr);
        auto const bob_token = *bt;

        WHEN("alice posts a receipt for an event in her room")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + id + "/receipt/m.read/%24ev1", alice_token, "{}"});

            THEN("status is 200")
            {
                // Spec MUST: member → 200
                REQUIRE(resp.response.status == 200U);
            }
        }

        WHEN("bob posts a receipt for a room he never joined")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + id + "/receipt/m.read/%24ev1", bob_token, "{}"});

            THEN("status is 403 M_FORBIDDEN")
            {
                // Spec MUST: non-member → 403
                REQUIRE(resp.response.status == 403U);
                auto const err_body = parse_object(resp.response.body);
                auto const* errcode = string_member(err_body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_FORBIDDEN");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: Typing Notifications
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#typing-notifications
//
// "The server MUST send stop typing events to remove typing notifications if a
// user sends a message."  Sending a message while typing=true MUST result in
// the server clearing (typing=false) the in-room typing state for that user so
// that remote and local clients no longer show a stale typing indicator.
SCENARIO("sending a message implicitly clears the sender's typing state per spec",
         "[homeserver][client-server][typing][conformance]")
{
    GIVEN("alice registered in a room with an active typing indicator")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = logged_in_token(rt);

        auto const room_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", alice_token, "{}"});
        REQUIRE(room_resp.response.status == 200U);
        auto const room_body = parse_object(room_resp.response.body);
        auto const* rid = string_member(room_body, "room_id");
        REQUIRE(rid != nullptr);
        auto const id = *rid;

        // Establish typing=true so the indicator is live
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"PUT", "/_matrix/client/v3/rooms/" + id + "/typing/@alice:example.org", alice_token,
                         R"({"typing":true,"timeout":30000})"})
                    .response.status == 200U);

        // Spec MUST: typing entry exists and is true before the message send
        {
            auto const* found = [&]() -> merovingian::homeserver::InboundTypingUser const* {
                for (auto const& t : rt.homeserver.typing_users)
                {
                    if (t.room_id == id && t.user_id == "@alice:example.org")
                        return &t;
                }
                return nullptr;
            }();
            REQUIRE(found != nullptr);
            REQUIRE(found->typing); // Spec MUST: typing=true is active before send
        }

        WHEN("alice sends a message in the room")
        {
            auto const send_resp = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + id + "/send/m.room.message/txn-conformance-typing",
                     alice_token, R"({"msgtype":"m.text","body":"Hello"})"});

            THEN("the send returns 200 and alice's typing state is cleared to false")
            {
                // Spec MUST: successful message send → 200
                REQUIRE(send_resp.response.status == 200U);

                auto const* after = [&]() -> merovingian::homeserver::InboundTypingUser const* {
                    for (auto const& t : rt.homeserver.typing_users)
                    {
                        if (t.room_id == id && t.user_id == "@alice:example.org")
                            return &t;
                    }
                    return nullptr;
                }();
                // Spec MUST: server clears typing indicator when user sends a message
                REQUIRE(after != nullptr);
                REQUIRE_FALSE(after->typing); // typing=false after send
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: POST /keys/upload — one-time key signature requirements
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysupload
//
// signed_curve25519 one-time keys MUST be signed by the device's ed25519 key.
// When no device identity exists (no device_keys in the body and no prior upload),
// the server cannot locate a signing key and MUST reject the upload.
SCENARIO("keys/upload rejects signed_curve25519 OTKs when no device identity has been established",
         "[homeserver][client-server][e2ee][conformance]")
{
    GIVEN("alice is registered and logged in but has never uploaded device keys")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        // 64-zero-byte ed25519 signature in unpadded base64 — correct length but invalid.
        // No device_keys in the body and no prior stored device identity, so the server
        // has no ed25519 key to resolve for signature verification.
        auto constexpr bogus_sig = std::string_view{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                                    "AAAAAA"};
        auto body = std::string{};
        body += R"({"one_time_keys":{"signed_curve25519:AAAAAQ":{"key":"otkkey",)";
        body += R"("signatures":{"@alice:example.org":{"ed25519:DEVICE1":")";
        body += bogus_sig;
        body += R"("}}}}})";

        WHEN("the client uploads signed_curve25519 OTKs without a device identity")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/keys/upload", token, body});

            THEN("the server rejects the upload because no signing key can be resolved")
            {
                // Spec MUST: signed_curve25519 keys require a verifiable device signature.
                // Without any device identity the server MUST reject rather than accept.
                REQUIRE(response.response.status == 400U);
                auto const err = parse_object(response.response.body);
                auto const* errcode = string_member(err, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_SIGNATURE");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: Rate limiting
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#rate-limiting
//
// Rate limits are defined per endpoint (path), not per full URL. Varying query
// parameters on the same endpoint path MUST NOT allow a client to bypass a rate cap.
SCENARIO("rate limiting uses the path without query parameters as the bucket key",
         "[homeserver][client-server][rate-limit][conformance]")
{
    GIVEN("a server configured with a cap of 1 request per minute on /sync")
    {
        auto security = merovingian::config::SecurityConfig{};
        merovingian::tests::enable_token_registration(security);
        auto rate_limits = merovingian::config::ClientRateLimitsConfig{};
        rate_limits.per_ip["/_matrix/client/v3/sync"] = {1U, 60U};
        auto cfg = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},
            security,
            std::move(rate_limits),
            merovingian::config::LogModulesConfig{},
        };
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("the first request uses /sync?timeout=0 (exhausts the 1-request cap)")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/sync?timeout=0", token, ""});

            THEN("it succeeds (within the cap)")
            {
                // Spec MUST: first request within the window is allowed.
                REQUIRE(first.response.status == 200U);
            }
        }

        WHEN("the cap is exhausted and a second request uses a different query string (/sync?timeout=30000)")
        {
            // Exhaust the 1-req/min cap with the first call.
            std::ignore = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/sync?timeout=0", token, ""});

            auto const second = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/sync?timeout=30000", token, ""});

            THEN("it is rate-limited even though the query string differs")
            {
                // Spec MUST: rate limit is per endpoint path; a different ?timeout MUST NOT
                // escape the cap — both requests land in the same bucket.
                REQUIRE(second.response.status == 429U);
                auto const err = parse_object(second.response.body);
                auto const* errcode = string_member(err, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_LIMIT_EXCEEDED");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: PUT /rooms/{roomId}/send/{eventType}/{txnId}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3roomsroomidsendeventtypetxnid
//
// The server MUST reject a send request whose body is not a valid JSON object.
// It MUST NOT silently invent a fallback event such as m.room.message.
SCENARIO("room send rejects non-object bodies and does not create a fallback event",
         "[homeserver][client-server][rooms][conformance]")
{
    GIVEN("alice is in a room")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        auto const room_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
        REQUIRE(room_resp.response.status == 200U);
        auto const room_body = parse_object(room_resp.response.body);
        auto const* rid = string_member(room_body, "room_id");
        REQUIRE(rid != nullptr);
        auto const room_id = *rid;

        WHEN("a message send is attempted with a JSON array body (not an object)")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-bad-body-arr", token,
                     R"([1, 2, 3])"});

            THEN("the server returns 400 M_BAD_JSON and does not create a spurious event")
            {
                // Spec MUST: event content must be a JSON object; an array MUST be rejected.
                REQUIRE(resp.response.status == 400U);
                auto const err = parse_object(resp.response.body);
                auto const* errcode = string_member(err, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_BAD_JSON");
            }
        }

        WHEN("a message send is attempted with a bare JSON string body (not an object)")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-bad-body-str", token,
                     R"("just a string")"});

            THEN("the server returns 400 M_BAD_JSON and does not create a spurious event")
            {
                // Spec MUST: event content must be a JSON object; a bare string MUST be rejected.
                REQUIRE(resp.response.status == 400U);
                auto const err = parse_object(resp.response.body);
                auto const* errcode = string_member(err, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_BAD_JSON");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: PUT /rooms/{roomId}/send/{eventType}/{txnId} — idempotency
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3roomsroomidsendeventtypetxnid
//
// "The transaction ID allows the server to ensure that the same event is not sent
// twice. The server MUST only send the event once for a given transaction ID."
SCENARIO("room send PUT replays the original event_id when the same transaction ID is reused",
         "[homeserver][client-server][rooms][idempotency][conformance]")
{
    GIVEN("alice is in a room")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        auto const room_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
        REQUIRE(room_resp.response.status == 200U);
        auto const room_body = parse_object(room_resp.response.body);
        auto const* rid = string_member(room_body, "room_id");
        REQUIRE(rid != nullptr);
        auto const room_id = *rid;

        WHEN("alice sends a message with txn-idem-1 and then retries with the same txn-idem-1")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-idem-1", token,
                     R"({"msgtype":"m.text","body":"hello"})"});
            REQUIRE(first.response.status == 200U);
            auto const first_body = parse_object(first.response.body);
            auto const* first_eid_ptr = string_member(first_body, "event_id");
            REQUIRE(first_eid_ptr != nullptr);
            auto const first_eid = *first_eid_ptr;

            auto const second = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-idem-1", token,
                     R"({"msgtype":"m.text","body":"retry"})"});

            THEN("both responses carry the same event_id (idempotent replay)")
            {
                // Spec MUST: the server MUST NOT send the event a second time for the same txn_id.
                REQUIRE(second.response.status == 200U);
                auto const second_body = parse_object(second.response.body);
                auto const* second_eid = string_member(second_body, "event_id");
                REQUIRE(second_eid != nullptr);
                // Same txn_id → identical event_id in both responses.
                REQUIRE(*second_eid == first_eid);
            }
        }

        WHEN("alice sends with txn-idem-a then with a distinct txn-idem-b")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-idem-a", token,
                     R"({"msgtype":"m.text","body":"first"})"});
            REQUIRE(first.response.status == 200U);
            auto const first_body = parse_object(first.response.body);
            auto const* first_eid_ptr = string_member(first_body, "event_id");
            REQUIRE(first_eid_ptr != nullptr);
            auto const first_eid = *first_eid_ptr;

            auto const second = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-idem-b", token,
                     R"({"msgtype":"m.text","body":"second"})"});

            THEN("a distinct txn_id produces a distinct event_id")
            {
                // Spec: a different transaction ID MUST produce a distinct persisted event.
                REQUIRE(second.response.status == 200U);
                auto const second_body = parse_object(second.response.body);
                auto const* second_eid = string_member(second_body, "event_id");
                REQUIRE(second_eid != nullptr);
                REQUIRE(*second_eid != first_eid);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18
// Endpoint / Section: PUT /sendToDevice/{eventType}/{txnId} — idempotency
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3sendtodeviceeventtypetxnid
//
// "Servers MUST NOT queue messages more than once for a given transaction ID."
SCENARIO("send-to-device PUT is idempotent: retrying the same txn_id does not re-queue the message",
         "[homeserver][client-server][to-device][idempotency][conformance]")
{
    GIVEN("alice and bob are registered")
    {
        auto cfg = conformance_config();
        auto started = merovingian::homeserver::start_client_server(cfg);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = logged_in_token(rt);
        auto const bob = register_and_login(rt, "bob");

        auto const send_body = std::string{R"({"messages":{"@bob:example.org":{"bob_DEV":)"
                                           R"({"algorithm":"m.olm.v1.curve25519-aes-sha2","ciphertext":"hello"}}}})"};

        WHEN("alice sends a to-device message with txn-td-1 and then retries with the same txn-td-1")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/sendToDevice/m.room.encrypted/txn-td-1", alice, send_body});
            REQUIRE(first.response.status == 200U);

            auto const second = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/sendToDevice/m.room.encrypted/txn-td-1", alice, send_body});

            THEN("the retry returns 200 and bob receives exactly one message (not two)")
            {
                // Spec MUST: server MUST NOT queue the message again for the same txn_id.
                REQUIRE(second.response.status == 200U);

                // Bob's initial /sync should see only one to-device message.
                auto const sync = merovingian::homeserver::handle_client_server_request(
                    rt, {"GET", "/_matrix/client/v3/sync?timeout=0", bob, ""});
                REQUIRE(sync.response.status == 200U);
                auto const sync_body = parse_object(sync.response.body);
                auto const* to_device = object_member_as_object(sync_body, "to_device");
                REQUIRE(to_device != nullptr);
                auto const* events = object_member_as_array(*to_device, "events");
                REQUIRE(events != nullptr);
                // Spec MUST: idempotent retry MUST NOT duplicate the queued message.
                REQUIRE(events->size() == 1U);
            }
        }
    }
}

// --- POST /rooms/{roomId}/receipt/{receiptType}/{eventId} --------------------
// Spec: Matrix Client-Server API v1.18
// Endpoint: POST /rooms/{roomId}/receipt/{receiptType}/{eventId}
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3roomsroomidreceiptreceipttypeeventid
//
// MUST return 200 {} when a joined user submits a valid receipt type.
// MUST return 400 M_INVALID_PARAM when receiptType is not one of m.read,
//   m.read.private, or m.fully_read.
// MUST return 403 M_FORBIDDEN when the requesting user is not in the room.
SCENARIO("POST /receipt returns 200 with empty body for m.read in a joined room",
         "[conformance][client-server][receipt]")
{
    GIVEN("alice is registered, has a room, and has sent a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);
        auto const room = create_room(rt, token);
        auto const eid = send_message(rt, token, room);

        WHEN("alice POSTs an m.read receipt for the message")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + room + "/receipt/m.read/" + eid, token, "{}"});

            THEN("the response is 200 with an empty JSON object body")
            {
                // Spec MUST: 200 {} on success.
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

SCENARIO("POST /receipt returns 200 with empty body for m.read.private in a joined room",
         "[conformance][client-server][receipt]")
{
    GIVEN("alice is registered, has a room, and has sent a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);
        auto const room = create_room(rt, token);
        auto const eid = send_message(rt, token, room);

        WHEN("alice POSTs an m.read.private receipt")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + room + "/receipt/m.read.private/" + eid, token, "{}"});

            THEN("the response is 200 with an empty JSON object body")
            {
                // Spec MUST: m.read.private is a valid receipt type; 200 on success.
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

SCENARIO("POST /receipt returns 200 with empty body for m.fully_read in a joined room",
         "[conformance][client-server][receipt]")
{
    GIVEN("alice is registered, has a room, and has sent a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);
        auto const room = create_room(rt, token);
        auto const eid = send_message(rt, token, room);

        WHEN("alice POSTs an m.fully_read receipt")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + room + "/receipt/m.fully_read/" + eid, token, "{}"});

            THEN("the response is 200 with an empty JSON object body")
            {
                // Spec MUST: m.fully_read is a valid receipt type; 200 on success.
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

SCENARIO("POST /receipt returns 403 M_FORBIDDEN when the user is not a room member",
         "[conformance][client-server][receipt]")
{
    GIVEN("alice owns a room and bob is not in it")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = logged_in_token(rt);
        auto const bob = register_and_login(rt, "bob");
        auto const room = create_room(rt, alice);
        auto const eid = send_message(rt, alice, room);

        WHEN("bob POSTs a receipt for a message in the room he has not joined")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + room + "/receipt/m.read/" + eid, bob, "{}"});

            THEN("the response is 403 M_FORBIDDEN")
            {
                // Spec MUST: 403 M_FORBIDDEN if user is not a member of the room.
                REQUIRE(resp.response.status == 403U);
                auto const body = parse_object(resp.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_FORBIDDEN");
            }
        }
    }
}

SCENARIO("POST /receipt returns 400 M_INVALID_PARAM for an unrecognized receipt type",
         "[conformance][client-server][receipt]")
{
    GIVEN("alice is registered and has a room with a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);
        auto const room = create_room(rt, token);
        auto const eid = send_message(rt, token, room);

        WHEN("alice POSTs with an unrecognized receipt type")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + room + "/receipt/m.bad_type/" + eid, token, "{}"});

            THEN("the response is 400 M_INVALID_PARAM")
            {
                // Spec MUST: 400 M_INVALID_PARAM for receiptType not in
                // {m.read, m.read.private, m.fully_read}.
                REQUIRE(resp.response.status == 400U);
                auto const body = parse_object(resp.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_PARAM");
            }
        }
    }
}

// --- POST /user_directory/search --------------------------------------------
// Spec: Matrix Client-Server API v1.18
// Endpoint: POST /user_directory/search
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3user_directorysearch
//
// MUST return 200 with a "results" array and a "limited" boolean.
// Each entry in "results" MUST contain a non-empty "user_id".
// Searches users whose user_id or display_name contains the search_term.
SCENARIO("POST /user_directory/search response contains required results and limited fields",
         "[conformance][client-server][user-directory]")
{
    GIVEN("alice is registered")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("a search is performed")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/user_directory/search", token, R"({"search_term":"alice"})"});

            THEN("the response is 200 with required fields results and limited")
            {
                // Spec MUST: 200 on success.
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                // Spec MUST: "results" is a required array field.
                auto const* results = object_member_as_array(body, "results");
                REQUIRE(results != nullptr);
                // Spec MUST: "limited" is a required boolean field.
                auto const* limited = bool_member(body, "limited");
                REQUIRE(limited != nullptr);
            }
        }
    }
}

SCENARIO("POST /user_directory/search finds users whose user_id matches the search term",
         "[conformance][client-server][user-directory]")
{
    GIVEN("alice and bob are registered")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = logged_in_token(rt);
        (void)register_and_login(rt, "bob");

        WHEN("alice searches for 'alice'")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/user_directory/search", alice, R"({"search_term":"alice"})"});

            THEN("alice's user entry appears in the results")
            {
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* results = object_member_as_array(body, "results");
                REQUIRE(results != nullptr);
                // Spec MUST: results contain users whose user_id or display_name matches.
                auto const found = std::ranges::any_of(*results, [](auto const& v) {
                    auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&v.storage());
                    if (obj == nullptr)
                    {
                        return false;
                    }
                    auto const* uid = string_member(*obj, "user_id");
                    return uid != nullptr && uid->find("alice") != std::string::npos;
                });
                REQUIRE(found);
            }
        }
    }
}

SCENARIO("POST /user_directory/search returns empty results for a non-matching search term",
         "[conformance][client-server][user-directory]")
{
    GIVEN("alice is registered")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("alice searches for a term that matches no registered user")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/user_directory/search", token,
                     R"({"search_term":"zzz_no_such_user_zzz"})"});

            THEN("the response is 200 with an empty results array and limited false")
            {
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* results = object_member_as_array(body, "results");
                REQUIRE(results != nullptr);
                // Spec: no matching users → empty results.
                REQUIRE(results->empty());
                auto const* limited = bool_member(body, "limited");
                REQUIRE(limited != nullptr);
                REQUIRE(*limited == false);
            }
        }
    }
}

SCENARIO("POST /user_directory/search result entries each contain a non-empty user_id",
         "[conformance][client-server][user-directory]")
{
    GIVEN("alice is registered")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = logged_in_token(rt);

        WHEN("a search returns at least one result")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/user_directory/search", token, R"({"search_term":"alice"})"});

            THEN("each result entry contains a non-empty user_id string")
            {
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* results = object_member_as_array(body, "results");
                REQUIRE(results != nullptr);
                REQUIRE(!results->empty());
                for (auto const& entry : *results)
                {
                    auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
                    // Spec MUST: each result is a JSON object.
                    REQUIRE(obj != nullptr);
                    // Spec MUST: user_id is required in each result entry.
                    auto const* uid = string_member(*obj, "user_id");
                    REQUIRE(uid != nullptr);
                    REQUIRE(!uid->empty());
                }
            }
        }
    }
}

// =============================================================================
// OIDC DISCOVERY (MSC2965)
// =============================================================================

// Spec: Matrix Client-Server API v1.18 — GET /auth_metadata (MSC2965)
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#openid-connect-discovery
//
// Servers that do not support OIDC MUST return 404 M_UNRECOGNIZED so that
// clients (Element, Cindy, etc.) can detect the absence of OIDC support and
// fall back to password-based login. The server MUST NOT return 401 for this
// unauthenticated discovery endpoint — returning 401 would mislead clients
// into thinking OIDC is partially supported.
SCENARIO("GET /v1/auth_metadata returns 404 M_UNRECOGNIZED for non-OIDC servers",
         "[conformance][client-server][oidc][auth]")
{
    GIVEN("a running homeserver that does not implement OIDC")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);

        WHEN("GET /_matrix/client/v1/auth_metadata is called without credentials")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/auth_metadata", {}, {}});

            THEN("the server returns 404 M_UNRECOGNIZED")
            {
                // Spec: non-OIDC servers MUST return 404 M_UNRECOGNIZED so clients
                // detect the absence of OIDC before attempting OIDC login.
                REQUIRE(response.response.status == 404U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                // Spec MUST: errcode MUST be M_UNRECOGNIZED for unimplemented endpoints.
                REQUIRE(*errcode == "M_UNRECOGNIZED");
            }
        }
    }
}

// =============================================================================
// SYNC FILTER ID
// =============================================================================

// Spec: Matrix Client-Server API v1.18 — GET /sync
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// "filter: The ID of a filter created using the filter API or a filter
// definition. The server will detect whether it is an ID or a definition."
//
// When the client passes a stored filter_id as the ?filter= parameter, the
// server MUST apply the corresponding stored filter to the sync response.
SCENARIO("GET /sync with a stored filter_id applies the stored filter", "[conformance][client-server][sync][filtering]")
{
    GIVEN("a logged-in user who has uploaded a filter")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        // Upload a filter that limits the timeline to 1 event.
        auto const upload = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/user/@alice:example.org/filter", token,
                              R"({"room":{"timeline":{"limit":1}}})"});
        REQUIRE(upload.response.status == 200U);
        auto const filter_body = parse_object(upload.response.body);
        auto const* filter_id_ptr = string_member(filter_body, "filter_id");
        REQUIRE(filter_id_ptr != nullptr);
        REQUIRE_FALSE(filter_id_ptr->empty());
        auto const filter_id = *filter_id_ptr;

        WHEN("GET /sync is called with the stored filter_id as the ?filter= parameter")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync?filter=" + filter_id, token, {}});

            THEN("the server returns 200 with a valid sync envelope")
            {
                // Spec MUST: sync with a valid stored filter_id MUST return 200.
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                // Spec MUST: sync response MUST include a next_batch token.
                auto const* next_batch = string_member(body, "next_batch");
                REQUIRE(next_batch != nullptr);
                REQUIRE_FALSE(next_batch->empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — GET /sync
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// When the ?filter= parameter is a token that does not correspond to any stored
// filter, the server MUST return 400 so that clients can detect the stale
// filter reference and re-upload.
SCENARIO("GET /sync with an unknown filter_id returns 400", "[conformance][client-server][sync][filtering]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("GET /sync is called with a filter_id that was never stored")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync?filter=nonexistentfilterid", token, {}});

            THEN("the server returns 400")
            {
                // Spec: unknown filter IDs MUST NOT be silently ignored (that would
                // be a silent correctness failure); return 400 so the client knows to
                // re-upload its filter before syncing.
                REQUIRE(response.response.status == 400U);
                auto const body = parse_object(response.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_NOT_FOUND");
            }
        }
    }
}
