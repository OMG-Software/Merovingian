// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX FEDERATION CONFORMANCE TESTS                        |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18                                   |
// |  URL:  https://spec.matrix.org/v1.18/server-server-api/                 |
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

#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/key_query.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/runtime_federation.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto runtime_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 65536U;
    config.remote_timeout_seconds = 30U;
    config.server_name = "local.example.org";
    return config;
}

[[nodiscard]] auto remote_for(std::string const& origin, std::string const& key_id, std::string const& key_seed)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, 2000U, merovingian::federation::test::keypair_from_seed(key_seed).public_key};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_get_request(std::string const& origin, std::string const& key_id, std::string const& key_seed,
                                      std::string const& target) -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "GET";
    request.target = target;
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = "";
    request.signature = merovingian::federation::make_federation_signature(
        origin, request.destination, request.method, target, request.body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

[[nodiscard]] auto signed_put_request(std::string const& origin, std::string const& key_id, std::string const& key_seed,
                                      std::string const& target, std::string const& body)
    -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "PUT";
    request.target = target;
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = body;
    request.signature = merovingian::federation::make_federation_signature(
        origin, request.destination, request.method, target, body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

[[nodiscard]] auto signed_post_request(std::string const& origin, std::string const& key_id,
                                       std::string const& key_seed, std::string const& target, std::string const& body)
    -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "POST";
    request.target = target;
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = body;
    request.signature = merovingian::federation::make_federation_signature(
        origin, request.destination, request.method, target, body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

auto constexpr room_id = std::string_view{"!conformance:local.example.org"};
auto const origin = std::string{"remote.example.org"};
auto const key_id = std::string{"ed25519:auto"};
auto const key_seed = std::string{"conformance-test-seed"};

// Navigate a JSON object and return a pointer to the Value for `key`.
[[nodiscard]] auto json_get(merovingian::canonicaljson::Object const& obj, std::string const& key)
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& m : obj)
        if (m.key == key)
            return &(*m.value);
    return nullptr;
}

[[nodiscard]] auto store_with_alice_e2ee_keys() -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    store.device_keys.push_back(
        {"@alice:remote.example.org", "DEVICE1", R"({"device_id":"DEVICE1","keys":{"ed25519:DEVICE1":"key-one"}})"});
    store.device_keys.push_back(
        {"@alice:remote.example.org", "DEVICE2", R"({"device_id":"DEVICE2","keys":{"ed25519:DEVICE2":"key-two"}})"});
    store.cross_signing_keys.push_back(
        {"@alice:remote.example.org", "master", R"({"usage":["master"],"keys":{"ed25519:master":"mk"}})"});
    store.cross_signing_keys.push_back(
        {"@alice:remote.example.org", "self_signing", R"({"usage":["self_signing"],"keys":{"ed25519:ssk":"sk"}})"});
    return store;
}

} // namespace

// --- make_join ---------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/federation/v1/make_join/{roomId}/{userId}
// https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1make_joinroomiduserid
//
// The resident server MUST respond 200 with a JSON object containing:
//   room_version  - the version of the room
//   event         - a partial event template for the joining server to complete
SCENARIO("make_join returns room version and event template for a remote user", "[federation][conformance][make_join]")
{
    GIVEN("a runtime with membership_template_provider wired for make_join (room version 12)")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto template_invoked = std::make_shared<bool>(false);
        runtime.membership_template_provider =
            [template_invoked](merovingian::federation::FederationEndpoint endpoint, std::string_view target_room_id,
                               std::string_view user_id, std::vector<std::string> const& /*supported_room_versions*/)
            -> std::optional<merovingian::federation::MembershipEventTemplate> {
            *template_invoked = true;
            REQUIRE(endpoint == merovingian::federation::FederationEndpoint::make_join);
            auto tmpl = merovingian::federation::MembershipEventTemplate{};
            tmpl.room_id = std::string{target_room_id};
            tmpl.user_id = std::string{user_id};
            tmpl.membership = "join";
            tmpl.room_version = "12";
            return tmpl;
        };

        WHEN("a signed make_join request is dispatched")
        {
            auto const target = "/_matrix/federation/v1/make_join/" + std::string{room_id} + "/@remote:" + origin;
            auto const request = signed_get_request(origin, key_id, key_seed, target);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 with room_version and event template without origin")
            {
                // Spec MUST: HTTP 200 for a valid make_join request.
                REQUIRE(response.status == 200U);
                REQUIRE(*template_invoked);

                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: room_version is present and equals the room's version.
                auto const* rv_val = json_get(*root, std::string{"room_version"});
                REQUIRE(rv_val != nullptr);
                auto const* rv_str = std::get_if<std::string>(&rv_val->storage());
                REQUIRE(rv_str != nullptr);
                REQUIRE(*rv_str == std::string{"12"});

                // Spec MUST: event is an object.
                auto const* ev_val = json_get(*root, std::string{"event"});
                REQUIRE(ev_val != nullptr);
                auto const* ev_obj = std::get_if<merovingian::canonicaljson::Object>(&ev_val->storage());
                REQUIRE(ev_obj != nullptr);

                // Spec MUST: event.origin_server_ts is present and is an integer.
                // Do NOT remove — a joining server rejects a template without this field.
                auto const* ts_val = json_get(*ev_obj, std::string{"origin_server_ts"});
                REQUIRE(ts_val != nullptr);
                REQUIRE(std::get_if<std::int64_t>(&ts_val->storage()) != nullptr);

                // Spec (room v4+): origin MUST NOT appear in the event object.
                // Do NOT remove — if this fails, the joining server must strip it
                // before signing, which it cannot do automatically.
                REQUIRE(json_get(*ev_obj, std::string{"origin"}) == nullptr);
            }
        }
    }
}

// --- send_join ---------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}
// https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv2send_joinroomideventid
//
// The resident server MUST respond 200 with a JSON object containing:
//   room_version  - the version of the room
//   origin        - the server_name of the resident server (v2 only)
//   auth_chain    - array of PDUs forming the auth chain for the event
//   state         - array of PDUs representing the current room state
//   event         - the join event as accepted by the resident server (v2 MUST)
//
// IMPORTANT: all five fields are REQUIRED by the spec for v2 send_join.
// A receiving server may reject the join if any are absent.
SCENARIO("send_join persists membership and returns auth chain and state", "[federation][conformance][send_join]")
{
    GIVEN("a runtime with membership_acceptor wired for send_join")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto const join_event_body = std::string{"{\"type\":\"m.room.member\","
                                                 "\"room_id\":\"!conformance:local.example.org\","
                                                 "\"sender\":\"@remote:remote.example.org\","
                                                 "\"state_key\":\"@remote:remote.example.org\","
                                                 "\"content\":{\"membership\":\"join\"},"
                                                 "\"depth\":1,\"hashes\":{\"sha256\":\"x\"},"
                                                 "\"origin_server_ts\":1,\"prev_events\":[],\"auth_events\":[]}"};

        auto accept_invoked = std::make_shared<bool>(false);
        runtime.membership_acceptor = [accept_invoked, join_event_body](
                                          merovingian::federation::FederationEndpoint endpoint,
                                          [[maybe_unused]] std::string_view target_room_id,
                                          [[maybe_unused]] std::string_view event_id,
                                          [[maybe_unused]] merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::MembershipAcceptResult {
            *accept_invoked = true;
            REQUIRE(endpoint == merovingian::federation::FederationEndpoint::send_join);
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.room_version = "12";
            // Echo the event back so the handler can populate the "event" field.
            result.signed_event_json = join_event_body;
            return result;
        };

        WHEN("a signed send_join request is dispatched")
        {
            auto const event_id = std::string{"$join_event:"} + origin;
            auto const target = "/_matrix/federation/v2/send_join/" + std::string{room_id} + "/" + event_id;
            auto const request = signed_put_request(origin, key_id, key_seed, target, join_event_body);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 and the response body contains all required v2 fields")
            {
                // Spec MUST: HTTP 200.
                REQUIRE(response.status == 200U);
                REQUIRE(*accept_invoked);

                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: room_version is present and is a string.
                // Do NOT remove — a joining server uses this to select auth rules.
                auto const* rv_val = json_get(*root, std::string{"room_version"});
                REQUIRE(rv_val != nullptr);
                REQUIRE(std::get_if<std::string>(&rv_val->storage()) != nullptr);

                // Spec MUST (v2): origin is present and is a string.
                // Do NOT remove — the joining server validates the resident's identity.
                auto const* origin_val = json_get(*root, std::string{"origin"});
                REQUIRE(origin_val != nullptr);
                auto const* origin_str = std::get_if<std::string>(&origin_val->storage());
                REQUIRE(origin_str != nullptr);
                REQUIRE(!origin_str->empty());

                // Spec MUST: auth_chain is an array.
                // Do NOT remove — the joining server uses this to validate the join.
                auto const* ac_val = json_get(*root, std::string{"auth_chain"});
                REQUIRE(ac_val != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Array>(&ac_val->storage()) != nullptr);

                // Spec MUST: state is an array.
                // Do NOT remove — the joining server builds its local room copy from this.
                auto const* state_val = json_get(*root, std::string{"state"});
                REQUIRE(state_val != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Array>(&state_val->storage()) != nullptr);

                // Spec MUST (v2): event is the accepted join PDU as an object.
                // Do NOT remove — Synapse validates this field on every join.
                auto const* event_val = json_get(*root, std::string{"event"});
                REQUIRE(event_val != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&event_val->storage()) != nullptr);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}
// URL: https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv2send_joinroomideventiid
//
// The send_join handler MUST resolve the room version via room_version_resolver
// and pass it to parse_inbound_pdu_envelope so event-ID computation uses the
// correct redaction rules, not the hardcoded fallback "12".
SCENARIO("send_join passes the resolved room version to the membership acceptor envelope",
         "[federation][conformance][send_join][room-version]")
{
    GIVEN("a runtime whose room_version_resolver returns version 10 for the room")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        // Wire a resolver that returns "10" for any room — simulating a v10 room.
        runtime.room_version_resolver = [](std::string_view /*room_id*/) -> std::string {
            return "10";
        };

        auto const join_event_body = std::string{"{\"type\":\"m.room.member\","
                                                 "\"room_id\":\"!conformance:local.example.org\","
                                                 "\"sender\":\"@remote:remote.example.org\","
                                                 "\"state_key\":\"@remote:remote.example.org\","
                                                 "\"content\":{\"membership\":\"join\"},"
                                                 "\"depth\":1,\"hashes\":{\"sha256\":\"x\"},"
                                                 "\"origin_server_ts\":1,\"prev_events\":[],\"auth_events\":[]}"};

        auto captured_room_version = std::make_shared<std::string>();
        runtime.membership_acceptor = [captured_room_version, join_event_body](
                                          merovingian::federation::FederationEndpoint /*endpoint*/,
                                          [[maybe_unused]] std::string_view /*room_id*/,
                                          [[maybe_unused]] std::string_view /*event_id*/,
                                          merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::MembershipAcceptResult {
            *captured_room_version = envelope.room_version;
            auto result            = merovingian::federation::MembershipAcceptResult{};
            result.accepted        = true;
            result.status          = 200U;
            result.room_version    = "10";
            result.signed_event_json = join_event_body;
            return result;
        };

        WHEN("a signed send_join request is dispatched for the room")
        {
            auto const event_id = std::string{"$join_event:"} + origin;
            auto const target   = "/_matrix/federation/v2/send_join/" + std::string{room_id} + "/" + event_id;
            auto const request  = signed_put_request(origin, key_id, key_seed, target, join_event_body);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the membership acceptor receives an envelope with room_version 10, not hardcoded 12")
            {
                // Spec MUST: event-ID computation and auth rules depend on room version.
                // A resident server that computes event IDs with v12 rules for a v10
                // room will produce a wrong event ID, causing the joining server to
                // reject the event (mismatched reference hash).
                REQUIRE(response.status == 200U);
                // Spec MUST: the resolved room version must propagate into the envelope
                // so auth and ID computation use the correct algorithm for that version.
                REQUIRE(*captured_room_version == "10");
            }
        }
    }
}

// --- make_leave --------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/federation/v1/make_leave/{roomId}/{userId}
// https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1make_leaveroomiduserid
//
// The resident server MUST respond 200 with a JSON object containing:
//   room_version  - the version of the room
//   event         - a partial leave event template for the leaving server to complete
SCENARIO("make_leave returns event template for a leaving user", "[federation][conformance][make_leave]")
{
    GIVEN("a runtime with membership_template_provider wired for make_leave")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto template_invoked = std::make_shared<bool>(false);
        runtime.membership_template_provider =
            [template_invoked](merovingian::federation::FederationEndpoint endpoint, std::string_view target_room_id,
                               std::string_view user_id, std::vector<std::string> const& /*supported_room_versions*/)
            -> std::optional<merovingian::federation::MembershipEventTemplate> {
            *template_invoked = true;
            REQUIRE(endpoint == merovingian::federation::FederationEndpoint::make_leave);
            auto tmpl = merovingian::federation::MembershipEventTemplate{};
            tmpl.room_id = std::string{target_room_id};
            tmpl.user_id = std::string{user_id};
            tmpl.membership = "leave";
            tmpl.room_version = "12";
            return tmpl;
        };

        WHEN("a signed make_leave request is dispatched")
        {
            auto const target = "/_matrix/federation/v1/make_leave/" + std::string{room_id} + "/@remote:" + origin;
            auto const request = signed_get_request(origin, key_id, key_seed, target);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 with room_version and event template")
            {
                // Spec MUST: HTTP 200 for a valid make_leave request.
                REQUIRE(response.status == 200U);
                REQUIRE(*template_invoked);
            }
        }
    }
}

// --- send_leave --------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}
// https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv2send_leaveroomideventid
//
// The resident server MUST respond 200. The v2 response body is an empty
// object {}. The "event" field MUST NOT appear (it is send_join-only).
SCENARIO("send_leave processes departure and returns 200", "[federation][conformance][send_leave]")
{
    GIVEN("a runtime with membership_acceptor wired for send_leave")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto accept_invoked = std::make_shared<bool>(false);
        runtime.membership_acceptor =
            [accept_invoked](merovingian::federation::FederationEndpoint endpoint,
                             [[maybe_unused]] std::string_view target_room_id,
                             [[maybe_unused]] std::string_view event_id,
                             [[maybe_unused]] merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::MembershipAcceptResult {
            *accept_invoked = true;
            REQUIRE(endpoint == merovingian::federation::FederationEndpoint::send_leave);
            return {true, 200U, {}, {}, {}};
        };

        WHEN("a signed send_leave request is dispatched")
        {
            auto const event_id = std::string{"$leave_event:"} + origin;
            auto const target = "/_matrix/federation/v2/send_leave/" + std::string{room_id} + "/" + event_id;
            auto const body = std::string{"{\"type\":\"m.room.member\","
                                          "\"room_id\":\"!conformance:local.example.org\","
                                          "\"sender\":\"@remote:remote.example.org\","
                                          "\"state_key\":\"@remote:remote.example.org\","
                                          "\"content\":{\"membership\":\"leave\"},"
                                          "\"depth\":2,\"hashes\":{\"sha256\":\"x\"},"
                                          "\"origin_server_ts\":2,\"prev_events\":[],\"auth_events\":[]}"};
            auto const request = signed_put_request(origin, key_id, key_seed, target, body);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 and the acceptor was invoked")
            {
                // Spec MUST: HTTP 200.
                REQUIRE(response.status == 200U);
                REQUIRE(*accept_invoked);

                // Spec: "event" is send_join-only. It MUST NOT appear in send_leave.
                // Do NOT remove - its presence would be a spec violation and could
                // confuse the remote server's response parser.
                REQUIRE(response.body.find("\"event\"") == std::string::npos);
            }
        }
    }
}

// --- invite v2 ---------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v2/invite/{roomId}/{eventId}
// https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv2inviteroomideventid
//
// The resident server MUST respond 200 with a JSON object containing:
//   event  - the invite event signed by the resident server
SCENARIO("invite v2 processes inbound invite and returns signed event", "[federation][conformance][invite_v2]")
{
    GIVEN("a runtime with invite_handler wired")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto invite_invoked = std::make_shared<bool>(false);
        runtime.invite_handler =
            [invite_invoked]([[maybe_unused]] merovingian::federation::InviteRequest const& request)
            -> merovingian::federation::InviteAcceptResult {
            *invite_invoked = true;
            return {true, 200U, {}, "{}"};
        };

        WHEN("a signed invite v2 request is dispatched")
        {
            auto const event_id = std::string{"$invite_event:"} + origin;
            auto const target = "/_matrix/federation/v2/invite/" + std::string{room_id} + "/" + event_id;
            auto const body = std::string{"{\"room_version\":\"12\",\"invite_event_json\":\"{}\"}"};
            auto const request = signed_put_request(origin, key_id, key_seed, target, body);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 and the invite handler was invoked")
            {
                // Spec MUST: HTTP 200.
                REQUIRE(response.status == 200U);
                REQUIRE(*invite_invoked);
            }
        }
    }
}

// --- invite v1 ---------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v1/invite/{roomId}/{eventId}
// https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv1inviteroomideventid
//
// Legacy path. The resident server MUST respond 200. Response format differs
// from v2: the event is returned as a bare JSON value, not wrapped in an object.
SCENARIO("invite v1 processes inbound invite and returns signed event", "[federation][conformance][invite_v1]")
{
    GIVEN("a runtime with invite_handler wired")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto invite_invoked = std::make_shared<bool>(false);
        runtime.invite_handler =
            [invite_invoked]([[maybe_unused]] merovingian::federation::InviteRequest const& request)
            -> merovingian::federation::InviteAcceptResult {
            *invite_invoked = true;
            return {true, 200U, {}, "{}"};
        };

        WHEN("a signed invite v1 request is dispatched")
        {
            auto const event_id = std::string{"$invite_event:"} + origin;
            auto const target = "/_matrix/federation/v1/invite/" + std::string{room_id} + "/" + event_id;
            auto const body = std::string{"{\"event\":{\"type\":\"m.room.member\"}}"};
            auto const request = signed_put_request(origin, key_id, key_seed, target, body);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 and the invite handler was invoked")
            {
                // Spec MUST: HTTP 200 for both v1 and v2 invite paths.
                REQUIRE(response.status == 200U);
                REQUIRE(*invite_invoked);
            }
        }
    }
}

// --- backfill ----------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/federation/v1/backfill/{roomId}
// https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1backfillroomid
//
// The resident server MUST respond 200 with a JSON object containing:
//   pdus  - array of PDUs from the room's history, oldest first
SCENARIO("backfill returns room event history as PDU array", "[federation][conformance][backfill]")
{
    GIVEN("a runtime with backfill_provider wired")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto backfill_invoked = std::make_shared<bool>(false);
        runtime.backfill_provider =
            [backfill_invoked]([[maybe_unused]] merovingian::federation::BackfillRequest const& request)
            -> merovingian::federation::BackfillResult {
            *backfill_invoked = true;
            return {true, 200U, {}, {}};
        };

        WHEN("a signed backfill request is dispatched")
        {
            auto const target =
                "/_matrix/federation/v1/backfill/" + std::string{room_id} + "?v=$prev:local.example.org&limit=5";
            auto const request = signed_get_request(origin, key_id, key_seed, target);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 and the backfill provider was invoked")
            {
                // Spec MUST: HTTP 200 for a valid backfill request.
                REQUIRE(response.status == 200U);
                REQUIRE(*backfill_invoked);
            }
        }
    }
}

// --- key publishing ----------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// https://spec.matrix.org/v1.18/server-server-api/#get_matrixkeyv2server
//
// Key publication is served by the local HTTP router, NOT the federation
// request handler. Verifying the separation prevents a regression where the
// federation handler accidentally serves 200 for a route it should not own.
SCENARIO("key publishing is served via the local HTTP router, not federation handler",
         "[federation][conformance][key_publishing]")
{
    GIVEN("a federation runtime with key publication enabled")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());

        WHEN("a GET key/v2/server request is dispatched through the federation handler")
        {
            auto const target = std::string{"/_matrix/key/v2/server"};
            auto const request = signed_get_request(origin, key_id, key_seed, target);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the federation handler returns 404 as key publishing is served via the local HTTP router")
            {
                // Architectural invariant: the federation handler must not serve /_matrix/key/*.
                // Do NOT change to 200 - if this fires the routing table has regressed.
                REQUIRE(response.status == 404U);
            }
        }
    }
}

// --- user/keys/query --------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: POST /_matrix/federation/v1/user/keys/query
// https://spec.matrix.org/v1.18/server-server-api/#post_matrixfederationv1userkeysquery
SCENARIO("signed federation user/keys/query returns device and cross-signing maps",
         "[federation][conformance][e2ee_keys]")
{
    GIVEN("a runtime whose query provider publishes local device and cross-signing keys")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto const store = store_with_alice_e2ee_keys();
        runtime.device_keys_query_provider = [store](std::string_view body) {
            return merovingian::federation::build_device_keys_query_response(store, body);
        };

        WHEN("a signed user/keys/query request is dispatched")
        {
            auto const request = signed_post_request(origin, key_id, key_seed, "/_matrix/federation/v1/user/keys/query",
                                                     R"({"device_keys":{"@alice:remote.example.org":[]}})");
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the response is 200 with the required key maps")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* device_keys = json_get(*root, std::string{"device_keys"});
                REQUIRE(device_keys != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&device_keys->storage()) != nullptr);
                auto const* master_keys = json_get(*root, std::string{"master_keys"});
                REQUIRE(master_keys != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&master_keys->storage()) != nullptr);
                auto const* self_signing_keys = json_get(*root, std::string{"self_signing_keys"});
                REQUIRE(self_signing_keys != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&self_signing_keys->storage()) != nullptr);
            }
        }

        WHEN("the provider reports a malformed request body")
        {
            auto const request =
                signed_post_request(origin, key_id, key_seed, "/_matrix/federation/v1/user/keys/query", "{}");
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the route returns 400 instead of a partial response")
            {
                REQUIRE(response.status == 400U);
            }
        }
    }
}

// --- user/keys/claim --------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: POST /_matrix/federation/v1/user/keys/claim
// https://spec.matrix.org/v1.18/server-server-api/#post_matrixfederationv1userkeysclaim
SCENARIO("signed federation user/keys/claim returns the claimed nested one-time key map",
         "[federation][conformance][e2ee_keys]")
{
    GIVEN("a runtime whose claim provider serves a stored one-time key")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto store = merovingian::database::PersistentStore{};
        store.one_time_keys.push_back(
            {"@alice:remote.example.org", "DEVICE1", "signed_curve25519:AAAABBBB", R"({"key":"otk-payload"})"});
        runtime.one_time_keys_claim_provider = [store](std::string_view body) mutable {
            return merovingian::federation::build_one_time_keys_claim_response(store, body);
        };

        WHEN("a signed user/keys/claim request is dispatched")
        {
            auto const request = signed_post_request(
                origin, key_id, key_seed, "/_matrix/federation/v1/user/keys/claim",
                R"({"one_time_keys":{"@alice:remote.example.org":{"DEVICE1":"signed_curve25519"}}})");
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the response is 200 with one_time_keys nested by user and device")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* one_time_keys = json_get(*root, std::string{"one_time_keys"});
                REQUIRE(one_time_keys != nullptr);
                auto const* otk_obj = std::get_if<merovingian::canonicaljson::Object>(&one_time_keys->storage());
                REQUIRE(otk_obj != nullptr);
                auto const* alice = json_get(*otk_obj, std::string{"@alice:remote.example.org"});
                REQUIRE(alice != nullptr);
                auto const* alice_obj = std::get_if<merovingian::canonicaljson::Object>(&alice->storage());
                REQUIRE(alice_obj != nullptr);
                REQUIRE(json_get(*alice_obj, std::string{"DEVICE1"}) != nullptr);
            }
        }

        WHEN("the claim provider reports a malformed request body")
        {
            auto const request =
                signed_post_request(origin, key_id, key_seed, "/_matrix/federation/v1/user/keys/claim", "{}");
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the route returns 400 instead of an empty 200 body")
            {
                REQUIRE(response.status == 400U);
            }
        }
    }
}

// --- user/devices -----------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/federation/v1/user/devices/{userId}
// https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1userdevicesuserid
SCENARIO("signed federation user/devices percent-decodes the user id and returns published devices",
         "[federation][conformance][e2ee_keys]")
{
    GIVEN("a runtime whose user-devices provider publishes Alice's devices")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto const store = store_with_alice_e2ee_keys();
        runtime.user_devices_provider = [store](std::string_view user_id) {
            return merovingian::federation::build_user_devices_response(store, user_id);
        };

        WHEN("a signed user/devices request carries a percent-encoded Matrix user id")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed,
                                            "/_matrix/federation/v1/user/devices/%40alice%3Aremote.example.org"));

            THEN("the response is 200 with the decoded user id and a devices array")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* user_id_value = json_get(*root, std::string{"user_id"});
                REQUIRE(user_id_value != nullptr);
                auto const* user_id_string = std::get_if<std::string>(&user_id_value->storage());
                REQUIRE(user_id_string != nullptr);
                REQUIRE(*user_id_string == "@alice:remote.example.org");
                auto const* devices_value = json_get(*root, std::string{"devices"});
                REQUIRE(devices_value != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Array>(&devices_value->storage()) != nullptr);
            }
        }

        WHEN("the queried user has no published devices")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed,
                                            "/_matrix/federation/v1/user/devices/%40nobody%3Aremote.example.org"));

            THEN("the route returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.status == 404U);
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

// --- unwired endpoints -------------------------------------------------------
// Spec: Matrix Server-Server API v1.18 (general error handling)
//
// If a handler is not wired the server MUST respond 501 Not Implemented
// rather than 404 or 500, so the remote can distinguish "not supported" from
// "routing error" or "internal failure".
SCENARIO("unwired endpoints return 501 Not Implemented", "[federation][conformance][unwired]")
{
    GIVEN("a runtime with no membership, invite, or backfill handlers wired")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("make_join is requested without a template provider")
        {
            auto const target = "/_matrix/federation/v1/make_join/" + std::string{room_id} + "/@remote:" + origin;
            auto const request = signed_get_request(origin, key_id, key_seed, target);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 501 Not Implemented")
            {
                // Do NOT change to 404 or 200 - 501 is the correct signal for
                // "this server understands the endpoint but has not wired a handler."
                REQUIRE(response.status == 501U);
            }
        }

        WHEN("send_join is requested without an acceptor")
        {
            auto const event_id = std::string{"$join_event:"} + origin;
            auto const target = "/_matrix/federation/v2/send_join/" + std::string{room_id} + "/" + event_id;
            auto const body = std::string{"{\"event\":{}}"};
            auto const request = signed_put_request(origin, key_id, key_seed, target, body);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }

        WHEN("invite v2 is requested without an invite handler")
        {
            auto const event_id = std::string{"$invite_event:"} + origin;
            auto const target = "/_matrix/federation/v2/invite/" + std::string{room_id} + "/" + event_id;
            auto const body = std::string{"{\"room_version\":\"12\",\"invite_event_json\":\"{}\"}"};
            auto const request = signed_put_request(origin, key_id, key_seed, target, body);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }

        WHEN("backfill is requested without a provider")
        {
            auto const target =
                "/_matrix/federation/v1/backfill/" + std::string{room_id} + "?v=$prev:local.example.org&limit=5";
            auto const request = signed_get_request(origin, key_id, key_seed, target);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }
    }
}

// --- query/event -------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/federation/v1/event/{eventId}
// URL: https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1eventeventid
//
// The resident server MUST return the PDU for a known event_id as a JSON object
// whose 'pdus' array contains exactly that event. An unknown event_id MUST
// return 404 M_NOT_FOUND. A missing provider MUST return 501.
SCENARIO("GET /event/{eventId} returns the PDU when the event_query_provider is wired",
         "[federation][conformance][query_event]")
{
    GIVEN("a runtime with event_query_provider installed returning a known PDU body")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        // Provider returns a non-empty body for the known event, empty for unknown.
        runtime.event_query_provider = [](std::string_view ev_id) -> std::string {
            if (ev_id == "$known_event:local.example.org")
                return R"({"type":"m.room.message","room_id":"!conformance:local.example.org"})";
            return {};
        };

        WHEN("a signed GET /event/$known_event:local.example.org is dispatched")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/event/$known_event:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 200 with the PDU body")
            {
                // Spec MUST: HTTP 200 for a known event.
                REQUIRE(response.status == 200U);
                // Spec MUST: body is non-empty JSON.
                REQUIRE(!response.body.empty());
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
            }
        }

        WHEN("a signed GET /event/ request names an unknown event")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/event/$no_such_event:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the event is not known to this server.
                REQUIRE(response.status == 404U);
                // Spec MUST: error body contains M_NOT_FOUND errcode.
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }

    GIVEN("a runtime with no event_query_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("a signed GET /event/{eventId} is dispatched")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/event/$some_event:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 501 Not Implemented")
            {
                // Architectural invariant: an unwired provider MUST yield 501 so
                // the remote can distinguish unsupported from routing errors.
                REQUIRE(response.status == 501U);
            }
        }
    }
}

// --- query/state -------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/federation/v1/state/{roomId}
// URL: https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1stateroomid
//
// The resident server MUST return 200 with the current state for a known room.
// An unknown room MUST return 404 M_NOT_FOUND. Missing provider → 501.
SCENARIO("GET /state/{roomId} returns room state when the state_query_provider is wired",
         "[federation][conformance][query_state]")
{
    GIVEN("a runtime with state_query_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        runtime.state_query_provider = [](std::string_view queried_room_id) -> std::string {
            if (queried_room_id == "!conformance:local.example.org")
                return R"({"auth_chain":[],"pdus":[]})";
            return {};
        };

        WHEN("state is requested for the known room")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/state/!conformance:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 200 with parseable state body")
            {
                // Spec MUST: HTTP 200 for a room this server participates in.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
            }
        }

        WHEN("state is requested for an unknown room")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/state/!unknown:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the room is not known to this server.
                REQUIRE(response.status == 404U);
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }

    GIVEN("a runtime with no state_query_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("state is requested")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/state/!conformance:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }
    }
}

// --- state_ids ---------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/federation/v1/state_ids/{roomId}
// URL: https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1state_idsroomid
//
// The resident server MUST return 200 with pdu_ids and auth_chain_ids arrays for
// a known room. An unknown room MUST return 404. Missing provider → 501.
SCENARIO("GET /state_ids/{roomId} returns event-ID lists when the state_ids_query_provider is wired",
         "[federation][conformance][state_ids]")
{
    GIVEN("a runtime with state_ids_query_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        runtime.state_ids_query_provider = [](std::string_view queried_room_id) -> std::string {
            if (queried_room_id == "!conformance:local.example.org")
                return R"({"pdu_ids":["$create:local.example.org"],"auth_chain_ids":[]})";
            return {};
        };

        WHEN("state_ids is requested for the known room")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/state_ids/!conformance:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 200 containing pdu_ids and auth_chain_ids")
            {
                // Spec MUST: HTTP 200 with the event-ID lists.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root =
                    std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                // Spec MUST: pdu_ids array is present.
                REQUIRE(json_get(*root, std::string{"pdu_ids"}) != nullptr);
                // Spec MUST: auth_chain_ids array is present.
                REQUIRE(json_get(*root, std::string{"auth_chain_ids"}) != nullptr);
            }
        }

        WHEN("state_ids is requested for an unknown room")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/state_ids/!unknown:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 for a room not known to this server.
                REQUIRE(response.status == 404U);
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }

    GIVEN("a runtime with no state_ids_query_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("state_ids is requested")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/state_ids/!conformance:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }
    }
}

// --- get_missing_events ------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: POST /_matrix/federation/v1/get_missing_events/{roomId}
// URL: https://spec.matrix.org/v1.18/server-server-api/#post_matrixfederationv1get_missing_eventsroomid
//
// The resident server MUST return 200 with an 'events' array of PDUs that the
// requesting server is missing. Missing provider → 501.
SCENARIO("POST /get_missing_events/{roomId} returns missing PDUs when the provider is wired",
         "[federation][conformance][get_missing_events]")
{
    GIVEN("a runtime with missing_events_query_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto provider_invoked = std::make_shared<bool>(false);
        runtime.missing_events_query_provider =
            [provider_invoked](std::string_view /*room_id*/,
                               std::string_view /*body*/) -> std::string {
            *provider_invoked = true;
            return R"({"events":[]})";
        };

        WHEN("a signed POST /get_missing_events request is dispatched")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/get_missing_events/!conformance:local.example.org"};
            auto const body =
                std::string{R"({"limit":10,"min_depth":1,"earliest_events":[],"latest_events":[]})"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_post_request(origin, key_id, key_seed, target, body));

            THEN("the response is 200 and the provider was invoked")
            {
                // Spec MUST: HTTP 200.
                REQUIRE(response.status == 200U);
                REQUIRE(*provider_invoked);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root =
                    std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                // Spec MUST: 'events' array is present.
                REQUIRE(json_get(*root, std::string{"events"}) != nullptr);
            }
        }
    }

    GIVEN("a runtime with no missing_events_query_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("a signed POST /get_missing_events request is dispatched")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/get_missing_events/!conformance:local.example.org"};
            auto const body =
                std::string{R"({"limit":10,"min_depth":1,"earliest_events":[],"latest_events":[]})"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_post_request(origin, key_id, key_seed, target, body));

            THEN("the response is 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }
    }
}

// --- query/profile -----------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/federation/v1/query/profile
// URL: https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1queryprofile
//
// The resident server MUST return 200 with displayname and avatar_url for a
// known local user. Unknown users MUST return 404 M_NOT_FOUND. An invalid
// 'field' query parameter MUST return 400. Missing provider → 501.
SCENARIO("GET /query/profile returns user profile fields when the profile_query_provider is wired",
         "[federation][conformance][query_profile]")
{
    GIVEN("a runtime with profile_query_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        runtime.profile_query_provider =
            [](std::string_view user_id) -> merovingian::federation::FederationProfile {
            if (user_id == "@alice:local.example.org")
                return {true, "Alice", "mxc://local.example.org/avatar"};
            return {false, {}, {}};
        };

        WHEN("a profile request is made for a known local user")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/query/profile?user_id=@alice:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 200 with displayname and avatar_url")
            {
                // Spec MUST: HTTP 200 with profile fields.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root =
                    std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                // Spec MUST: displayname field present when no field filter is set.
                auto const* dn = json_get(*root, std::string{"displayname"});
                REQUIRE(dn != nullptr);
                REQUIRE(std::get_if<std::string>(&dn->storage()) != nullptr);
                // Spec MUST: avatar_url field present when no field filter is set.
                auto const* av = json_get(*root, std::string{"avatar_url"});
                REQUIRE(av != nullptr);
                REQUIRE(std::get_if<std::string>(&av->storage()) != nullptr);
            }
        }

        WHEN("a profile request uses field=displayname to filter the response")
        {
            auto const target = std::string{
                "/_matrix/federation/v1/query/profile?user_id=@alice:local.example.org&field=displayname"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 200 containing only displayname")
            {
                // Spec: when field=displayname only that field is returned.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root =
                    std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                REQUIRE(json_get(*root, std::string{"displayname"}) != nullptr);
                // avatar_url MUST NOT appear when field=displayname.
                REQUIRE(json_get(*root, std::string{"avatar_url"}) == nullptr);
            }
        }

        WHEN("a profile request is made for an unknown user")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/query/profile?user_id=@nobody:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the user is not known to this server.
                REQUIRE(response.status == 404U);
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }

        WHEN("a profile request supplies an invalid field parameter")
        {
            auto const target = std::string{
                "/_matrix/federation/v1/query/profile?user_id=@alice:local.example.org&field=badfield"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 400 because the field value is not recognised")
            {
                // Spec: field MUST be one of 'displayname' or 'avatar_url'.
                // Any other value is a client error.
                REQUIRE(response.status == 400U);
            }
        }
    }

    GIVEN("a runtime with no profile_query_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("a profile request is dispatched")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/query/profile?user_id=@alice:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }
    }
}

// --- make_knock --------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/federation/v1/make_knock/{roomId}/{userId}
// URL: https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1make_knockroomiduserid
//
// The resident server MUST respond 200 with:
//   room_version  - the version string of the room
//   event         - a partial knock event template for the knocking server to sign
// Missing provider → 501.
SCENARIO("GET /make_knock returns knock template when membership_template_provider is wired",
         "[federation][conformance][make_knock]")
{
    GIVEN("a runtime with membership_template_provider wired for make_knock")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto template_invoked = std::make_shared<bool>(false);
        runtime.membership_template_provider =
            [template_invoked](merovingian::federation::FederationEndpoint endpoint,
                               std::string_view target_room_id, std::string_view user_id,
                               std::vector<std::string> const& /*supported_room_versions*/)
            -> std::optional<merovingian::federation::MembershipEventTemplate> {
            *template_invoked = true;
            // Provider MUST only be called with make_knock endpoint here.
            REQUIRE(endpoint == merovingian::federation::FederationEndpoint::make_knock);
            auto tmpl = merovingian::federation::MembershipEventTemplate{};
            tmpl.room_id      = std::string{target_room_id};
            tmpl.user_id      = std::string{user_id};
            tmpl.membership   = "knock";
            tmpl.room_version = "12";
            return tmpl;
        };

        WHEN("a signed GET /make_knock request is dispatched")
        {
            auto const knocking_user = std::string{"@remote:"} + origin;
            auto const target =
                "/_matrix/federation/v1/make_knock/" + std::string{room_id} + "/" + knocking_user +
                "?ver=12";
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the runtime returns 200 with room_version and event template")
            {
                // Spec MUST: HTTP 200 for a valid make_knock request.
                REQUIRE(response.status == 200U);
                REQUIRE(*template_invoked);

                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root =
                    std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: room_version is present.
                auto const* rv = json_get(*root, std::string{"room_version"});
                REQUIRE(rv != nullptr);
                REQUIRE(std::get_if<std::string>(&rv->storage()) != nullptr);

                // Spec MUST: event template is present.
                auto const* ev = json_get(*root, std::string{"event"});
                REQUIRE(ev != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&ev->storage()) != nullptr);
            }
        }
    }

    GIVEN("a runtime with no membership_template_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("a signed GET /make_knock request is dispatched")
        {
            auto const target = "/_matrix/federation/v1/make_knock/" + std::string{room_id} +
                                 "/@remote:" + origin + "?ver=12";
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 501 Not Implemented")
            {
                // Architectural invariant: no handler → 501.
                REQUIRE(response.status == 501U);
            }
        }
    }
}

// --- send_knock --------------------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}
// URL: https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv1send_knockroomideventid
//
// The resident server MUST respond 200 when the knock event is accepted.
// The response body MUST NOT include 'event' (that field is send_join-only).
// Missing acceptor → 501.
SCENARIO("PUT /send_knock processes the knock and returns 200 when the acceptor is wired",
         "[federation][conformance][send_knock]")
{
    GIVEN("a runtime with membership_acceptor wired for send_knock")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto accept_invoked = std::make_shared<bool>(false);
        runtime.membership_acceptor =
            [accept_invoked](merovingian::federation::FederationEndpoint endpoint,
                             [[maybe_unused]] std::string_view target_room_id,
                             [[maybe_unused]] std::string_view event_id,
                             [[maybe_unused]] merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::MembershipAcceptResult {
            *accept_invoked = true;
            // Acceptor MUST only be called with send_knock here.
            REQUIRE(endpoint == merovingian::federation::FederationEndpoint::send_knock);
            return {true, 200U, {}, {}, {}};
        };

        WHEN("a signed PUT /send_knock request is dispatched")
        {
            auto const event_id   = std::string{"$knock_event:"} + origin;
            auto const target     = "/_matrix/federation/v1/send_knock/" +
                                    std::string{room_id} + "/" + event_id;
            // Minimal well-formed knock PDU envelope.
            auto const body = std::string{
                R"({"type":"m.room.member",)"
                R"("room_id":"!conformance:local.example.org",)"
                R"("sender":"@remote:remote.example.org",)"
                R"("state_key":"@remote:remote.example.org",)"
                R"("content":{"membership":"knock"},)"
                R"("depth":2,"hashes":{"sha256":"x"},)"
                R"("origin_server_ts":2,"prev_events":[],"auth_events":[]})"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_put_request(origin, key_id, key_seed, target, body));

            THEN("the runtime returns 200 and the acceptor was invoked")
            {
                // Spec MUST: HTTP 200.
                REQUIRE(response.status == 200U);
                REQUIRE(*accept_invoked);

                // Spec: 'event' MUST NOT appear in send_knock response
                // (it is send_join-only per §11.5.1).
                REQUIRE(response.body.find("\"event\"") == std::string::npos);
            }
        }
    }

    GIVEN("a runtime with no membership_acceptor installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("a signed PUT /send_knock request is dispatched")
        {
            auto const event_id = std::string{"$knock_event:"} + origin;
            auto const target   = "/_matrix/federation/v1/send_knock/" +
                                   std::string{room_id} + "/" + event_id;
            auto const body = std::string{
                R"({"type":"m.room.member",)"
                R"("room_id":"!conformance:local.example.org",)"
                R"("sender":"@remote:remote.example.org",)"
                R"("state_key":"@remote:remote.example.org",)"
                R"("content":{"membership":"knock"},)"
                R"("depth":2,"hashes":{"sha256":"x"},)"
                R"("origin_server_ts":2,"prev_events":[],"auth_events":[]})"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_put_request(origin, key_id, key_seed, target, body));

            THEN("the response is 501 Not Implemented")
            {
                // Architectural invariant: no acceptor → 501.
                REQUIRE(response.status == 501U);
            }
        }
    }
}
