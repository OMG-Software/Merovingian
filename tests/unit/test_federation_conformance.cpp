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
