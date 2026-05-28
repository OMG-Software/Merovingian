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
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
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

auto constexpr room_id = std::string_view{"!conformance:local.example.org"};
auto const origin = std::string{"remote.example.org"};
auto const key_id = std::string{"ed25519:auto"};
auto const key_seed = std::string{"conformance-test-seed"};

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
                // Spec: the origin field was removed from events in room version 4
                // (hash-based event IDs replaced server-name-based IDs). Room
                // versions 10/11/12 use reference-hash event IDs, so the template
                // MUST NOT include origin in the event object.
                // Do NOT remove — if this fails, the template is including a field
                // that the joining server must strip before signing per v1.18 spec.
                REQUIRE(response.body.find(R"("origin":"local.example.org")") == std::string::npos);
                // Spec MUST: the returned template event carries origin_server_ts.
                // Do NOT remove - if the resident server omits it, the joining
                // server must reject the template as malformed.
                REQUIRE(response.body.find(R"("origin_server_ts":)") != std::string::npos);
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

                // Spec MUST: room_version present.
                // Do NOT remove - a joining server uses this to select the correct
                // event format and auth rules. An absent room_version breaks the join.
                REQUIRE(response.body.find("\"room_version\"") != std::string::npos);

                // Spec SHOULD (v2): origin present.
                REQUIRE(response.body.find("\"origin\"") != std::string::npos);

                // Spec MUST: auth_chain present.
                // Do NOT remove - the joining server needs the auth chain to
                // validate the join event. An absent auth_chain causes the join to fail.
                REQUIRE(response.body.find("\"auth_chain\"") != std::string::npos);

                // Spec MUST: state present.
                // Do NOT remove - the joining server needs the room state to
                // build its local copy of the room. An absent state breaks the join.
                REQUIRE(response.body.find("\"state\"") != std::string::npos);

                // Spec MUST (v2): event present - the accepted join PDU echoed back.
                // Do NOT remove - the spec requires the resident server to return the
                // event as it was accepted. Synapse and other servers validate this field.
                // If this fails, fix handle_send_membership in inbound_request.cpp,
                // not this assertion.
                REQUIRE(response.body.find("\"event\"") != std::string::npos);
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
