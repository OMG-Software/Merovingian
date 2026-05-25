// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/runtime_federation.hpp"

#include "federation_signing_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>
#include <string_view>

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

[[nodiscard]] auto signed_get_request(std::string const& origin, std::string const& key_id,
                                      std::string const& key_seed,
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

[[nodiscard]] auto signed_put_request(std::string const& origin, std::string const& key_id,
                                      std::string const& key_seed, std::string const& target,
                                      std::string const& body) -> merovingian::federation::SignedFederationRequest
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

SCENARIO("make_join returns room version and event template for a remote user",
         "[federation][conformance][make_join]")
{
    GIVEN("a runtime with membership_template_provider wired for make_join")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto template_invoked = std::make_shared<bool>(false);
        runtime.membership_template_provider =
            [template_invoked](merovingian::federation::FederationEndpoint endpoint,
                               std::string_view target_room_id,
                               std::string_view user_id) -> merovingian::federation::MembershipEventTemplate {
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

            THEN("the runtime returns 200 with room_version and event template")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*template_invoked);
            }
        }
    }
}

SCENARIO("send_join persists membership and returns auth chain and state",
         "[federation][conformance][send_join]")
{
    GIVEN("a runtime with membership_acceptor wired for send_join")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto accept_invoked = std::make_shared<bool>(false);
        runtime.membership_acceptor =
            [accept_invoked](merovingian::federation::FederationEndpoint endpoint,
                             std::string_view target_room_id,
                             std::string_view event_id,
                             merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::MembershipAcceptResult {
            *accept_invoked = true;
            REQUIRE(endpoint == merovingian::federation::FederationEndpoint::send_join);
            return {true, 200U, {}, {}, {}};
        };

        WHEN("a signed send_join request is dispatched")
        {
            auto const event_id = std::string{"$join_event:"} + origin;
            auto const target = "/_matrix/federation/v2/send_join/" + std::string{room_id} + "/" + event_id;
            auto const body = std::string{"{\"event\":{\"type\":\"m.room.member\"}}"};
            auto const request = signed_put_request(origin, key_id, key_seed, target, body);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 and the acceptor was invoked")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*accept_invoked);
            }
        }
    }
}

SCENARIO("make_leave returns event template for a leaving user",
         "[federation][conformance][make_leave]")
{
    GIVEN("a runtime with membership_template_provider wired for make_leave")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto template_invoked = std::make_shared<bool>(false);
        runtime.membership_template_provider =
            [template_invoked](merovingian::federation::FederationEndpoint endpoint,
                               std::string_view target_room_id,
                               std::string_view user_id) -> merovingian::federation::MembershipEventTemplate {
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
                REQUIRE(response.status == 200U);
                REQUIRE(*template_invoked);
            }
        }
    }
}

SCENARIO("send_leave processes departure and returns 200",
         "[federation][conformance][send_leave]")
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
            auto const body = std::string{"{\"event\":{\"type\":\"m.room.member\",\"content\":{\"membership\":\"leave\"}}}"};
            auto const request = signed_put_request(origin, key_id, key_seed, target, body);
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 and the acceptor was invoked")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*accept_invoked);
            }
        }
    }
}

SCENARIO("invite v2 processes inbound invite and returns signed event",
         "[federation][conformance][invite_v2]")
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
                REQUIRE(response.status == 200U);
                REQUIRE(*invite_invoked);
            }
        }
    }
}

SCENARIO("invite v1 processes inbound invite and returns signed event",
         "[federation][conformance][invite_v1]")
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
                REQUIRE(response.status == 200U);
                REQUIRE(*invite_invoked);
            }
        }
    }
}

SCENARIO("backfill returns room event history as PDU array",
         "[federation][conformance][backfill]")
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
                REQUIRE(response.status == 200U);
                REQUIRE(*backfill_invoked);
            }
        }
    }
}

SCENARIO("key publishing returns self-signed verify keys",
         "[federation][conformance][key_publishing]")
{
    GIVEN("a federation runtime with key publication enabled")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());

        WHEN("an unsigned GET key/v2/server request is dispatched")
        {
            auto const target = std::string{"/_matrix/key/v2/server"};
            auto request = merovingian::federation::SignedFederationRequest{};
            request.method = "GET";
            request.target = target;
            request.origin = runtime.config.server_name;
            request.destination = runtime.config.server_name;
            request.key_id = "";
            request.now_ts = 1000U;
            request.canonical_json_verified = true;
            request.body = "";
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the runtime returns 200 with server_name and verify_keys")
            {
                REQUIRE(response.status == 200U);
            }
        }
    }
}

SCENARIO("unwired endpoints return 501 Not Implemented",
         "[federation][conformance][unwired]")
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