// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  SECURITY FIX TESTS — Issues #460-#463                                   |
// |                                                                         |
// |  BDD tests for the four security fixes introduced in 0.10.62.           |
// |  Each scenario follows GIVEN/WHEN/THEN and tests the security invariant |
// |  the fix establishes — not implementation details.                      |
// +-------------------------------------------------------------------------+

#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include "../support/registration_token.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <sodium.h>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto federation_runtime_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 16384U;
    config.remote_timeout_seconds = 30U;
    config.server_name = "example.org";
    return config;
}

auto constexpr local_server = "example.org";
auto constexpr remote_origin = "remote.example.org";
auto constexpr remote_key_id = "ed25519:auto";
auto constexpr remote_key_seed = "security-test-remote-seed";

[[nodiscard]] auto remote_for_test() -> merovingian::federation::FederationRemoteRuntime
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

[[nodiscard]] auto signed_put(std::string const& target, std::string const& body)
    -> merovingian::federation::SignedFederationRequest
{
    auto req = merovingian::federation::SignedFederationRequest{};
    req.method = "PUT";
    req.target = target;
    req.origin = remote_origin;
    req.destination = local_server;
    req.key_id = remote_key_id;
    req.now_ts = 1000U;
    req.canonical_json_verified = true;
    req.body = body;
    req.signature = merovingian::federation::make_federation_signature(
        req.origin, req.destination, req.method, target, body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return req;
}

// Build a properly signed m.room.member join PDU from the remote server.
[[nodiscard]] auto make_signed_join_pdu(std::string const& room_id, std::string const& sender,
                                         std::vector<std::string> const& auth_events = {})
    -> std::string
{
    // Build the unsigned event JSON (no hashes or signatures — sign_event_for_server
    // computes and attaches both).
    auto auth_events_json = std::string{"["};
    for (std::size_t i = 0U; i < auth_events.size(); ++i)
    {
        if (i != 0U)
        {
            auth_events_json += ',';
        }
        auth_events_json += "\"" + auth_events[i] + "\"";
    }
    auth_events_json += "]";

    auto const unsigned_json =
        std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id + "\",\"sender\":\"" + sender +
        "\",\"state_key\":\"" + sender + "\",\"content\":{\"membership\":\"join\"},\"depth\":6,\"origin_server_ts\":2000," +
        "\"prev_events\":[],\"auth_events\":" + auth_events_json + "}";

    return merovingian::federation::test::make_signed_event_json(unsigned_json, remote_origin, remote_key_id,
                                                                 remote_key_seed, "12");
}

// Build a properly signed m.room.member invite PDU from the remote server.
[[nodiscard]] auto
make_signed_invite_pdu(std::string const& room_id, std::string const& sender, std::string const& state_key)
    -> std::string
{
    auto const unsigned_json =
        std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id + "\",\"sender\":\"" + sender +
        "\",\"state_key\":\"" + state_key + "\",\"content\":{\"membership\":\"invite\"},\"depth\":1,\"origin_server_ts\":1000," +
        "\"prev_events\":[],\"auth_events\":[]}";

    return merovingian::federation::test::make_signed_event_json(unsigned_json, remote_origin, remote_key_id,
                                                                 remote_key_seed, "12");
}

// Build a v2 invite body wrapping a signed invite event.
[[nodiscard]] auto make_v2_invite_body(std::string const& signed_event_json) -> std::string
{
    return std::string{"{\"room_version\":\"12\",\"event\":"} + signed_event_json + ",\"invite_room_state\":[]}";
}

} // namespace

// ===========================================================================
// Issue #460: Unauthenticated media download/thumbnail via v1 endpoints
// ===========================================================================
// Spec: Matrix v1.18 §13.8 — GET /_matrix/client/v1/media/download and
// /_matrix/client/v1/media/thumbnail require an access token.
//
// GIVEN a locally-stored media blob
// WHEN an unauthenticated GET /_matrix/client/v1/media/download/{serverName}/{mediaId} is sent
// THEN the server responds 401 and does not return the blob
// (and the same for /thumbnail/).
SCENARIO("Unauthenticated v1 media download is rejected with 401", "[security][media][auth][issue-460]")
{
    GIVEN("a started client-server runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        // The test only needs to verify the auth gate stops the request.
        // No media blob needs to be planted — the request must never reach
        // the media handler.
        auto const server_name = std::string{local_server};
        auto const media_id = std::string{"test-media-id-460"};

        WHEN("an unauthenticated GET v1 media download is dispatched")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/" + server_name + "/" + media_id, "", ""});

            THEN("the server responds 401 M_MISSING_TOKEN and does not return any media")
            {
                REQUIRE(result.response.status == 401U);
                REQUIRE(result.response.body.find("M_MISSING_TOKEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("Unauthenticated v1 media thumbnail is rejected with 401", "[security][media][auth][issue-460]")
{
    GIVEN("a started client-server runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const server_name = std::string{local_server};
        auto const media_id = std::string{"test-thumb-id-460"};

        WHEN("an unauthenticated GET v1 media thumbnail is dispatched")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v1/media/thumbnail/" + server_name + "/" + media_id + "?width=32&height=32", "", ""});

            THEN("the server responds 401 M_MISSING_TOKEN and does not return any media")
            {
                REQUIRE(result.response.status == 401U);
                REQUIRE(result.response.body.find("M_MISSING_TOKEN") != std::string::npos);
            }
        }
    }
}

// ===========================================================================
// Issue #461: Forged membership events — send_join/send_leave/send_knock
//             skip PDU signature, content-hash, and auth-rules verification
// ===========================================================================
// Spec: src/federation/AGENTS.md rule 2 — "Verify every inbound PDU's signature
// against the sending server's published key before allowing it to enter the
// event graph. Unverified events must be silently dropped."
//
// GIVEN a send_join PDU whose own signature is invalid
// WHEN a federated server submits it
// THEN the resident server rejects the event (does not persist, does not upsert membership)
SCENARIO("send_join with invalid PDU signature is rejected", "[security][federation][issue-461]")
{
    GIVEN("a federation runtime with a membership acceptor and a remote server")
    {
        REQUIRE(sodium_init() >= 0);
        auto runtime = merovingian::federation::make_federation_runtime_state(federation_runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_test());

        auto acceptor_called = std::make_shared<bool>(false);
        runtime.membership_acceptor =
            [acceptor_called](merovingian::federation::FederationEndpoint, std::string_view,
                              std::string_view, merovingian::federation::InboundPduEnvelope const&)
            -> merovingian::federation::MembershipAcceptResult {
            *acceptor_called = true;
            return {true, 200U, {}, {}, {}, "12", {}};
        };

        auto const room_id = std::string{"!room461:example.org"};
        auto const sender = std::string{"@alice:"} + remote_origin;
        auto const join_event_id = std::string{"$join461:"} + remote_origin;

        // Build a PDU with a FAKE signature — the event claims to be signed by
        // remote.example.org but the signature is garbage.
        auto const forged_join_body =
            std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id + "\",\"sender\":\"" + sender +
            "\",\"state_key\":\"" + sender + "\",\"content\":{\"membership\":\"join\"},\"depth\":6," +
            "\"hashes\":{\"sha256\":\"x\"},\"origin_server_ts\":2000,\"prev_events\":[],\"auth_events\":[]," +
            "\"signatures\":{\"remote.example.org\":{\"ed25519:auto\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}}";

        auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join_event_id;

        WHEN("the forged send_join is handled")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime, signed_put(target, forged_join_body));

            THEN("the server rejects the PDU and does not call the membership acceptor")
            {
                REQUIRE(response.status != 200U);
                REQUIRE_FALSE(*acceptor_called);
            }
        }
    }
}

SCENARIO("send_join with valid PDU signature is accepted", "[security][federation][issue-461]")
{
    GIVEN("a federation runtime with a membership acceptor and a remote server")
    {
        REQUIRE(sodium_init() >= 0);
        auto runtime = merovingian::federation::make_federation_runtime_state(federation_runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_test());

        auto acceptor_called = std::make_shared<bool>(false);
        runtime.membership_acceptor =
            [acceptor_called](merovingian::federation::FederationEndpoint, std::string_view,
                              std::string_view, merovingian::federation::InboundPduEnvelope const&)
            -> merovingian::federation::MembershipAcceptResult {
            *acceptor_called = true;
            return {true, 200U, {}, {}, {}, "12", {}};
        };

        auto const room_id = std::string{"!room461b:example.org"};
        auto const sender = std::string{"@alice:"} + remote_origin;
        auto const join_event_id = std::string{"$join461b:"} + remote_origin;

        // Build a PROPERLY signed join PDU.
        auto const signed_join = make_signed_join_pdu(room_id, sender);
        REQUIRE_FALSE(signed_join.empty());

        auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join_event_id;

        WHEN(" the valid send_join is handled")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime, signed_put(target, signed_join));

            THEN("the server accepts the PDU and calls the membership acceptor")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*acceptor_called);
            }
        }
    }
}

SCENARIO("send_join with sender domain mismatch is rejected", "[security][federation][issue-461]")
{
    GIVEN("a federation runtime with a membership acceptor and a remote server")
    {
        REQUIRE(sodium_init() >= 0);
        auto runtime = merovingian::federation::make_federation_runtime_state(federation_runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_test());

        auto acceptor_called = std::make_shared<bool>(false);
        runtime.membership_acceptor =
            [acceptor_called](merovingian::federation::FederationEndpoint, std::string_view,
                              std::string_view, merovingian::federation::InboundPduEnvelope const&)
            -> merovingian::federation::MembershipAcceptResult {
            *acceptor_called = true;
            return {true, 200U, {}, {}, {}, "12", {}};
        };

        auto const room_id = std::string{"!room461c:example.org"};
        // Sender claims to be from a DIFFERENT server than the X-Matrix origin.
        auto const sender = std::string{"@victim:evil.example.org"};
        auto const join_event_id = std::string{"$join461c:"} + remote_origin;

        // Build a signed PDU — but signed with remote.example.org's key while
        // the sender claims to be from evil.example.org. The key record is for
        // remote.example.org, so the sender domain won't match the key.
        auto const unsigned_json =
            std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id + "\",\"sender\":\"" + sender +
            "\",\"state_key\":\"" + sender + "\",\"content\":{\"membership\":\"join\"},\"depth\":6," +
            "\"origin_server_ts\":2000,\"prev_events\":[],\"auth_events\":[]}";

        // Sign with remote's key but the sender domain is evil.example.org.
        auto const signed_join = merovingian::federation::test::make_signed_event_json(
            unsigned_json, remote_origin, remote_key_id, remote_key_seed, "12");
        REQUIRE_FALSE(signed_join.empty());

        auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join_event_id;

        WHEN("the mismatched send_join is handled")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime, signed_put(target, signed_join));

            THEN("the server rejects the PDU because the sender domain does not match the key")
            {
                REQUIRE(response.status != 200U);
                REQUIRE_FALSE(*acceptor_called);
            }
        }
    }
}

// ===========================================================================
// Issue #462: Forged invite events — invite path skips signature verification
//             and origin/sender check
// ===========================================================================
// Spec: Matrix v1.18 §server-server-api:4217-4225 — reject with M_INVALID_PARAM
// when the signature fails or the sender is not on the origin server.
//
// GIVEN an invite event whose signature does not verify
// WHEN a federated server submits PUT /_matrix/federation/v2/invite/{roomId}/{eventId}
// THEN the receiving server returns an error and does not persist or re-sign the invite
SCENARIO("invite with invalid PDU signature is rejected", "[security][federation][issue-462]")
{
    GIVEN("a federation runtime with an invite handler and a remote server")
    {
        REQUIRE(sodium_init() >= 0);
        auto runtime = merovingian::federation::make_federation_runtime_state(federation_runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_test());

        auto handler_called = std::make_shared<bool>(false);
        runtime.invite_handler =
            [handler_called](merovingian::federation::InviteRequest const&) -> merovingian::federation::InviteAcceptResult {
            *handler_called = true;
            return {true, 200U, {}, "signed"};
        };

        auto const room_id = std::string{"!room462:example.org"};
        auto const sender = std::string{"@remote_host:"} + remote_origin;
        auto const target_user = std::string{"@local_user:"} + local_server;
        auto const invite_event_id = std::string{"$invite462:"} + remote_origin;

        // Forged invite event with a garbage signature.
        auto const forged_invite_body =
            std::string{"{\"room_version\":\"12\",\"event\":{\"type\":\"m.room.member\",\"state_key\":\""} + target_user +
            "\",\"content\":{\"membership\":\"invite\"},\"room_id\":\"" + room_id + "\",\"sender\":\"" + sender +
            "\",\"event_id\":\"" + invite_event_id +
            "\",\"depth\":1,\"prev_events\":[],\"auth_events\":[],\"hashes\":{\"sha256\":\"x\"}," +
            "\"origin_server_ts\":1000,\"signatures\":{\"remote.example.org\":{\"ed25519:auto\":\"AAAA\"}}}," +
            "\"invite_room_state\":[]}";

        auto const target = "/_matrix/federation/v2/invite/" + room_id + "/" + invite_event_id;

        WHEN("the forged invite is handled")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime, signed_put(target, forged_invite_body));

            THEN("the server rejects the invite and does not call the invite handler")
            {
                REQUIRE(response.status != 200U);
                REQUIRE_FALSE(*handler_called);
            }
        }
    }
}

SCENARIO("invite with valid PDU signature is accepted", "[security][federation][issue-462]")
{
    GIVEN("a federation runtime with an invite handler and a remote server")
    {
        REQUIRE(sodium_init() >= 0);
        auto runtime = merovingian::federation::make_federation_runtime_state(federation_runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_test());

        auto handler_called = std::make_shared<bool>(false);
        runtime.invite_handler =
            [handler_called](merovingian::federation::InviteRequest const& req)
            -> merovingian::federation::InviteAcceptResult {
            *handler_called = true;
            return {true, 200U, {}, req.invite_event_json};
        };

        auto const room_id = std::string{"!room462b:example.org"};
        auto const sender = std::string{"@remote_host:"} + remote_origin;
        auto const target_user = std::string{"@local_user:"} + local_server;
        auto const invite_event_id = std::string{"$invite462b:"} + remote_origin;

        // Build a properly signed invite event.
        auto const signed_invite = make_signed_invite_pdu(room_id, sender, target_user);
        REQUIRE_FALSE(signed_invite.empty());

        auto const invite_body = make_v2_invite_body(signed_invite);
        auto const target = "/_matrix/federation/v2/invite/" + room_id + "/" + invite_event_id;

        WHEN("the valid invite is handled")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime, signed_put(target, invite_body));

            THEN("the server accepts the invite and calls the invite handler")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*handler_called);
            }
        }
    }
}

SCENARIO("invite with sender/origin mismatch is rejected", "[security][federation][issue-462]")
{
    GIVEN("a federation runtime with an invite handler and a remote server")
    {
        REQUIRE(sodium_init() >= 0);
        auto runtime = merovingian::federation::make_federation_runtime_state(federation_runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_test());

        auto handler_called = std::make_shared<bool>(false);
        runtime.invite_handler =
            [handler_called](merovingian::federation::InviteRequest const&) -> merovingian::federation::InviteAcceptResult {
            *handler_called = true;
            return {true, 200U, {}, "signed"};
        };

        auto const room_id = std::string{"!room462c:example.org"};
        // Sender claims to be from a DIFFERENT server than the X-Matrix origin.
        auto const sender = std::string{"@evil:evil.example.org"};
        auto const target_user = std::string{"@local_user:"} + local_server;
        auto const invite_event_id = std::string{"$invite462c:"} + remote_origin;

        // Build a signed PDU signed by remote.example.org but with sender from evil.example.org.
        auto const unsigned_json =
            std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id + "\",\"sender\":\"" + sender +
            "\",\"state_key\":\"" + target_user + "\",\"content\":{\"membership\":\"invite\"},\"depth\":1," +
            "\"origin_server_ts\":1000,\"prev_events\":[],\"auth_events\":[]}";

        auto const signed_invite = merovingian::federation::test::make_signed_event_json(
            unsigned_json, remote_origin, remote_key_id, remote_key_seed, "12");
        REQUIRE_FALSE(signed_invite.empty());

        auto const invite_body = make_v2_invite_body(signed_invite);
        auto const target = "/_matrix/federation/v2/invite/" + room_id + "/" + invite_event_id;

        WHEN(" the mismatched invite is handled")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime, signed_put(target, invite_body));

            THEN("the server rejects the invite because the sender domain does not match the origin")
            {
                REQUIRE(response.status != 200U);
                REQUIRE_FALSE(*handler_called);
            }
        }
    }
}

// ===========================================================================
// Issue #463: Raw bearer access tokens written to logs and audit_log
// ===========================================================================
// GIVEN a request with a valid bearer token that triggers a pre-auth rejection
// WHEN the audit entry is recorded
// THEN the actor field in the audit_events contains a placeholder, never the raw token
SCENARIO("audit log actor field never contains the raw bearer token on 413 rejection",
         "[security][audit][issue-463]")
{
    GIVEN("a started client-server runtime and a raw bearer token")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const raw_token = std::string{"sct_secret_bearer_token_463_should_never_appear"};

        // Build an oversized request body to trigger the 413 path.
        auto const body = std::string(100000, 'x'); // > 64 KiB default body limit

        WHEN("the oversized request is dispatched (triggers 413 pre-auth)")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/sendToDevice/m.room_key_request/txn463", raw_token, body});

            THEN("the server responds 413 and the audit log actor never contains the raw token")
            {
                REQUIRE(result.response.status == 413U);

                // Check every audit event — none should contain the raw token.
                auto const& audit_events = runtime.homeserver.database.audit_events;
                for (auto const& event : audit_events)
                {
                    REQUIRE(event.actor.find(raw_token) == std::string::npos);
                }
            }
        }
    }
}

SCENARIO("audit log actor field never contains the raw bearer token on 429 rejection",
         "[security][audit][issue-463]")
{
    GIVEN("a started client-server runtime and a logged-in user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        // Register and login a user to get a real access token.
        auto const registered = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/register", "",
                      merovingian::tests::registration_json("rate_test_user_463", "CorrectHorse7!")});
        REQUIRE(registered.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/login", "",
                      "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"rate_test_user_463\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"DEV463\"}"});
        REQUIRE(login.response.status == 200U);

        // Extract the access token from the login response.
        auto const& login_body = login.response.body;
        auto const token_begin = login_body.find("\"access_token\":\"");
        REQUIRE(token_begin != std::string::npos);
        auto const token_start = token_begin + std::string{"\"access_token\":\""}.size();
        auto const token_end = login_body.find('"', token_start);
        REQUIRE(token_end != std::string::npos);
        auto const real_token = login_body.substr(token_start, token_end - token_start);

        // Install a strict per-user rate limit to trigger 429 quickly.
        merovingian::homeserver::install_test_per_user_rate_limit_engine(runtime);

        WHEN("multiple requests are sent to trigger rate limiting")
        {
            auto got_429 = false;
            for (auto i = 0; i < 10 && !got_429; ++i)
            {
                auto const result = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/account/whoami", real_token, ""});
                if (result.response.status == 429U)
                {
                    got_429 = true;
                }
            }

            THEN("at least one 429 was returned and the audit log actor never contains the raw token")
            {
                REQUIRE(got_429);

                auto const& audit_events = runtime.homeserver.database.audit_events;
                for (auto const& event : audit_events)
                {
                    REQUIRE(event.actor.find(real_token) == std::string::npos);
                }
            }
        }
    }
}