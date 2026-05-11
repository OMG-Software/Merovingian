// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/federation/inbound_request.hpp>
#include <merovingian/federation/runtime_federation.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto runtime_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 4096U;
    config.remote_timeout_seconds = 30U;
    return config;
}

[[nodiscard]] auto remote_for(std::string const& origin, std::string const& key_id, std::string const& verify_token)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, verify_token, 2000U};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_request(
    std::string const& origin,
    std::string const& key_id,
    std::string const& verify_token,
    std::string const& body
) -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "PUT";
    request.target = "/_matrix/federation/v1/send/txn123";
    request.origin = origin;
    request.key_id = key_id;
    request.origin_server_ts = 1000U;
    request.now_ts = 1000U;
    request.body = body;
    request.signature = merovingian::federation::make_federation_signature(
        request.origin,
        request.key_id,
        verify_token,
        request.method,
        request.target,
        request.origin_server_ts,
        request.body
    );
    return request;
}

[[nodiscard]] auto pdu_for(std::string const& origin) -> std::string
{
    return "$event1:example.org,!room1:example.org,m.room.message,@alice:" + origin + ',' + origin + ",ed25519:auto,signature";
}

} // namespace

SCENARIO("Federation signing key summaries never disclose verification material", "[federation][inbound][security]")
{
    GIVEN("loaded key material")
    {
        WHEN("the signing boundary is created and summarized")
        {
            auto const key = merovingian::federation::load_server_signing_key("matrix.example.org", "ed25519:auto", "local-signing-material");
            auto const summary = merovingian::federation::signing_key_summary(key);

            THEN("the key is usable and the summary is redacted")
            {
                REQUIRE(key.loaded);
                REQUIRE(key.server_name == "matrix.example.org");
                REQUIRE(key.key_id == "ed25519:auto");
                REQUIRE_FALSE(key.verify_token.empty());
                REQUIRE(summary.find("matrix.example.org") != std::string::npos);
                REQUIRE(summary.find(key.verify_token) == std::string::npos);
                REQUIRE(summary.find("local-signing-material") == std::string::npos);
            }
        }
    }
}

SCENARIO("Signed federation request verification rejects stale bad or mismatched signatures", "[federation][inbound][security]")
{
    GIVEN("a key record and signed request")
    {
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto const key = merovingian::federation::FederationKeyRecord{origin, key_id, token, 2000U};
        auto valid = signed_request(origin, key_id, token, pdu_for(origin));
        auto stale = valid;
        stale.origin_server_ts = 10U;
        auto mismatched = valid;
        mismatched.origin = "elsewhere.example.org";
        auto bad_signature = valid;
        bad_signature.signature = "sig:v1:wrong";

        WHEN("requests are verified")
        {
            auto const accepted = merovingian::federation::verify_signed_federation_request(valid, key, 300U);
            auto const rejected_stale = merovingian::federation::verify_signed_federation_request(stale, key, 300U);
            auto const rejected_mismatch = merovingian::federation::verify_signed_federation_request(mismatched, key, 300U);
            auto const rejected_bad_signature = merovingian::federation::verify_signed_federation_request(bad_signature, key, 300U);

            THEN("only the fresh matching signature is accepted")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected_stale.accepted);
                REQUIRE(rejected_stale.status == 401U);
                REQUIRE_FALSE(rejected_mismatch.accepted);
                REQUIRE(rejected_mismatch.reason == "request signing key does not match origin");
                REQUIRE_FALSE(rejected_bad_signature.accepted);
                REQUIRE(rejected_bad_signature.reason == "request signature verification failed");
            }
        }
    }
}

SCENARIO("Inbound federation transaction accepts signed public trusted remotes", "[federation][inbound][transaction]")
{
    GIVEN("a runtime with a known public remote")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto const request = signed_request(origin, key_id, token, pdu_for(origin));

        WHEN("the signed transaction is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the transaction is accepted and audited safely")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body == "accepted pdus=1");
                REQUIRE(runtime.accepted_transactions.size() == 1U);
                REQUIRE(runtime.accepted_transactions.front().transaction_id == "txn123");
                REQUIRE(runtime.remotes.front().trust.consecutive_failures == 0U);
                REQUIRE(merovingian::federation::federation_audit_is_safe(runtime));
            }
        }
    }
}

SCENARIO("Inbound federation fails closed for unknown private denied and quarantined remotes", "[federation][inbound][security]")
{
    GIVEN("validly signed requests with failing remote controls")
    {
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto const request = signed_request(origin, key_id, token, pdu_for(origin));

        auto unknown_runtime = merovingian::federation::make_federation_runtime_state(runtime_config());

        auto private_runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto private_remote = remote_for(origin, key_id, token);
        private_remote.discovery.resolved_addresses = {"127.0.0.1"};
        merovingian::federation::upsert_remote(private_runtime, private_remote);

        auto denied_config = runtime_config();
        denied_config.denied_servers = {origin};
        auto denied_runtime = merovingian::federation::make_federation_runtime_state(denied_config);
        merovingian::federation::upsert_remote(denied_runtime, remote_for(origin, key_id, token));

        auto quarantined_runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto quarantined_remote = remote_for(origin, key_id, token);
        quarantined_remote.trust.quarantined = true;
        merovingian::federation::upsert_remote(quarantined_runtime, quarantined_remote);

        WHEN("each request is handled")
        {
            auto const unknown_response = merovingian::federation::handle_inbound_federation_request(unknown_runtime, request);
            auto const private_response = merovingian::federation::handle_inbound_federation_request(private_runtime, request);
            auto const denied_response = merovingian::federation::handle_inbound_federation_request(denied_runtime, request);
            auto const quarantined_response = merovingian::federation::handle_inbound_federation_request(quarantined_runtime, request);

            THEN("all failing controls reject the request")
            {
                REQUIRE(unknown_response.status == 403U);
                REQUIRE(unknown_response.body == "remote is unknown");
                REQUIRE(private_response.status == 403U);
                REQUIRE(private_response.body == "remote address is private or loopback");
                REQUIRE(denied_response.status == 403U);
                REQUIRE(denied_response.body == "remote server is denied");
                REQUIRE(quarantined_response.status == 403U);
                REQUIRE(quarantined_response.body == "remote server is quarantined");
            }
        }
    }
}

SCENARIO("Inbound federation applies backoff and increments failure count", "[federation][inbound][trust]")
{
    GIVEN("a remote with a bad signature and then a backoff state")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto bad_request = signed_request(origin, key_id, token, pdu_for(origin));
        bad_request.signature = "sig:v1:bad";

        WHEN("bad signatures accumulate")
        {
            auto const first = merovingian::federation::handle_inbound_federation_request(runtime, bad_request);
            auto const second = merovingian::federation::handle_inbound_federation_request(runtime, bad_request);
            auto const third = merovingian::federation::handle_inbound_federation_request(runtime, bad_request);
            auto const backoff = merovingian::federation::handle_inbound_federation_request(runtime, bad_request);

            THEN("failures are counted and backoff returns 429")
            {
                REQUIRE(first.status == 401U);
                REQUIRE(second.status == 401U);
                REQUIRE(third.status == 401U);
                REQUIRE(runtime.remotes.front().trust.consecutive_failures == 3U);
                REQUIRE(backoff.status == 429U);
                REQUIRE(backoff.body == "remote backoff required");
            }
        }
    }
}

SCENARIO("Federation PDU authorization rejects sender origin and event signature mismatches", "[federation][inbound][pdu]")
{
    GIVEN("PDUs with mismatched origin and signatures")
    {
        auto valid = merovingian::federation::parse_federation_pdu(pdu_for("matrix.example.org"));
        auto bad_sender = valid;
        bad_sender.sender = "@alice:elsewhere.example.org";
        auto bad_signature = valid;
        bad_signature.signatures.front().server_name = "elsewhere.example.org";

        WHEN("PDUs are authorized")
        {
            auto const accepted = merovingian::federation::authorize_federation_pdu(valid, "matrix.example.org");
            auto const rejected_sender = merovingian::federation::authorize_federation_pdu(bad_sender, "matrix.example.org");
            auto const rejected_signature = merovingian::federation::authorize_federation_pdu(bad_signature, "matrix.example.org");

            THEN("origin and signature mismatches fail closed")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected_sender.accepted);
                REQUIRE(rejected_sender.reason == "PDU sender does not match origin");
                REQUIRE_FALSE(rejected_signature.accepted);
                REQUIRE(rejected_signature.reason == "missing event signature for expected server");
            }
        }
    }
}
