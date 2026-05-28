// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include "federation_signing_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sodium.h>

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

[[nodiscard]] auto signed_request(std::string const& origin, std::string const& key_id, std::string const& key_seed,
                                  std::string const& body) -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "PUT";
    request.target = "/_matrix/federation/v1/send/txn123";
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = body;
    request.signature = merovingian::federation::make_federation_signature(
        request.origin, request.destination, request.method, request.target, request.body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

[[nodiscard]] auto pdu_for(std::string const& origin) -> std::string
{
    // A minimal valid JSON request body. The Matrix request-signing scheme
    // embeds the body as a parsed JSON object, so test bodies must be JSON.
    return R"({"origin":")" + origin + R"("})";
}

[[nodiscard]] auto comma_delimited_pdu(std::string const& origin) -> std::string
{
    // Legacy comma-delimited single-PDU encoding accepted by
    // parse_federation_pdu: event_id,room_id,type,sender,origin,key_id,signature.
    return "$event1:example.org,!room1:example.org,m.room.message,@alice:" + origin + ',' + origin +
           ",ed25519:auto,signature";
}

[[nodiscard]] auto sodium_is_ready() noexcept -> bool
{
    static auto const ready = sodium_init() >= 0;
    return ready;
}

auto derive_test_keypair(std::string_view key_material,
                         std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>& public_key,
                         std::array<unsigned char, crypto_sign_SECRETKEYBYTES>& secret_key) noexcept -> bool
{
    if (!sodium_is_ready())
    {
        return false;
    }
    auto seed = std::array<unsigned char, crypto_sign_SEEDBYTES>{};
    if (crypto_generichash(seed.data(), seed.size(), reinterpret_cast<unsigned char const*>(key_material.data()),
                           key_material.size(), nullptr, 0U) != 0)
    {
        return false;
    }
    return crypto_sign_seed_keypair(public_key.data(), secret_key.data(), seed.data()) == 0;
}

class FederationTestSigningStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit FederationTestSigningStore(merovingian::crypto::SigningKeyRecord key)
        : key_{std::move(key)}
    {
    }

    [[nodiscard]] auto active_key_for_server(std::string_view server_name)
        -> merovingian::crypto::SigningKeyLookupResult override
    {
        if (server_name != key_.server_name)
        {
            return {{}, "signing key not found"};
        }
        return {key_, {}};
    }

private:
    merovingian::crypto::SigningKeyRecord key_{};
};

class FederationTestEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    explicit FederationTestEd25519Provider(std::string key_material)
        : key_material_{std::move(key_material)}
    {
    }

    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const&, std::string_view message)
        -> merovingian::crypto::SignatureResult override
    {
        auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
        auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
        if (!derive_test_keypair(key_material_, public_key, secret_key))
        {
            return {{}, "unable to derive signing key"};
        }
        auto signature = std::string(crypto_sign_BYTES, '\0');
        if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                                 reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                 secret_key.data()) != 0)
        {
            return {{}, "signing failed"};
        }
        return {merovingian::crypto::Ed25519Signature{std::move(signature)}, {}};
    }

    [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const&, std::string_view,
                              merovingian::crypto::Ed25519Signature const&)
        -> merovingian::crypto::VerificationResult override
    {
        return {false, "test provider does not verify"};
    }

private:
    std::string key_material_{};
};

[[nodiscard]] auto signed_json_pdu(std::string const& origin, std::string const& key_id, std::string const& token)
    -> std::string
{
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(derive_test_keypair(token, public_key, secret_key));
    auto const event_json =
        "{\"auth_events\":[],\"content\":{\"body\":\"hi\",\"msgtype\":\"m.text\"},\"depth\":1,\"hashes\":{\"sha256\":"
        "\"hash\"},\"origin_server_ts\":1,\"prev_events\":[],\"room_id\":\"!room:example.org\",\"sender\":\"@alice:" +
        origin + "\",\"type\":\"m.room.message\"}";
    auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(policy != nullptr);
    auto store = FederationTestSigningStore{
        merovingian::crypto::SigningKeyRecord{
                                              origin, key_id,
                                              merovingian::crypto::Ed25519PublicKey{
                std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()}},
                                              true, }
    };
    auto provider = FederationTestEd25519Provider{token};
    auto signed_event = merovingian::events::sign_event_for_server(parsed.value, *policy, store, provider, origin);
    REQUIRE(signed_event.error.empty());
    return signed_event.event_json;
}

} // namespace

SCENARIO("Federation signing key summaries never disclose verification material", "[federation][inbound][security]")
{
    GIVEN("loaded key material")
    {
        WHEN("the signing boundary is created and summarized")
        {
            auto const key = merovingian::federation::load_server_signing_key("matrix.example.org", "ed25519:auto",
                                                                              "local-signing-material");
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

SCENARIO("Signed federation request verification rejects stale bad mismatched and uncanonical requests",
         "[federation][inbound][security]")
{
    GIVEN("a key record and signed request")
    {
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto key = merovingian::federation::FederationKeyRecord{};
        key.server_name = origin;
        key.key_id = key_id;
        key.valid_until_ts = 2000U;
        key.public_key_bytes = merovingian::federation::test::keypair_from_seed(token).public_key;
        auto expired_key = key;
        expired_key.valid_until_ts = 500U;
        auto valid = signed_request(origin, key_id, token, pdu_for(origin));
        auto mismatched = valid;
        mismatched.origin = "elsewhere.example.org";
        auto bad_signature = valid;
        bad_signature.signature = "sig:v1:wrong";
        auto uncanonical = valid;
        uncanonical.canonical_json_verified = false;

        WHEN("requests are verified against the remote signing key")
        {
            auto const accepted = merovingian::federation::verify_signed_federation_request(valid, key);
            auto const rejected_expired = merovingian::federation::verify_signed_federation_request(valid, expired_key);
            auto const rejected_mismatch =
                merovingian::federation::verify_signed_federation_request(mismatched, key);
            auto const rejected_bad_signature =
                merovingian::federation::verify_signed_federation_request(bad_signature, key);
            auto const rejected_uncanonical =
                merovingian::federation::verify_signed_federation_request(uncanonical, key);

            THEN("only the valid matching canonical signature from a live key is accepted")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected_expired.accepted);
                REQUIRE(rejected_expired.status == 502U);
                REQUIRE(rejected_expired.reason == "request signing key has expired");
                REQUIRE_FALSE(rejected_mismatch.accepted);
                REQUIRE(rejected_mismatch.status == 502U);
                REQUIRE(rejected_mismatch.reason == "request signing key does not match origin");
                REQUIRE_FALSE(rejected_bad_signature.accepted);
                REQUIRE(rejected_bad_signature.status == 502U);
                REQUIRE(rejected_bad_signature.reason == "request signature verification failed");
                REQUIRE_FALSE(rejected_uncanonical.accepted);
                REQUIRE(rejected_uncanonical.reason == "canonical JSON signature verification required");
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
        auto const json_pdu = signed_json_pdu(origin, key_id, token);
        auto const request = signed_request(origin, key_id, token, json_pdu);

        WHEN("the signed transaction is handled twice")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);
            auto const duplicate = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the transaction is accepted once and retries are idempotent")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body == R"({"pdus":{}})");
                REQUIRE(duplicate.status == 200U);
                REQUIRE(duplicate.body == R"({"pdus":{}})");
                REQUIRE(runtime.accepted_transactions.size() == 1U);
                REQUIRE(runtime.accepted_transactions.front().transaction_id == "txn123");
                REQUIRE(runtime.remotes.front().trust.consecutive_failures == 0U);
                REQUIRE(merovingian::federation::federation_audit_is_safe(runtime));
            }
        }
    }
}

SCENARIO("Inbound federation seeds discovery state for remotes resolved on demand",
         "[federation][inbound][transaction]")
{
    GIVEN("an unknown remote with an on-demand resolver that returns a full runtime record")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        runtime.remote_key_resolver =
            [origin, key_id, token](
                std::string_view server_name,
                std::string_view request_key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != origin || request_key_id != key_id)
            {
                return std::nullopt;
            }
            return remote_for(origin, key_id, token);
        };
        auto const json_pdu = signed_json_pdu(origin, key_id, token);
        auto const request = signed_request(origin, key_id, token, json_pdu);

        WHEN("the first signed request from that remote is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the resolved discovery and signing state allow the transaction")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body == R"({"pdus":{}})");
                REQUIRE(runtime.remotes.size() == 1U);
                REQUIRE(runtime.remotes.front().discovery.resolved_addresses ==
                        std::vector<std::string>{"203.0.113.10"});
                REQUIRE(runtime.remotes.front().trust.reputation_score == 100U);
            }
        }
    }
}

SCENARIO("Inbound federation handles non-transaction endpoints without PDU validation", "[federation][inbound][routes]")
{
    GIVEN("a runtime with a signed v1 invite request and an invite handler")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        // v1 invite body IS the bare signed event — the handler echoes it
        // back as the response payload. The shape is valid canonical JSON
        // so parse_invite_body succeeds without a v2 envelope.
        auto const invite_event_json = std::string{
            R"({"type":"m.room.member","state_key":"@alice:matrix.example.org","sender":"@alice:matrix.example.org",)"
            R"("room_id":"!room1:example.org","content":{"membership":"invite"}})"};
        auto invite_seen = std::make_shared<bool>(false);
        runtime.invite_handler = [invite_seen](merovingian::federation::InviteRequest const& request) {
            *invite_seen = true;
            auto result = merovingian::federation::InviteAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.signed_event_json = request.invite_event_json;
            return result;
        };
        auto request = signed_request(origin, key_id, token, invite_event_json);
        request.target = "/_matrix/federation/v1/invite/!room1:example.org/$event1:example.org";
        request.signature = merovingian::federation::make_federation_signature(
            origin, request.destination, request.method, request.target, request.body,
            merovingian::federation::test::keypair_from_seed(token).secret_key);

        WHEN("the request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the invite handler runs and produces a 200 response without transaction-validating the body")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*invite_seen);
                REQUIRE(runtime.accepted_transactions.empty());
            }
        }
    }
}

SCENARIO("Inbound federation rejects malformed send targets and unsigned PDUs", "[federation][inbound][security]")
{
    GIVEN("a runtime with malformed transaction requests")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto extra_segment = signed_request(origin, key_id, token, pdu_for(origin));
        extra_segment.target = "/_matrix/federation/v1/send/txn123/extra";
        extra_segment.signature = merovingian::federation::make_federation_signature(
            origin, extra_segment.destination, extra_segment.method, extra_segment.target, extra_segment.body,
            merovingian::federation::test::keypair_from_seed(token).secret_key);
        auto missing_signature = signed_request(origin, key_id, token, R"({"type":"m.room.message"})");

        WHEN("the requests are handled")
        {
            auto const bad_route = merovingian::federation::handle_inbound_federation_request(runtime, extra_segment);
            auto const bad_pdu = merovingian::federation::handle_inbound_federation_request(runtime, missing_signature);

            THEN("extra path segments fail closed with 404")
            {
                REQUIRE(bad_route.status == 404U);
                REQUIRE(bad_route.body == "federation route not found");
            }

            THEN("a PDU with missing required fields returns 200 with a per-PDU error — not 400 for the transaction")
            {
                // Per Matrix federation spec, individual PDU failures must be
                // reported inside {"pdus": {"$id": {"error": "..."}}} at HTTP 200.
                // Returning a non-200 causes the remote to back off all federation.
                REQUIRE(bad_pdu.status == 200U);
                REQUIRE(bad_pdu.body.find("\"pdus\"") != std::string::npos);
                REQUIRE(bad_pdu.body.find("\"error\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Inbound federation fails closed for unknown private denied and quarantined remotes",
         "[federation][inbound][security]")
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
            auto const unknown_response =
                merovingian::federation::handle_inbound_federation_request(unknown_runtime, request);
            auto const private_response =
                merovingian::federation::handle_inbound_federation_request(private_runtime, request);
            auto const denied_response =
                merovingian::federation::handle_inbound_federation_request(denied_runtime, request);
            auto const quarantined_response =
                merovingian::federation::handle_inbound_federation_request(quarantined_runtime, request);

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
                REQUIRE(first.status == 502U);
                REQUIRE(second.status == 502U);
                REQUIRE(third.status == 502U);
                REQUIRE(runtime.remotes.front().trust.consecutive_failures == 3U);
                REQUIRE(backoff.status == 429U);
                REQUIRE(backoff.body == "remote backoff required");
            }
        }
    }
}

SCENARIO("Federation PDU authorization rejects sender origin and event signature mismatches",
         "[federation][inbound][pdu]")
{
    GIVEN("PDUs with mismatched origin and signatures")
    {
        auto valid = merovingian::federation::parse_federation_pdu(comma_delimited_pdu("matrix.example.org"));
        auto bad_sender = valid;
        bad_sender.sender = "@alice:elsewhere.example.org";
        auto spoofed_sender = valid;
        spoofed_sender.sender = "@alice:matrix.example.org.evil";
        auto bad_signature = valid;
        bad_signature.signatures.front().server_name = "elsewhere.example.org";

        WHEN("PDUs are authorized")
        {
            auto const accepted = merovingian::federation::authorize_federation_pdu(valid, "matrix.example.org");
            auto const rejected_sender =
                merovingian::federation::authorize_federation_pdu(bad_sender, "matrix.example.org");
            auto const rejected_spoofed_sender =
                merovingian::federation::authorize_federation_pdu(spoofed_sender, "matrix.example.org");
            auto const rejected_signature =
                merovingian::federation::authorize_federation_pdu(bad_signature, "matrix.example.org");

            THEN("origin and signature mismatches fail closed")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected_sender.accepted);
                REQUIRE(rejected_sender.reason == "PDU sender does not match origin");
                REQUIRE_FALSE(rejected_spoofed_sender.accepted);
                REQUIRE(rejected_spoofed_sender.reason == "PDU sender does not match origin");
                REQUIRE_FALSE(rejected_signature.accepted);
                REQUIRE(rejected_signature.reason == "missing event signature for expected server");
            }
        }
    }
}

SCENARIO("Federation PDU authorization verifies JSON event signatures with the remote signing key",
         "[federation][inbound][pdu][signing]")
{
    GIVEN("a JSON PDU signed with the expected remote key material")
    {
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto const pdu = merovingian::federation::parse_federation_pdu(signed_json_pdu(origin, key_id, token));
        auto key = merovingian::federation::FederationKeyRecord{};
        key.server_name = origin;
        key.key_id = key_id;
        key.valid_until_ts = 2000U;
        key.public_key_bytes = merovingian::federation::test::keypair_from_seed(token).public_key;
        auto wrong_key = key;
        wrong_key.public_key_bytes = merovingian::federation::test::keypair_from_seed("wrong-token").public_key;

        WHEN("the PDU is authorized with matching and mismatching key material")
        {
            auto const accepted = merovingian::federation::authorize_federation_pdu(pdu, origin, key);
            auto const rejected = merovingian::federation::authorize_federation_pdu(pdu, origin, wrong_key);

            THEN("only the cryptographically verified event is accepted")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected.accepted);
                REQUIRE(rejected.reason == "signature verification failed");
            }
        }
    }
}

SCENARIO("Federation PDU authorization rejects comma-delimited PDUs when a signing key is available",
         "[federation][inbound][pdu][security]")
{
    GIVEN("a comma-delimited PDU without JSON and a signing key record")
    {
        auto const pdu_text =
            std::string{"$event1:example.org,!room1:example.org,m.room.message,@alice:matrix.example.org,"
                        "matrix.example.org,ed25519:auto,c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nz"
                        "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzcw=="};
        auto const pdu = merovingian::federation::parse_federation_pdu(pdu_text);
        auto key = merovingian::federation::FederationKeyRecord{};
        key.server_name = "matrix.example.org";
        key.key_id = "ed25519:auto";
        key.valid_until_ts = 2000U;
        key.public_key_bytes = merovingian::federation::test::keypair_from_seed("verify-token").public_key;

        WHEN("the comma-delimited PDU is authorized with a key record")
        {
            auto const decision = merovingian::federation::authorize_federation_pdu(pdu, "matrix.example.org", key);

            THEN("the PDU is rejected because legacy format cannot be cryptographically verified")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.reason == "comma-delimited PDUs require JSON for cryptographic verification");
            }
        }
    }
}
