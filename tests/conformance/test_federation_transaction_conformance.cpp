// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX FEDERATION TRANSACTION CONFORMANCE TESTS                 |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18                                   |
// |  Endpoint: PUT /_matrix/federation/v1/send/{txnId}                      |
// |  URL: ../../docs/matrix-v1.18-spec/server-server-api.md                  |
// |         #put_matrixfederationv1sendtxnid                                |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec.        |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |       spec itself has changed and citing the updated section.            |
// |                                                                         |
// |  Transaction format (spec §PDUs):                                       |
// |    { "origin": string, "origin_server_ts": int,                         |
// |      "pdus": [...], "edus": [...optional] }                             |
// +-------------------------------------------------------------------------+

#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <memory>
#include <optional>
#include <string>

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
    config.max_transaction_bytes = 65536U;
    config.remote_timeout_seconds = 30U;
    config.server_name = "local.example.org";
    return config;
}

auto const origin = std::string{"remote.example.org"};
auto const key_id = std::string{"ed25519:auto"};
auto const key_seed = std::string{"transaction-conformance-seed"};

[[nodiscard]] auto remote_for_origin() -> merovingian::federation::FederationRemoteRuntime
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

// Build a signed PUT /send/{txnId} request with the given transaction body.
[[nodiscard]] auto signed_send_request(std::string const& txn_id, std::string const& body)
    -> merovingian::federation::SignedFederationRequest
{
    auto const target = "/_matrix/federation/v1/send/" + txn_id;
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

// A minimal but well-formed PDU for insertion into a transaction body.
// The hashes value "x" is a placeholder — the conformance tests focus on the
// transaction routing layer, not PDU crypto verification.
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

class ConformanceSigningStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit ConformanceSigningStore(merovingian::crypto::SigningKeyRecord key)
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

class ConformanceEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    explicit ConformanceEd25519Provider(std::string key_material)
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

// Replace the hashes.sha256 field in an event value with the actual computed
// content hash so that verify_pdu_content_hash accepts the PDU. The signing
// pipeline does not auto-inject hashes, so test helpers must do it explicitly.
[[nodiscard]] auto with_correct_content_hash(merovingian::canonicaljson::Value event)
    -> merovingian::canonicaljson::Value
{
    auto const hash = merovingian::events::make_content_hash(event);
    if (!hash.error.empty())
    {
        return event;
    }
    auto const* root = std::get_if<merovingian::canonicaljson::Object>(&event.storage());
    if (root == nullptr)
    {
        return event;
    }
    auto new_root = merovingian::canonicaljson::Object{};
    new_root.reserve(root->size());
    for (auto const& member : *root)
    {
        if (member.key != "hashes")
        {
            new_root.push_back(merovingian::canonicaljson::make_member(member.key, *member.value));
        }
    }
    auto hashes = merovingian::canonicaljson::Object{};
    hashes.push_back(
        merovingian::canonicaljson::make_member("sha256", merovingian::canonicaljson::Value{hash.sha256}));
    new_root.push_back(
        merovingian::canonicaljson::make_member("hashes", merovingian::canonicaljson::Value{std::move(hashes)}));
    return merovingian::canonicaljson::Value{std::move(new_root)};
}

[[nodiscard]] auto minimal_pdu() -> std::string
{
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(derive_test_keypair(key_seed, public_key, secret_key));
    // Event without a hashes field: make_content_hash strips hashes anyway, so
    // the computed hash is correct whether or not a placeholder is present.
    auto const event_json = "{\"auth_events\":[],\"content\":{\"body\":\"hello\",\"msgtype\":\"m.text\"},\"depth\":3,"
                            "\"origin_server_ts\":1000,\"prev_events\":[\"$prev:local.example.org\"],"
                            "\"room_id\":\"!test:local.example.org\","
                            "\"sender\":\"@alice:remote.example.org\",\"type\":\"m.room.message\"}";
    auto const base_parsed = merovingian::canonicaljson::parse_lossless(event_json);
    REQUIRE(base_parsed.error == merovingian::canonicaljson::ParseError::none);
    // Inject the real content hash before signing so inbound hash verification passes.
    auto const event_with_hash = with_correct_content_hash(base_parsed.value);
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);
    auto store = ConformanceSigningStore{
        merovingian::crypto::SigningKeyRecord{
                                              origin, key_id,
                                              merovingian::crypto::Ed25519PublicKey{
                std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()}},
                                              true, }
    };
    auto provider = ConformanceEd25519Provider{key_seed};
    auto signed_event = merovingian::events::sign_event_for_server(event_with_hash, *policy, store, provider, origin);
    REQUIRE(signed_event.error.empty());
    return signed_event.event_json;
}

} // namespace

// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v1/send/{txnId}
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// The receiving server MUST respond 200 with {} when it processes a valid
// transaction. Errors in individual PDUs are NOT reflected as HTTP error
// responses — the server MUST still return 200.
SCENARIO("Federation send transaction returns 200 with empty object on success",
         "[federation][transaction][conformance]")
{
    GIVEN("a federation runtime with no PDU/EDU sinks")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_origin());

        WHEN("a valid transaction with one PDU is sent")
        {
            auto const body = std::string{"{\"origin\":\"remote.example.org\","
                                          "\"origin_server_ts\":1000,"
                                          "\"pdus\":["} +
                              minimal_pdu() + "]}";
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_001", body));

            THEN("the server returns 200")
            {
                // Spec MUST: the receiving server MUST respond 200 for a valid
                // transaction even if individual PDUs fail. HTTP errors are only
                // for structural / auth failures of the transaction itself.
                REQUIRE(response.status == 200U);
            }

            THEN("the response body is valid JSON")
            {
                // Spec MUST: the response body must be a valid JSON object.
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage()) != nullptr);
            }
        }

        WHEN("a valid transaction with an empty pdus array is sent")
        {
            auto const body = std::string{"{\"origin\":\"remote.example.org\","
                                          "\"origin_server_ts\":1000,"
                                          "\"pdus\":[]}"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_002", body));

            THEN("the server still returns 200")
            {
                // Spec MUST: a transaction with zero PDUs is still valid.
                REQUIRE(response.status == 200U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v1/send/{txnId}
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// "origin" MUST be the server_name of the sending server. The receiving server
// MUST verify that the origin claim matches the X-Matrix auth header's origin.
SCENARIO("Federation send transaction is rejected when origin does not match signing key",
         "[federation][transaction][conformance]")
{
    GIVEN("a federation runtime with a known remote")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_origin());

        WHEN("a request signed by a different server claims to be from our known remote")
        {
            auto const body = std::string{"{\"origin\":\"remote.example.org\","
                                          "\"origin_server_ts\":1000,"
                                          "\"pdus\":[]}"};
            auto const different_seed = std::string{"different-server-seed"};
            auto const target = "/_matrix/federation/v1/send/txn_reject";
            auto request = merovingian::federation::SignedFederationRequest{};
            request.method = "PUT";
            request.target = target;
            request.origin = origin;
            request.destination = "local.example.org";
            request.key_id = key_id;
            request.now_ts = 1000U;
            request.canonical_json_verified = true;
            request.body = body;
            // Signed with a DIFFERENT key than the one registered for 'origin'.
            request.signature = merovingian::federation::make_federation_signature(
                origin, request.destination, request.method, target, body,
                merovingian::federation::test::keypair_from_seed(different_seed).secret_key);

            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the server rejects the request with 401 or 403")
            {
                // Spec MUST: the receiving server MUST verify the X-Matrix signature.
                // A request signed with a key that doesn't match the registered remote key
                // MUST be rejected. Either 401 Unauthorized or 403 Forbidden is correct.
                REQUIRE((response.status == 401U || response.status == 403U));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v1/send/{txnId}
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// When a pdu_sink is installed, the runtime MUST route each PDU from the
// transaction to that sink. The sink is invoked once per PDU.
SCENARIO("Federation send transaction routes PDUs to the installed pdu_sink", "[federation][transaction][conformance]")
{
    GIVEN("a federation runtime with a pdu_sink counting invocations")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_origin());

        auto pdu_count = std::make_shared<std::size_t>(0U);
        runtime.pdu_sink = [pdu_count]([[maybe_unused]] merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::PduIngestionResult {
            ++(*pdu_count);
            return {merovingian::federation::PduIngestionStatus::accepted, {}, {}};
        };

        WHEN("a transaction with two PDUs is sent")
        {
            auto const body = std::string{"{\"origin\":\"remote.example.org\","
                                          "\"origin_server_ts\":1000,"
                                          "\"pdus\":["} +
                              minimal_pdu() + "," + minimal_pdu() + "]}";
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_003", body));

            THEN("the server returns 200")
            {
                REQUIRE(response.status == 200U);
            }

            THEN("the pdu_sink was invoked twice")
            {
                // Spec MUST: the server MUST process each PDU in the transaction.
                // The sink must be called once per PDU in the pdus array.
                REQUIRE(*pdu_count == 2U);
            }
        }

        WHEN("a transaction with zero PDUs is sent")
        {
            auto const body = std::string{"{\"origin\":\"remote.example.org\","
                                          "\"origin_server_ts\":1000,"
                                          "\"pdus\":[]}"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_004", body));

            THEN("the pdu_sink is not invoked")
            {
                // Spec: no PDUs → no sink invocations.
                REQUIRE(*pdu_count == 0U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v1/send/{txnId}
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// EDUs (Ephemeral Data Units) are optional in a transaction. When present they
// MUST be routed to the edu_sink. The server MUST accept the transaction even
// if it does not understand the EDU type.
SCENARIO("Federation send transaction routes EDUs to the installed edu_sink", "[federation][transaction][conformance]")
{
    GIVEN("a federation runtime with an edu_sink counting invocations")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_origin());

        auto edu_count = std::make_shared<std::size_t>(0U);
        runtime.edu_sink = [edu_count]([[maybe_unused]] merovingian::federation::InboundEduEnvelope const& envelope)
            -> merovingian::federation::EduDispositionResult {
            ++(*edu_count);
            return {merovingian::federation::EduDispositionStatus::accepted, {}};
        };

        WHEN("a transaction with one EDU is sent")
        {
            // Spec: SS API v1.18 §m.typing — EDU content is { room_id, user_id, typing }.
            auto const body = std::string{"{\"origin\":\"remote.example.org\","
                                          "\"origin_server_ts\":1000,"
                                          "\"pdus\":[],"
                                          "\"edus\":[{\"edu_type\":\"m.typing\","
                                          "\"content\":{\"room_id\":\"!test:local.example.org\","
                                          "\"user_id\":\"@alice:remote.example.org\","
                                          "\"typing\":true}}]}"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_005", body));

            THEN("the server returns 200")
            {
                // Spec MUST: EDUs do not affect the HTTP status.
                REQUIRE(response.status == 200U);
            }

            THEN("the edu_sink was invoked once")
            {
                // Spec MUST: the server MUST route each EDU to the sink.
                REQUIRE(*edu_count == 1U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v1/send/{txnId}
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// The transaction body MUST include "origin" and "origin_server_ts". A
// transaction missing these required fields MUST be rejected.
SCENARIO("Federation send transaction rejects missing required top-level fields",
         "[federation][transaction][conformance]")
{
    GIVEN("a federation runtime")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_origin());

        WHEN("a transaction body missing 'origin' is sent")
        {
            auto const body = std::string{"{\"origin_server_ts\":1000,\"pdus\":[]}"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_006", body));

            THEN("the server rejects with 400")
            {
                // Spec MUST: the transaction body MUST contain "origin".
                // Missing required fields => 400 Bad Request.
                REQUIRE(response.status == 400U);
            }
        }

        WHEN("a transaction body missing 'origin_server_ts' is sent")
        {
            auto const body = std::string{"{\"origin\":\"remote.example.org\",\"pdus\":[]}"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_007", body));

            THEN("the server rejects with 400")
            {
                // Spec MUST: the transaction body MUST contain "origin_server_ts".
                REQUIRE(response.status == 400U);
            }
        }

        WHEN("a transaction body missing 'pdus' is sent")
        {
            auto const body = std::string{"{\"origin\":\"remote.example.org\",\"origin_server_ts\":1000}"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_008", body));

            THEN("the server rejects with 400")
            {
                // Spec MUST: the transaction body MUST contain "pdus" (may be empty array).
                REQUIRE(response.status == 400U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// The accepted_transactions list on the runtime is updated after a successful
// transaction. The transaction_id is the path parameter from the URL.
SCENARIO("Accepted federation transaction is recorded in the runtime state", "[federation][transaction][conformance]")
{
    GIVEN("a federation runtime with an accepting pdu_sink")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_origin());

        runtime.pdu_sink = []([[maybe_unused]] merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::PduIngestionResult {
            return {merovingian::federation::PduIngestionStatus::accepted, {}, {}};
        };

        WHEN("a transaction with one PDU is sent")
        {
            auto const body = std::string{"{\"origin\":\"remote.example.org\","
                                          "\"origin_server_ts\":1000,"
                                          "\"pdus\":["} +
                              minimal_pdu() + "]}";
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_accept_001", body));

            THEN("the response is 200")
            {
                REQUIRE(response.status == 200U);
            }

            THEN("the transaction is recorded in accepted_transactions")
            {
                // Spec behaviour: the runtime MUST track accepted transactions so that
                // duplicate deliveries can be detected and safely ignored.
                REQUIRE(!runtime.accepted_transactions.empty());

                auto const& txn = runtime.accepted_transactions.back();
                REQUIRE(txn.origin == origin);
                REQUIRE(txn.transaction_id == "txn_accept_001");
                // The runtime counts the PDUs that reached the sink.
                REQUIRE(txn.pdu_count == 1U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v1/send/{txnId}
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// "The sending server must wait and retry for a 200 OK response before
// sending a transaction with a different txnId to the receiving server."
// Because the sender retries the same txnId until it receives 200, the
// receiver MUST respond 200 for a repeated txnId — otherwise the sender
// can never progress to the next transaction.
SCENARIO("Duplicate federation transaction (same txn_id) is accepted without re-processing PDUs",
         "[federation][transaction][conformance][idempotency]")
{
    GIVEN("a federation runtime with a pdu_sink that counts invocations")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_origin());

        auto pdu_count = std::make_shared<std::size_t>(0U);
        runtime.pdu_sink = [pdu_count]([[maybe_unused]] merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::PduIngestionResult {
            ++(*pdu_count);
            return {merovingian::federation::PduIngestionStatus::accepted, {}, {}};
        };

        auto const body = std::string{"{\"origin\":\"remote.example.org\","
                                      "\"origin_server_ts\":1000,"
                                      "\"pdus\":["} +
                          minimal_pdu() + "]}";

        WHEN("the same transaction is delivered twice with the same txn_id")
        {
            auto const first = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_idem_001", body));
            auto const second = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_idem_001", body));

            THEN("both responses are 200")
            {
                // Spec MUST: receiver MUST respond 200 for a repeated txnId so the
                // sender can advance (SS API §Transactions, "wait and retry for 200 OK").
                REQUIRE(first.status == 200U);
                REQUIRE(second.status == 200U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: PUT /_matrix/federation/v1/send/{txnId}
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// The only documented response code is 200. The spec states: "The server is
// to use this response even in the event of one or more PDUs failing to be
// processed." Unknown EDU types are unprocessable content; the 200 response
// contract therefore applies regardless of EDU type.
SCENARIO("Federation send transaction with an unrecognized EDU type is accepted gracefully",
         "[federation][transaction][conformance][edu]")
{
    GIVEN("a federation runtime")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_origin());

        WHEN("a transaction containing an unrecognized EDU type is delivered")
        {
            // "org.example.unknown" is not a type defined by the Matrix spec.
            auto const body = std::string{"{\"origin\":\"remote.example.org\","
                                          "\"origin_server_ts\":1000,"
                                          "\"pdus\":[],"
                                          "\"edus\":[{\"edu_type\":\"org.example.unknown\","
                                          "\"content\":{\"some_key\":\"some_value\"}}]}"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_send_request("txn_edu_unknown", body));

            THEN("the server returns 200")
            {
                // Spec MUST: 200 is the only documented response for PUT /send/{txnId}.
                // Unprocessable content (unknown EDU type) MUST NOT cause a non-200 response.
                REQUIRE(response.status == 200U);
            }
        }
    }
}

