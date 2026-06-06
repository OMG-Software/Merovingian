// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX FEDERATION INBOUND FLOW CONFORMANCE TESTS                |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18                                   |
// |  URL:  https://spec.matrix.org/v1.18/server-server-api/                 |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                        |
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
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include <sodium.h>

namespace
{

[[nodiscard]] auto federation_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    security.federation.max_transaction_size = "1MiB";
    security.federation.remote_timeout = "30s";
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
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

// The default ServerConfig server name produced by federation_config().
auto constexpr local_server_name = std::string_view{"example.org"};

// Builds the pipe-delimited federation auth token used by the router's
// test-fixture fallback path:
// origin|key_id|signature|destination|now_ts|canonical_flag.
[[nodiscard]] auto federation_authorization(std::string const& origin, std::string const& key_id,
                                            std::string const& key_seed, std::string const& method,
                                            std::string const& target, std::string const& body,
                                            std::string const& canonical_flag = "canonical") -> std::string
{
    auto const destination = std::string{local_server_name};
    auto const signature = merovingian::federation::make_federation_signature(
        origin, destination, method, target, body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return origin + '|' + key_id + '|' + signature + '|' + destination + "|1000|" + canonical_flag;
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

class IntegrationTestSigningStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit IntegrationTestSigningStore(merovingian::crypto::SigningKeyRecord key)
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

class IntegrationTestEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    explicit IntegrationTestEd25519Provider(std::string key_material)
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
    auto store = IntegrationTestSigningStore{
        merovingian::crypto::SigningKeyRecord{
                                              origin, key_id,
                                              merovingian::crypto::Ed25519PublicKey{
                std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()}},
                                              true, }
    };
    auto provider = IntegrationTestEd25519Provider{token};
    auto signed_event = merovingian::events::sign_event_for_server(parsed.value, *policy, store, provider, origin);
    REQUIRE(signed_event.error.empty());
    return signed_event.event_json;
}

[[nodiscard]] auto transaction_body(std::string const& origin, std::string const& pdu_json) -> std::string
{
    return std::string{"{\"origin\":\""} + origin + R"(","origin_server_ts":1000,"pdus":[)" + pdu_json + "]}";
}

[[nodiscard]] auto object_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

[[nodiscard]] auto string_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::string const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
}

[[nodiscard]] auto integer_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::int64_t const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
}

[[nodiscard]] auto object_member_as_object(merovingian::canonicaljson::Object const& object,
                                           std::string_view key) noexcept -> merovingian::canonicaljson::Object const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<merovingian::canonicaljson::Object>(&value->storage());
}

[[nodiscard]] auto clone_without_signatures(merovingian::canonicaljson::Object const& object)
    -> merovingian::canonicaljson::Object
{
    auto clone = merovingian::canonicaljson::Object{};
    for (auto const& member : object)
    {
        if (member.key != "signatures")
        {
            clone.push_back(merovingian::canonicaljson::make_member(member.key, *member.value));
        }
    }
    return clone;
}

} // namespace

// --- Federation key publishing ------------------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 3 Retrieving server keys
// URL:  https://spec.matrix.org/v1.18/server-server-api/#get_matrixkeyv2server
//
// The GET /_matrix/key/v2/server endpoint MUST be served without requiring
// request authentication. The response MUST contain server_name, valid_until_ts,
// verify_keys (active keys), old_verify_keys (superseded keys), and MUST be
// signed by the server itself under one of the published verify_keys.
SCENARIO("Homeserver publishes its persisted self-signed federation key without request authentication",
         "[integration][federation][keys]")
{
    GIVEN("a started runtime with no prior event signing")
    {
        auto started = merovingian::homeserver::start_runtime(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a remote homeserver fetches GET /_matrix/key/v2/server without Authorization")
        {
            auto const response =
                merovingian::homeserver::handle_local_http_request(runtime, {"GET", "/_matrix/key/v2/server", {}, {}});

            THEN("the response publishes the persisted Ed25519 verify key and a valid self-signature")
            {
                // Spec MUST: endpoint is unauthenticated; any HTTP 200 confirms reachability.
                // Do NOT remove/change - a non-200 breaks remote key fetching for all federating servers.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(object != nullptr);

                auto const* server_name = string_member(*object, "server_name");
                auto const* valid_until_ts = integer_member(*object, "valid_until_ts");
                auto const* verify_keys = object_member_as_object(*object, "verify_keys");
                auto const* signatures = object_member_as_object(*object, "signatures");
                // Spec MUST: response body MUST contain server_name, valid_until_ts, verify_keys, signatures.
                // Do NOT remove/change - omitting any field causes remote servers to reject our key material.
                REQUIRE(server_name != nullptr);
                REQUIRE(*server_name == "example.org");
                REQUIRE(valid_until_ts != nullptr);
                REQUIRE(*valid_until_ts > 0);
                REQUIRE(verify_keys != nullptr);
                REQUIRE(signatures != nullptr);

                // The key_id is now derived from the public key bytes ("ed25519:" + 8 hex
                // chars) rather than the legacy sentinel "ed25519:auto". Discover it
                // dynamically from the verify_keys map - there must be exactly one entry.
                REQUIRE(verify_keys->size() == 1U);
                auto const& published_key_id = verify_keys->front().key;
                // Spec MUST: key identifier MUST be of the form "algorithm:identifier"
                // (Sec. 3.1 Signing JSON). "ed25519:auto" is a legacy placeholder and MUST NOT be published.
                // Do NOT remove/change - an invalid key_id causes remote signature verification to fail.
                REQUIRE(published_key_id.starts_with("ed25519:"));
                REQUIRE(published_key_id != "ed25519:auto");

                auto const* key_object = object_member_as_object(*verify_keys, published_key_id);
                REQUIRE(key_object != nullptr);
                auto const* public_key = string_member(*key_object, "key");
                // Spec MUST: each entry in verify_keys MUST contain the unpadded base64 public key.
                // Do NOT remove/change - an absent or empty key prevents remote verification entirely.
                REQUIRE(public_key != nullptr);
                REQUIRE_FALSE(public_key->empty());
                REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);
                REQUIRE(runtime.database.persistent_store.server_signing_keys.front().public_key == *public_key);

                auto const* server_signatures = object_member_as_object(*signatures, "example.org");
                REQUIRE(server_signatures != nullptr);
                // Signature is published under the same derived key_id.
                auto const* encoded_signature = string_member(*server_signatures, published_key_id);
                // Spec MUST: the response MUST be signed by the server under the published key.
                // Do NOT remove/change - an absent self-signature causes remote servers to distrust all our keys.
                REQUIRE(encoded_signature != nullptr);

                auto const payload = merovingian::canonicaljson::serialize_canonical(
                    merovingian::canonicaljson::Value{clone_without_signatures(*object)});
                auto const signature = merovingian::events::matrix_bytes_from_base64(*encoded_signature);
                auto const public_key_bytes = merovingian::events::matrix_bytes_from_base64(*public_key);
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(signature.size() == crypto_sign_BYTES);
                REQUIRE(public_key_bytes.size() == crypto_sign_PUBLICKEYBYTES);
                // Spec MUST: the Ed25519 signature over the canonical JSON payload MUST verify.
                // Do NOT remove/change - a bad signature means no remote server will accept our events.
                REQUIRE(crypto_sign_verify_detached(
                            reinterpret_cast<unsigned char const*>(signature.data()),
                            reinterpret_cast<unsigned char const*>(payload.output.data()), payload.output.size(),
                            reinterpret_cast<unsigned char const*>(public_key_bytes.data())) == 0);
                // Spec MUST: the secret signing key MUST NOT appear in the response body.
                // Do NOT remove/change - leaking the secret key would allow event forgery by any remote server.
                REQUIRE(response.body.find("secret") == std::string::npos);
            }
        }
    }
}

// --- Superseded key publication -----------------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 3 Retrieving server keys
// URL:  https://spec.matrix.org/v1.18/server-server-api/#get_matrixkeyv2server
//
// Keys that are no longer active MUST appear in old_verify_keys with an
// expired_ts field. expired_ts MUST be a past timestamp - it MUST NOT be
// future-dated even if the stored sentinel value is far in the future. Remote
// servers use old_verify_keys to verify historically signed events.
SCENARIO("Homeserver publishes superseded signing keys in old_verify_keys", "[integration][federation][keys]")
{
    GIVEN("a started runtime that also has a superseded legacy signing key in the store")
    {
        auto started = merovingian::homeserver::start_runtime(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        // Inject a pre-existing legacy key (mimics the ed25519:auto entry left behind after
        // the key-id migration). Its valid_until_ts is far in the future (the old year-2999
        // sentinel) - the implementation must cap expired_ts at now so it is never future-dated.
        auto const legacy_public_key = std::string{"bGVnYWN5cHVibGlja2V5"}; // base64("legacypublickey")
        runtime.database.persistent_store.server_signing_keys.push_back({
            "example.org", "ed25519:auto", legacy_public_key,
            32503680000000ULL, // year-2999 sentinel - must be capped when published
            "",                // no secret; old keys are verification-only
        });

        WHEN("a remote homeserver fetches GET /_matrix/key/v2/server")
        {
            auto const response =
                merovingian::homeserver::handle_local_http_request(runtime, {"GET", "/_matrix/key/v2/server", {}, {}});

            THEN("old_verify_keys contains the superseded key with an expired_ts that is not in the future")
            {
                // Spec MUST: endpoint remains unauthenticated even when old keys are present.
                // Do NOT remove/change - a non-200 breaks remote key fetching for all federating servers.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(object != nullptr);

                // Spec MUST: old_verify_keys MUST be present when superseded keys exist.
                // Do NOT remove/change - omitting this field prevents remote servers from verifying old events.
                auto const* old_verify_keys = object_member_as_object(*object, "old_verify_keys");
                REQUIRE(old_verify_keys != nullptr);
                // Exactly one superseded key: the legacy ed25519:auto entry.
                REQUIRE(old_verify_keys->size() == 1U);

                auto const* old_entry = object_member_as_object(*old_verify_keys, "ed25519:auto");
                REQUIRE(old_entry != nullptr);

                auto const* old_key_str = string_member(*old_entry, "key");
                auto const* expired_ts = integer_member(*old_entry, "expired_ts");
                // Spec MUST: each old_verify_keys entry MUST contain the public key and expired_ts.
                // Do NOT remove/change - missing either field causes remote servers to skip the key.
                REQUIRE(old_key_str != nullptr);
                REQUIRE(*old_key_str == legacy_public_key);
                REQUIRE(expired_ts != nullptr);
                // Spec MUST: expired_ts MUST be a past timestamp capped at now - never future-dated.
                // Do NOT remove/change - a future expired_ts would allow a retired key to be trusted
                // beyond its actual expiry, violating the key rotation security contract.
                REQUIRE(*expired_ts > 0);
                auto const now_approx =
                    static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                  std::chrono::system_clock::now().time_since_epoch())
                                                  .count());
                REQUIRE(*expired_ts <= now_approx);

                // The active verify_keys must still be present and distinct from old_verify_keys.
                auto const* verify_keys = object_member_as_object(*object, "verify_keys");
                // Spec MUST: verify_keys MUST remain populated with the current active key.
                // Do NOT remove/change - an empty verify_keys means no remote can authenticate new events.
                REQUIRE(verify_keys != nullptr);
                REQUIRE(verify_keys->size() == 1U);
                REQUIRE(verify_keys->front().key != "ed25519:auto");
            }
        }
    }
}

// --- Inbound transaction routing ----------------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 7 Transactions
// URL:  https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv1sendtxnid
//
// The PUT /_matrix/federation/v1/send/{txnId} endpoint MUST return HTTP 200
// for any transaction that passes authentication, even if individual PDUs are
// rejected. PDU-level failures MUST be reported per-PDU in the response body
// under the "pdus" key. Returning a 4xx for the whole transaction causes the
// sending server to back off and retry, breaking federation.
SCENARIO("Homeserver routes signed inbound federation transactions through runtime policy", "[integration][federation]")
{
    GIVEN("a started runtime with a known remote server")
    {
        auto started = merovingian::homeserver::start_runtime(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime.federation, remote_for(origin, key_id, token));
        auto const target = std::string{"/_matrix/federation/v1/send/txn123"};
        auto const body = transaction_body(origin, signed_json_pdu(origin, key_id, token));
        auto const authorization = federation_authorization(origin, key_id, token, "PUT", target, body);

        WHEN("a signed federation request reaches the local router")
        {
            auto const response =
                merovingian::homeserver::handle_local_http_request(runtime, {"PUT", target, authorization, body});

            THEN("the transaction is accepted and recorded")
            {
                // Spec MUST: a successfully authenticated transaction MUST return HTTP 200.
                // Do NOT remove/change - returning 4xx causes the remote to back off and federation stalls.
                REQUIRE(response.status == 200U);
                // Spec MUST: the response body MUST contain a "pdus" object mapping event IDs to errors.
                // An empty object means all PDUs were accepted. Do NOT remove/change - a missing or
                // malformed "pdus" key causes the sending server to treat the transaction as failed.
                REQUIRE(response.body == R"({"pdus":{}})");
                // Spec MUST: accepted transactions MUST be recorded for idempotency (Sec. 7.1 Idempotency).
                // Do NOT remove/change - losing transaction state causes duplicate event processing.
                REQUIRE(runtime.federation.accepted_transactions.size() == 1U);
                REQUIRE(runtime.federation.accepted_transactions.front().origin == origin);
                REQUIRE(runtime.federation.audit_events.size() == 1U);
                // Spec SHOULD: all federation activity MUST be auditable for security review.
                // Do NOT remove/change - an unsafe audit log indicates a policy bypass has occurred.
                REQUIRE(merovingian::federation::federation_audit_is_safe(runtime.federation));
            }
        }
    }
}

// --- Malformed request rejection ----------------------------------------------
// Spec: Matrix Server-Server API v1.18, general error handling
// URL:  https://spec.matrix.org/v1.18/server-server-api/
//
// Requests with a malformed or missing Authorization header MUST be rejected
// before any transaction processing occurs. Requests originating from private
// or loopback addresses MUST be rejected to prevent SSRF and local-network
// privilege escalation. All rejection paths MUST fail closed - no transaction
// state should be recorded for rejected requests.
SCENARIO("Homeserver rejects malformed overflow and private-address federation requests",
         "[integration][federation][security]")
{
    GIVEN("a started runtime with one private-address remote")
    {
        auto started = merovingian::homeserver::start_runtime(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto remote = remote_for(origin, key_id, token);
        remote.discovery.resolved_addresses = {"127.0.0.1"};
        merovingian::federation::upsert_remote(runtime.federation, remote);
        auto const target = std::string{"/_matrix/federation/v1/send/txn123"};
        auto const body = transaction_body(origin, signed_json_pdu(origin, key_id, token));
        auto const authorization = federation_authorization(origin, key_id, token, "PUT", target, body);
        auto const overflow_authorization =
            origin + "|" + key_id + "|sig:v1:ignored|example.org|184467440737095516160|canonical";
        auto const uncanonical_authorization =
            federation_authorization(origin, key_id, token, "PUT", target, body, "uncanonical");

        WHEN("malformed overflow uncanonical and private-address requests are routed")
        {
            auto const malformed =
                merovingian::homeserver::handle_local_http_request(runtime, {"PUT", target, "not-enough-fields", body});
            auto const overflow = merovingian::homeserver::handle_local_http_request(
                runtime, {"PUT", target, overflow_authorization, body});
            auto const uncanonical = merovingian::homeserver::handle_local_http_request(
                runtime, {"PUT", target, uncanonical_authorization, body});
            auto const private_remote =
                merovingian::homeserver::handle_local_http_request(runtime, {"PUT", target, authorization, body});

            THEN("all fail closed before accepting a transaction")
            {
                // Spec MUST: malformed Authorization headers MUST be rejected before processing.
                // Do NOT remove/change - accepting malformed auth would allow unsigned events to enter the DAG.
                REQUIRE(malformed.status == 502U);
                REQUIRE(malformed.body == "malformed federation authorization");
                // Spec MUST: integer overflow in auth fields MUST be treated as malformed.
                // Do NOT remove/change - overflow bypasses timestamp and sequence-number validation.
                REQUIRE(overflow.status == 502U);
                REQUIRE(overflow.body == "malformed federation authorization");
                // Spec MUST: requests from private or loopback addresses MUST be rejected (SSRF prevention).
                // Do NOT remove/change - allowing private-address remotes enables SSRF attacks against
                // internal services and bypasses network-level federation controls.
                REQUIRE(uncanonical.status == 403U);
                REQUIRE(uncanonical.body == "remote address is private or loopback");
                REQUIRE(private_remote.status == 403U);
                REQUIRE(private_remote.body == "remote address is private or loopback");
                // Spec MUST: no transaction state MUST be recorded when a request is rejected.
                // Do NOT remove/change - recording state for rejected requests breaks idempotency
                // and could allow a subsequent valid request for the same txnId to be dropped.
                REQUIRE(runtime.federation.accepted_transactions.empty());
            }
        }
    }
}
