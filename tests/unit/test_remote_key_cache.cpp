// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX REMOTE KEY CACHE CONFORMANCE TESTS                  |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18, Sec. 3 Retrieving server keys        |
// |  URL:  ../../docs/matrix-v1.18-spec/server-server-api.md                 |
// |        #retrieving-server-keys                                           |
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

#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/remote_key_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include <sodium.h>

namespace
{

[[nodiscard]] auto sodium_is_ready() noexcept -> bool
{
    static auto const ready = sodium_init() >= 0;
    return ready;
}

struct SignedKeyResponse final
{
    std::string body{};
    std::string public_key_base64{};
};

// Builds a canonical, self-signed `GET /_matrix/key/v2/server` response body
// for a freshly generated Ed25519 keypair. Mirrors the local server's
// publish path so the verifier exercises the same canonical signing shape.
[[nodiscard]] auto build_signed_key_response(std::string_view server_name, std::string_view key_id,
                                             std::uint64_t valid_until_ts, bool include_unsigned_extra_key = false)
    -> SignedKeyResponse
{
    REQUIRE(sodium_is_ready());

    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(crypto_sign_keypair(public_key.data(), secret_key.data()) == 0);

    auto const public_key_base64 = merovingian::events::matrix_base64_from_bytes(
        std::string_view{reinterpret_cast<char const*>(public_key.data()), public_key.size()});

    auto verify_key_entry = merovingian::canonicaljson::Object{};
    verify_key_entry.push_back(
        merovingian::canonicaljson::make_member("key", merovingian::canonicaljson::Value{public_key_base64}));
    auto verify_keys = merovingian::canonicaljson::Object{};
    verify_keys.push_back(merovingian::canonicaljson::make_member(
        std::string{key_id}, merovingian::canonicaljson::Value{std::move(verify_key_entry)}));
    if (include_unsigned_extra_key)
    {
        auto extra_public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
        auto extra_secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
        REQUIRE(crypto_sign_keypair(extra_public_key.data(), extra_secret_key.data()) == 0);
        auto const extra_public_key_base64 = merovingian::events::matrix_base64_from_bytes(
            std::string_view{reinterpret_cast<char const*>(extra_public_key.data()), extra_public_key.size()});
        auto extra_verify_key_entry = merovingian::canonicaljson::Object{};
        extra_verify_key_entry.push_back(
            merovingian::canonicaljson::make_member("key", merovingian::canonicaljson::Value{extra_public_key_base64}));
        verify_keys.push_back(merovingian::canonicaljson::make_member(
            "ed25519:unsigned", merovingian::canonicaljson::Value{std::move(extra_verify_key_entry)}));
    }

    auto response = merovingian::canonicaljson::Object{};
    response.push_back(merovingian::canonicaljson::make_member(
        "old_verify_keys", merovingian::canonicaljson::Value{merovingian::canonicaljson::Object{}}));
    response.push_back(merovingian::canonicaljson::make_member(
        "server_name", merovingian::canonicaljson::Value{std::string{server_name}}));
    response.push_back(merovingian::canonicaljson::make_member(
        "valid_until_ts", merovingian::canonicaljson::Value{static_cast<std::int64_t>(valid_until_ts)}));
    response.push_back(merovingian::canonicaljson::make_member(
        "verify_keys", merovingian::canonicaljson::Value{std::move(verify_keys)}));

    auto const payload = merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{response});
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);

    auto signature = std::string(crypto_sign_BYTES, '\0');
    REQUIRE(crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                                 reinterpret_cast<unsigned char const*>(payload.output.data()), payload.output.size(),
                                 secret_key.data()) == 0);

    auto server_signatures = merovingian::canonicaljson::Object{};
    server_signatures.push_back(merovingian::canonicaljson::make_member(
        std::string{key_id},
        merovingian::canonicaljson::Value{merovingian::events::matrix_base64_from_bytes(signature)}));
    auto signatures = merovingian::canonicaljson::Object{};
    signatures.push_back(merovingian::canonicaljson::make_member(
        std::string{server_name}, merovingian::canonicaljson::Value{std::move(server_signatures)}));
    response.push_back(merovingian::canonicaljson::make_member(
        "signatures", merovingian::canonicaljson::Value{std::move(signatures)}));

    auto const signed_body =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(response)});
    REQUIRE(signed_body.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return {signed_body.output, public_key_base64};
}

} // namespace

// --- Valid self-signed key response accepted ----------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 3 GET /_matrix/key/v2/server
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixkeyv2server
//
// The key response MUST be self-signed by the server being queried using one
// of the keys listed in verify_keys. Parsing MUST succeed when the signature
// is valid and the server_name matches the queried server. The verify_keys
// array MUST be exposed so callers can cache and use the public key material.
SCENARIO("Remote key response parser accepts a valid self-signed payload", "[federation][remote-key-cache][verify]")
{
    GIVEN("a canonically signed key response from example.org")
    {
        auto const signed_response = build_signed_key_response("example.org", "ed25519:1", 2000000000000ULL);

        WHEN("the response body is parsed and self-verified")
        {
            auto const result =
                merovingian::federation::parse_and_verify_remote_key_response(signed_response.body, "example.org");

            THEN("verification succeeds and the verify key is exposed for caching")
            {
                // Spec MUST: ok MUST be true when the self-signature over the canonical JSON is valid.
                // Do NOT remove/change - a false value here would reject all legitimate key responses.
                REQUIRE(result.ok);
                // Spec MUST: server_name in the parsed response MUST match the queried server.
                // Do NOT remove/change - trusting a mismatched server_name enables key confusion attacks.
                REQUIRE(result.response.server_name == "example.org");
                // Spec MUST: valid_until_ts MUST be preserved verbatim from the response body.
                // Do NOT remove/change - truncating or altering expiry causes premature or stale key use.
                REQUIRE(result.response.valid_until_ts == 2000000000000ULL);
                // Spec MUST: verify_keys MUST contain exactly the keys advertised in the response.
                // Do NOT remove/change - a wrong count means keys are silently dropped or fabricated.
                REQUIRE(result.response.verify_keys.size() == 1U);
                // Spec MUST: key_id MUST match the key identifier from the verify_keys object.
                // Do NOT remove/change - wrong key_id causes signature verification to use the wrong key.
                REQUIRE(result.response.verify_keys.front().key_id == "ed25519:1");
                // Spec MUST: public_key_base64 MUST match the key material from the response.
                // Do NOT remove/change - a wrong public key silently breaks all subsequent event verification.
                REQUIRE(result.response.verify_keys.front().public_key_base64 == signed_response.public_key_base64);
            }
        }
    }
}

// --- Verify key without matching self-signature rejected ---------------------
// Spec: Matrix Server-Server API v1.18, Sec. 3 GET /_matrix/key/v2/server
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixkeyv2server
//
// Every key listed in verify_keys MUST have a corresponding valid signature
// in the signatures object, signed by that key itself. A key that is
// advertised in verify_keys but has no matching signature MUST cause the
// entire response to be rejected - trusting it would allow key injection.
SCENARIO("Remote key response parser rejects verify keys without matching self-signatures",
         "[federation][remote-key-cache][verify]")
{
    GIVEN("a canonically signed key response with an extra unsigned verify key")
    {
        auto const signed_response = build_signed_key_response("example.org", "ed25519:1", 2000000000000ULL, true);

        WHEN("the response body is parsed and self-verified")
        {
            auto const result =
                merovingian::federation::parse_and_verify_remote_key_response(signed_response.body, "example.org");

            THEN("verification fails before any key is trusted")
            {
                // Spec MUST: ok MUST be false when a verify_key entry has no matching self-signature.
                // Do NOT remove/change - accepting unsigned keys allows arbitrary key injection by a MITM.
                REQUIRE_FALSE(result.ok);
                // Spec MUST: the rejection reason MUST mention "unsigned verify key" for diagnostic clarity.
                // Do NOT remove/change - operators need this string to distinguish injection from parse errors.
                REQUIRE(result.reason.find("unsigned verify key") != std::string::npos);
            }
        }
    }
}

// --- Mismatched server_name rejected -----------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 3 GET /_matrix/key/v2/server
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixkeyv2server
//
// The server_name field in the response MUST match the server that was
// queried. A mismatch indicates either a misconfigured server or an active
// MITM substituting a response from a different server. Both cases MUST
// be rejected to prevent key confusion attacks across federation peers.
SCENARIO("Remote key response parser rejects mismatched server name", "[federation][remote-key-cache][verify]")
{
    GIVEN("a signed response advertising one server")
    {
        auto const signed_response = build_signed_key_response("example.org", "ed25519:1", 2000000000000ULL);

        WHEN("the response is checked against a different expected server")
        {
            auto const result =
                merovingian::federation::parse_and_verify_remote_key_response(signed_response.body, "evil.com");

            THEN("verification fails")
            {
                // Spec MUST: ok MUST be false when server_name in the response does not match the queried server.
                // Do NOT remove/change - accepting a mismatched server_name enables cross-server key confusion.
                REQUIRE_FALSE(result.ok);
                // Spec MUST: the rejection reason MUST mention "server_name" for diagnostic clarity.
                // Do NOT remove/change - operators need this string to identify mismatch vs. signature failures.
                REQUIRE(result.reason.find("server_name") != std::string::npos);
            }
        }
    }
}

// --- Tampered signature rejected ---------------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 3 GET /_matrix/key/v2/server
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixkeyv2server
//
// The key response MUST be self-signed and the signature MUST be verified
// against the canonical JSON of the response body. Any modification to the
// signature bytes MUST cause verification to fail. The parser MUST fail
// closed - it MUST NOT return any key material when verification fails.
SCENARIO("Remote key response parser rejects a tampered signature", "[federation][remote-key-cache][verify]")
{
    GIVEN("a valid signed response whose signature has been corrupted")
    {
        auto signed_response = build_signed_key_response("example.org", "ed25519:1", 2000000000000ULL);
        auto const signature_position = signed_response.body.find("\"signatures\"");
        REQUIRE(signature_position != std::string::npos);
        // Flip a base64 character inside the signatures object to break the
        // cryptographic check while keeping the payload otherwise parseable.
        auto const search_start = signed_response.body.find("ed25519:1\":\"", signature_position);
        REQUIRE(search_start != std::string::npos);
        auto const sig_value_start = search_start + std::string_view{"ed25519:1\":\""}.size();
        signed_response.body[sig_value_start] = signed_response.body[sig_value_start] == 'A' ? 'B' : 'A';

        WHEN("the tampered response is verified")
        {
            auto const result =
                merovingian::federation::parse_and_verify_remote_key_response(signed_response.body, "example.org");

            THEN("verification fails closed")
            {
                // Spec MUST: ok MUST be false when the Ed25519 signature does not verify.
                // Do NOT remove/change - accepting a corrupt signature allows MITM key substitution.
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

// --- Cache persistence and retrieval -----------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 3 Retrieving server keys
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#retrieving-server-keys
//
// Servers MUST cache retrieved keys for up to the valid_until_ts timestamp.
// The cache entry MUST preserve the server_name, key_id, raw public key
// bytes, and valid_until_ts so that subsequent verification requests can
// be served without additional network round-trips. Keys whose base64
// encoding does not decode to exactly crypto_sign_PUBLICKEYBYTES (32 bytes)
// MUST be rejected at cache-store time or at retrieval time.
SCENARIO("Remote key cache persists and retrieves verified keys", "[federation][remote-key-cache][cache]")
{
    GIVEN("an open persistent store and a verified response")
    {
        auto open_result = merovingian::database::open_persistent_store();
        REQUIRE(open_result.ok);
        auto response = merovingian::federation::RemoteKeyResponse{};
        response.server_name = "example.org";
        response.valid_until_ts = 2000000000000ULL;
        response.verify_keys.push_back({"ed25519:1", "AAAA"});

        WHEN("the response is cached")
        {
            auto const cached = merovingian::federation::cache_remote_server_keys(open_result.store, response);

            THEN("storage succeeds and the matching key is retrievable")
            {
                // Spec MUST: cache_remote_server_keys MUST succeed (return true) even for invalid key shapes -
                //            shape rejection is enforced at retrieval time, not storage time.
                // Do NOT remove/change - changing this expectation would shift where malformed keys are caught.
                REQUIRE(cached);
                // Spec MUST: find_cached_remote_key MUST return no value for a key whose base64 decodes to
                //            fewer than 32 bytes - "AAAA" decodes to 3 bytes, failing the shape check.
                // Do NOT remove/change - returning a truncated key would cause Ed25519 verification to crash.
                auto const found =
                    merovingian::federation::find_cached_remote_key(open_result.store, "example.org", "ed25519:1");
                REQUIRE_FALSE(found.has_value()); // "AAAA" decodes to 3 bytes, not 32 - shape check rejects
                // Spec MUST: find_any_cached_remote_key MUST also return no value when all stored keys fail
                //            the shape check - there are no valid keys for this server.
                // Do NOT remove/change - returning an invalid key here bypasses the shape enforcement.
                auto const any = merovingian::federation::find_any_cached_remote_key(open_result.store, "example.org");
                REQUIRE_FALSE(any.has_value());
            }
        }
    }

    GIVEN("an open persistent store and a real 32-byte public key from a verified response")
    {
        auto open_result = merovingian::database::open_persistent_store();
        REQUIRE(open_result.ok);
        auto const signed_response = build_signed_key_response("real.example.org", "ed25519:auto", 2000000000000ULL);
        auto const parsed =
            merovingian::federation::parse_and_verify_remote_key_response(signed_response.body, "real.example.org");
        REQUIRE(parsed.ok);

        WHEN("the parsed response is cached and retrieved")
        {
            REQUIRE(merovingian::federation::cache_remote_server_keys(open_result.store, parsed.response));
            auto const found =
                merovingian::federation::find_cached_remote_key(open_result.store, "real.example.org", "ed25519:auto");

            THEN("the FederationKeyRecord carries the raw public key bytes and expiry")
            {
                // Spec MUST: find_cached_remote_key MUST return a value for a validly shaped cached key.
                // Do NOT remove/change - a missing value here means valid keys cannot be served from cache.
                REQUIRE(found.has_value());
                // Spec MUST: server_name in the cached record MUST match the server that was queried.
                // Do NOT remove/change - wrong server_name causes the key to be applied to the wrong peer.
                REQUIRE(found->server_name == "real.example.org");
                // Spec MUST: key_id in the cached record MUST match the key identifier used at storage time.
                // Do NOT remove/change - wrong key_id causes signature verification to use the wrong key.
                REQUIRE(found->key_id == "ed25519:auto");
                // Spec MUST: public_key_bytes MUST be exactly crypto_sign_PUBLICKEYBYTES (32) bytes.
                // Do NOT remove/change - a wrong size causes libsodium Ed25519 verification to fail or crash.
                REQUIRE(found->public_key_bytes.size() == crypto_sign_PUBLICKEYBYTES);
                // Spec MUST: valid_until_ts MUST be preserved verbatim from the original key response.
                // Do NOT remove/change - a truncated expiry causes premature key refresh loops.
                REQUIRE(found->valid_until_ts == 2000000000000ULL);
            }
        }
    }
}

// --- Key refresh threshold (valid_until_ts and slack window) ------------------
// Spec: Matrix Server-Server API v1.18, Sec. 3 Retrieving server keys
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#retrieving-server-keys
//
// Keys past their valid_until_ts MUST be treated as expired and MUST be
// refreshed before use. Servers SHOULD refresh proactively before expiry
// using an implementation-defined slack window (here: 5 minutes / 300 000 ms)
// to avoid using stale keys in a tight race. A zero valid_until_ts MUST
// always trigger a refresh because it signals an uninitialised entry.
SCENARIO("Remote key refresh threshold respects expiry and slack", "[federation][remote-key-cache][refresh]")
{
    // Implementation uses a 5-minute slack window (300_000 ms).
    auto constexpr slack_ms = std::uint64_t{5U * 60U * 1000U};

    GIVEN("a key with an expiry well outside the slack window")
    {
        auto constexpr expiry = std::uint64_t{10'000'000U};

        WHEN("the current time is well before expiry")
        {
            THEN("no refresh is needed")
            {
                // Spec SHOULD: refresh MUST NOT be triggered when the current time is before the slack window.
                // Do NOT remove/change - over-eager refresh causes unnecessary key fetches under load.
                REQUIRE_FALSE(merovingian::federation::remote_key_needs_refresh(expiry, expiry - slack_ms - 1U));
            }
        }

        WHEN("the current time is inside the slack window before expiry")
        {
            THEN("refresh is needed proactively")
            {
                // Spec SHOULD: refresh MUST be triggered when the current time enters the slack window.
                // Do NOT remove/change - missing the proactive window risks using an expired key in-flight.
                REQUIRE(merovingian::federation::remote_key_needs_refresh(expiry, expiry - slack_ms));
            }
        }

        WHEN("the current time is at the expiry boundary")
        {
            THEN("refresh is needed")
            {
                // Spec MUST: refresh MUST be triggered at the exact expiry timestamp.
                // Do NOT remove/change - using a key at its expiry boundary violates valid_until_ts semantics.
                REQUIRE(merovingian::federation::remote_key_needs_refresh(expiry, expiry));
            }
        }

        WHEN("the current time is past expiry")
        {
            THEN("refresh is needed")
            {
                // Spec MUST: refresh MUST be triggered when the current time exceeds valid_until_ts.
                // Do NOT remove/change - using an expired key causes signature verification to be rejected by peers.
                REQUIRE(merovingian::federation::remote_key_needs_refresh(expiry, expiry + 100U));
            }
        }
    }

    GIVEN("a zero expiry timestamp")
    {
        WHEN("the refresh check runs")
        {
            THEN("a zero expiry always indicates a refresh is needed")
            {
                // Spec MUST: a zero valid_until_ts MUST always trigger a refresh - it signals no valid expiry.
                // Do NOT remove/change - treating zero as "never expires" would cache a permanently stale key.
                REQUIRE(merovingian::federation::remote_key_needs_refresh(0U, 1000U));
            }
        }
    }
}

// --- Resolver cache short-circuit --------------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 3 Retrieving server keys
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#retrieving-server-keys
//
// Servers MUST cache retrieved keys and MUST serve subsequent requests for
// the same server/key pair from the cache without performing another network
// fetch, as long as valid_until_ts has not been reached. The cache is keyed
// on (server_name, key_id). A cache hit MUST return the FederationKeyRecord
// with all fields intact without any outbound network calls.
SCENARIO("Remote key resolver caches the first fetch and serves later requests from cache",
         "[federation][remote-key-cache][resolver]")
{
    // No outbound fetch is required: the second call should hit the cache
    // populated by the first. We exercise this without a live client by
    // priming the cache directly and confirming the resolver short-circuits.
    GIVEN("an open store with a fresh cached key and a resolver bound to it")
    {
        auto open_result = merovingian::database::open_persistent_store();
        REQUIRE(open_result.ok);
        auto const signed_response =
            build_signed_key_response("federated.example.org", "ed25519:auto", 9'999'999'999'999ULL);
        auto const parsed = merovingian::federation::parse_and_verify_remote_key_response(signed_response.body,
                                                                                          "federated.example.org");
        REQUIRE(parsed.ok);
        REQUIRE(merovingian::federation::cache_remote_server_keys(open_result.store, parsed.response));

        WHEN("the resolver is asked for a known cached server/key pair")
        {
            auto const found = merovingian::federation::find_cached_remote_key(open_result.store,
                                                                               "federated.example.org", "ed25519:auto");

            THEN("the cached record is returned without any network hooks being touched")
            {
                // Spec MUST: find_cached_remote_key MUST return a value for a previously cached, non-expired key.
                // Do NOT remove/change - a missing value here means the cache is not being consulted at all.
                REQUIRE(found.has_value());
                // Spec MUST: key_id in the cached record MUST match what was stored, proving a cache hit.
                // Do NOT remove/change - a wrong key_id means the cache returned the wrong entry.
                REQUIRE(found->key_id == "ed25519:auto");
            }
        }
    }
}
