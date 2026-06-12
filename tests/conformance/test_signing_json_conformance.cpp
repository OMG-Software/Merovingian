// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX SIGNING JSON CONFORMANCE TESTS                     |
// |                                                                         |
// |  Spec: Matrix v1.18 Appendices — Signing JSON                          |
// |  URL:  ../../docs/matrix-v1.18-spec/appendices.md#signing-json          |
// |        ../../docs/matrix-v1.18-spec/appendices.md#cryptographic-test-vectors |
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
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sodium.h>

#include <array>
#include <string>
#include <string_view>
#include <utility>

// ---------------------------------------------------------------------------
// Spec: Matrix v1.18 Appendices — Signing JSON
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#signing-json
//
// To sign a JSON object:
//  1. Remove the "signatures" key if present
//  2. Remove the "unsigned" key if present
//  3. Serialize to canonical JSON
//  4. Sign the bytes using Ed25519
//  5. Encode the signature as unpadded base64
//  6. Add the signature to signatures.{server_name}.{key_id}
// ---------------------------------------------------------------------------

namespace
{

// A simple Ed25519Provider backed by libsodium.
class LibsodiumEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const& key_handle,
                            std::string_view message) -> merovingian::crypto::SignatureResult override
    {
        auto const& kp = m_keypair;
        if (kp.secret_key.size() != 64U)
        {
            return {{}, "invalid secret key length"};
        }
        static_cast<void>(key_handle);
        auto sig = std::string(64U, '\0');
        if (crypto_sign_ed25519_detached(reinterpret_cast<unsigned char*>(sig.data()), nullptr,
                                         reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                         reinterpret_cast<unsigned char const*>(kp.secret_key.data())) != 0)
        {
            return {{}, "sign failed"};
        }
        return {merovingian::crypto::Ed25519Signature{std::move(sig)}, {}};
    }

    [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const& public_key, std::string_view message,
                              merovingian::crypto::Ed25519Signature const& signature)
        -> merovingian::crypto::VerificationResult override
    {
        if (public_key.bytes.size() != 32U || signature.bytes.size() != 64U)
        {
            return {false, "invalid key or signature length"};
        }
        auto const result = crypto_sign_ed25519_verify_detached(
            reinterpret_cast<unsigned char const*>(signature.bytes.data()),
            reinterpret_cast<unsigned char const*>(message.data()), message.size(),
            reinterpret_cast<unsigned char const*>(public_key.bytes.data()));
        return {result == 0, result == 0 ? std::string{} : std::string{"signature verification failed"}};
    }

    void set_keypair(merovingian::federation::test::SigningKeypair kp)
    {
        m_keypair = std::move(kp);
    }

private:
    merovingian::federation::test::SigningKeypair m_keypair{};
};

// Simple signing key store backed by a fixed key.
class FixedSigningKeyStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit FixedSigningKeyStore(merovingian::crypto::SigningKeyRecord record)
        : m_record{std::move(record)}
    {
    }

    [[nodiscard]] auto active_key_for_server(std::string_view server_name)
        -> merovingian::crypto::SigningKeyLookupResult override
    {
        if (server_name != m_record.server_name)
        {
            return {{}, "key not found for server"};
        }
        return {m_record, {}};
    }

private:
    merovingian::crypto::SigningKeyRecord m_record{};
};

} // namespace

// Spec: Matrix v1.18 Appendices — Signing JSON
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#signing-json
//
// The signing payload MUST NOT contain the "signatures" or "unsigned" fields.
SCENARIO("Signing payload excludes signatures and unsigned fields per spec",
         "[conformance][signing][payload]")
{
    GIVEN("an event object containing both signatures and unsigned fields")
    {
        auto const event_json = std::string{
            R"({"content":{"body":"test"},"depth":1,"origin_server_ts":1,)"
            R"("room_id":"!room:example.org","sender":"@alice:example.org",)"
            R"("type":"m.room.message","signatures":{"example.org":{"ed25519:1":"sig"}},)"
            R"("unsigned":{"age":100}})"};

        auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the signing payload is derived")
        {
            auto const payload = merovingian::events::make_event_signing_payload(parsed.value);

            THEN("the payload excludes signatures and unsigned")
            {
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: "signatures" MUST NOT appear in the signing payload.
                // Rationale: signing over your own signatures field is circular.
                REQUIRE(payload.output.find(R"("signatures")") == std::string::npos);
                // Spec MUST: "unsigned" MUST NOT appear in the signing payload.
                // Rationale: unsigned data is not covered by the signature; including it
                // would cause verification to fail when unsigned data changes normally.
                REQUIRE(payload.output.find(R"("unsigned")") == std::string::npos);
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Signing JSON
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#signing-json
//
// The signing payload is canonical JSON: keys are sorted, no whitespace.
SCENARIO("Signing payload is canonical JSON (sorted keys, no whitespace)",
         "[conformance][signing][payload][canonicaljson]")
{
    GIVEN("an event object with unsorted keys")
    {
        auto const event_json = std::string{
            R"({"unsigned":{},"type":"m.room.message","sender":"@alice:example.org","depth":1})"};

        auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the signing payload is derived")
        {
            auto const payload = merovingian::events::make_event_signing_payload(parsed.value);

            THEN("the payload has sorted keys and no whitespace")
            {
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: canonical JSON — no whitespace, keys sorted lexicographically.
                REQUIRE(payload.output.find(' ') == std::string::npos);
                // Expect keys in lexicographic order: depth, sender, type (unsigned removed)
                auto const depth_pos = payload.output.find(R"("depth")");
                auto const sender_pos = payload.output.find(R"("sender")");
                auto const type_pos = payload.output.find(R"("type")");
                REQUIRE(depth_pos != std::string::npos);
                REQUIRE(sender_pos != std::string::npos);
                REQUIRE(type_pos != std::string::npos);
                REQUIRE(depth_pos < sender_pos);
                REQUIRE(sender_pos < type_pos);
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Signing JSON
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#signing-json
//
// The signature is placed at signatures.{server_name}.{key_id} in the result.
SCENARIO("Signed event contains the signature at the correct path per spec",
         "[conformance][signing][structure]")
{
    GIVEN("an event and a valid signing keypair")
    {
        auto const event_json = std::string{
            R"({"content":{"body":"hello"},"depth":1,"origin_server_ts":1,)"
            R"("room_id":"!room:example.org","sender":"@alice:example.org",)"
            R"("type":"m.room.message"})"};

        auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        auto const kp = merovingian::federation::test::keypair_from_seed("signing-test-seed");
        auto provider = LibsodiumEd25519Provider{};
        provider.set_keypair(kp);

        auto key_record = merovingian::crypto::SigningKeyRecord{};
        key_record.server_name = "example.org";
        key_record.key_id = "ed25519:1";
        key_record.public_key.bytes = kp.public_key;
        key_record.active = true;

        auto key_store = FixedSigningKeyStore{key_record};
        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);

        WHEN("the event is signed for the server")
        {
            auto const result =
                merovingian::events::sign_event_for_server(parsed.value, *policy, key_store, provider, "example.org");

            THEN("the signed event contains signatures.example.org.ed25519:1")
            {
                REQUIRE(result.error.empty());
                // Spec MUST: signatures field must be an object.
                REQUIRE(result.event_json.find(R"("signatures")") != std::string::npos);
                // Spec MUST: signature path is signatures.{server_name}.{key_id}.
                REQUIRE(result.event_json.find(R"("example.org")") != std::string::npos);
                REQUIRE(result.event_json.find(R"("ed25519:1")") != std::string::npos);
                // Spec MUST: signature value is a non-empty base64 string.
                REQUIRE_FALSE(result.signature.empty());
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Checking for a Signature
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#checking-for-a-signature
//
// To verify a signature:
//  1. Remove the "signatures" key from the object
//  2. Remove the "unsigned" key from the object
//  3. Serialize to canonical JSON
//  4. Verify the signature against the payload and the claimed public key
SCENARIO("Signature verification round-trip succeeds for a correctly signed event",
         "[conformance][signing][verify]")
{
    GIVEN("an event signed with a known key")
    {
        auto const event_json = std::string{
            R"({"content":{"body":"hello"},"depth":1,"origin_server_ts":1,)"
            R"("room_id":"!room:example.org","sender":"@alice:example.org",)"
            R"("type":"m.room.message"})"};

        auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        auto const kp = merovingian::federation::test::keypair_from_seed("verify-round-trip-seed");
        auto provider = LibsodiumEd25519Provider{};
        provider.set_keypair(kp);

        auto key_record = merovingian::crypto::SigningKeyRecord{};
        key_record.server_name = "example.org";
        key_record.key_id = "ed25519:1";
        key_record.public_key.bytes = kp.public_key;
        key_record.active = true;
        auto key_store = FixedSigningKeyStore{key_record};

        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);

        auto const signed_result =
            merovingian::events::sign_event_for_server(parsed.value, *policy, key_store, provider, "example.org");
        REQUIRE(signed_result.error.empty());

        WHEN("the signed event is verified with the corresponding public key")
        {
            auto const signed_parsed =
                merovingian::canonicaljson::parse_lossless(signed_result.event_json);
            REQUIRE(signed_parsed.error == merovingian::canonicaljson::ParseError::none);

            auto const public_key = merovingian::crypto::Ed25519PublicKey{kp.public_key};
            auto const verification = merovingian::events::verify_event_signature(
                signed_parsed.value, *policy, {key_record.server_name, key_record.key_id}, public_key, provider);

            THEN("verification succeeds")
            {
                // Spec MUST: a signature produced by sign_event_for_server must be verifiable
                // with the corresponding public key using verify_event_signature.
                REQUIRE(verification.valid);
                REQUIRE(verification.error.empty());
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Checking for a Signature
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#checking-for-a-signature
//
// A signature produced by one key MUST NOT verify against a different key.
SCENARIO("Signature verification fails when a different key is used",
         "[conformance][signing][verify][security]")
{
    GIVEN("an event signed with key A, and a different public key B for verification")
    {
        auto const event_json = std::string{
            R"({"content":{"body":"test"},"depth":1,"origin_server_ts":1,)"
            R"("room_id":"!room:example.org","sender":"@alice:example.org",)"
            R"("type":"m.room.message"})"};

        auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        auto const kp_a = merovingian::federation::test::keypair_from_seed("key-a-for-wrong-key-test");
        auto const kp_b = merovingian::federation::test::keypair_from_seed("key-b-for-wrong-key-test");

        auto provider = LibsodiumEd25519Provider{};
        provider.set_keypair(kp_a);

        auto key_record = merovingian::crypto::SigningKeyRecord{};
        key_record.server_name = "example.org";
        key_record.key_id = "ed25519:1";
        key_record.public_key.bytes = kp_a.public_key;
        key_record.active = true;
        auto key_store = FixedSigningKeyStore{key_record};

        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);

        auto const signed_result =
            merovingian::events::sign_event_for_server(parsed.value, *policy, key_store, provider, "example.org");
        REQUIRE(signed_result.error.empty());

        WHEN("the signed event is verified with the WRONG public key (key B)")
        {
            auto const signed_parsed =
                merovingian::canonicaljson::parse_lossless(signed_result.event_json);
            REQUIRE(signed_parsed.error == merovingian::canonicaljson::ParseError::none);

            auto const wrong_key = merovingian::crypto::Ed25519PublicKey{kp_b.public_key};
            auto const verification = merovingian::events::verify_event_signature(
                signed_parsed.value, *policy, {key_record.server_name, key_record.key_id}, wrong_key, provider);

            THEN("verification fails — wrong key MUST NOT verify a foreign signature")
            {
                // Spec MUST: a signature MUST be rejected when verified against a key that did not
                // produce it. This is the core security guarantee of event signing.
                REQUIRE_FALSE(verification.valid);
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Signing JSON
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#signing-json
//
// Signing an already-signed event adds to signatures without disturbing existing
// signatures from other servers.
SCENARIO("Signing an already-signed event preserves existing signatures",
         "[conformance][signing][multi-server]")
{
    GIVEN("an event already carrying a signature from server A")
    {
        auto const pre_signed_json = std::string{
            R"({"depth":1,"origin_server_ts":1,)"
            R"("room_id":"!room:example.org","sender":"@alice:example.org",)"
            R"("signatures":{"server-a.example.org":{"ed25519:1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},)"
            R"("type":"m.room.message"})"};

        auto const parsed = merovingian::canonicaljson::parse_lossless(pre_signed_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        auto const kp = merovingian::federation::test::keypair_from_seed("server-b-signing-seed");
        auto provider = LibsodiumEd25519Provider{};
        provider.set_keypair(kp);

        auto key_record = merovingian::crypto::SigningKeyRecord{};
        key_record.server_name = "server-b.example.org";
        key_record.key_id = "ed25519:1";
        key_record.public_key.bytes = kp.public_key;
        key_record.active = true;
        auto key_store = FixedSigningKeyStore{key_record};

        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);

        WHEN("server B also signs the event")
        {
            auto const result = merovingian::events::sign_event_for_server(
                parsed.value, *policy, key_store, provider, "server-b.example.org");

            THEN("the result contains both server A's and server B's signatures")
            {
                REQUIRE(result.error.empty());
                // Spec MUST: adding a new server's signature MUST NOT remove signatures from
                // other servers already present in the signatures object.
                REQUIRE(result.event_json.find(R"("server-a.example.org")") != std::string::npos);
                REQUIRE(result.event_json.find(R"("server-b.example.org")") != std::string::npos);
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Checking for a Signature
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#checking-for-a-signature
//
// verify_event_signature_presence returns an error when the expected
// server name or key ID is missing from the signatures object.
SCENARIO("Signature presence check returns error when server or key is absent",
         "[conformance][signing][verify][presence]")
{
    GIVEN("an event with no signatures field")
    {
        auto const no_sigs_json = std::string{
            R"({"depth":1,"type":"m.room.message"})"};
        auto const no_sigs = merovingian::canonicaljson::parse_lossless(no_sigs_json);
        REQUIRE(no_sigs.error == merovingian::canonicaljson::ParseError::none);

        WHEN("signature presence is checked for any server")
        {
            auto const result = merovingian::events::verify_event_signature_presence(
                no_sigs.value, {"example.org", "ed25519:1"});

            THEN("the check fails because signatures is absent")
            {
                // Spec MUST: an event without a signatures field MUST be treated as unsigned.
                REQUIRE_FALSE(result.valid);
                REQUIRE_FALSE(result.error.empty());
            }
        }
    }

    GIVEN("an event signed by server A but checked for server B")
    {
        auto const signed_by_a = std::string{
            R"({"depth":1,"signatures":{"server-a.org":{"ed25519:1":"sig"}},"type":"m.room.message"})"};
        auto const parsed = merovingian::canonicaljson::parse_lossless(signed_by_a);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("presence is checked for server B")
        {
            auto const result = merovingian::events::verify_event_signature_presence(
                parsed.value, {"server-b.org", "ed25519:1"});

            THEN("the check fails because server B has not signed the event")
            {
                // Spec MUST: absence of a server's entry in signatures means the server
                // has not signed the event.
                REQUIRE_FALSE(result.valid);
            }
        }
    }
}

// ===========================================================================
// Spec: Matrix v1.18 Appendices — Cryptographic Test Vectors
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#cryptographic-test-vectors
//
// These tests use the EXACT seed, inputs, and expected outputs from the spec.
// Any deviation means the implementation produces output incompatible with
// other Matrix servers.
//
// Seed (base64): YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1
// SERVER_NAME: "domain"   KEY_ID: "ed25519:1"
// ===========================================================================

namespace
{

// Derive the spec keypair from the known 32-byte seed.
// Seed = base64-decode("YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1")
// Hardcoded to avoid any base64-decode variant ambiguity.
[[nodiscard]] auto spec_seed_keypair() -> merovingian::federation::test::SigningKeypair
{
    static_cast<void>(sodium_init());
    // YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1 base64-decoded (standard, no padding)
    auto constexpr seed = std::array<unsigned char, crypto_sign_SEEDBYTES>{
        0x60, 0x90, 0xc1, 0x03, 0xd5, 0xe7, 0xaf, 0x6b, 0x15, 0xa9, 0x70, 0xfd,
        0x56, 0x3e, 0xd7, 0x55, 0x49, 0xe6, 0x15, 0x97, 0x19, 0xae, 0x5c, 0x3c,
        0x31, 0xde, 0xe4, 0x31, 0x6f, 0xb7, 0x5c, 0x0d,
    };
    auto pk = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto sk = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
    return {
        std::string{reinterpret_cast<char const*>(pk.data()), pk.size()},
        std::string{reinterpret_cast<char const*>(sk.data()), sk.size()},
    };
}

// Sign message bytes and return as standard (not URL-safe) unpadded base64.
[[nodiscard]] auto sign_standard_b64(std::string_view message,
                                     merovingian::federation::test::SigningKeypair const& kp) -> std::string
{
    auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
    if (crypto_sign_ed25519_detached(sig.data(), nullptr,
                                     reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                     reinterpret_cast<unsigned char const*>(kp.secret_key.data())) != 0)
    {
        return {};
    }
    auto out = std::string(sodium_base64_ENCODED_LEN(sig.size(),
                               sodium_base64_VARIANT_ORIGINAL_NO_PADDING), '\0');
    sodium_bin2base64(out.data(), out.size(), sig.data(), sig.size(),
                      sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    out.resize(std::char_traits<char>::length(out.c_str()));
    return out;
}

} // anonymous namespace (spec vector helpers)

// Spec: JSON Signing Test Vector 1 — empty object
// Input:    {}
// Expected: signatures.domain.ed25519:1 =
//           "K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"
SCENARIO("Spec crypto test vector: signing an empty JSON object produces the spec-defined signature",
         "[conformance][signing][spec-vector]")
{
    GIVEN("the spec signing key seed and an empty JSON object")
    {
        auto const kp = spec_seed_keypair();
        REQUIRE(kp.secret_key.size() == 64U);

        // Canonical JSON of {} is exactly the 2 bytes "{}".
        auto constexpr payload = std::string_view{"{}"};

        WHEN("the payload is signed with the spec key")
        {
            auto const sig = sign_standard_b64(payload, kp);

            THEN("the signature matches the spec test vector exactly")
            {
                // Spec MUST: this exact signature MUST result from signing '{}' with the spec key.
                // If this fails: the signing algorithm or base64 encoding is wrong.
                // Do NOT change the expected value — it is taken verbatim from the spec.
                REQUIRE(sig == "K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ");
            }
        }
    }
}

// Spec: JSON Signing Test Vector 2 — object with data
// Input:    {"one":1,"two":"Two"}   (canonical form)
// Expected: signatures.domain.ed25519:1 =
//           "KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"
SCENARIO("Spec crypto test vector: signing a data JSON object produces the spec-defined signature",
         "[conformance][signing][spec-vector]")
{
    GIVEN("the spec signing key seed and a JSON object with data values")
    {
        auto const kp = spec_seed_keypair();
        REQUIRE(kp.secret_key.size() == 64U);

        // The canonical JSON of {"one":1,"two":"Two"} is already sorted (o < t).
        auto constexpr payload = std::string_view{R"({"one":1,"two":"Two"})"};

        WHEN("the payload is signed with the spec key")
        {
            auto const sig = sign_standard_b64(payload, kp);

            THEN("the signature matches the spec test vector exactly")
            {
                // Spec MUST: this exact signature MUST result from signing the object.
                // Do NOT change the expected value — it is taken verbatim from the spec.
                REQUIRE(sig == "KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw");
            }
        }
    }
}

// Spec: Event Signing Test Vector — minimal event
// Input event: {"room_id":"!x:domain","sender":"@a:domain","origin":"domain",
//               "origin_server_ts":1000000,"signatures":{},"hashes":{},
//               "type":"X","content":{},"prev_events":[],"auth_events":[],"depth":3,
//               "unsigned":{"age_ts":1000000}}
// Expected content hash (sha256): "5jM4wQpv6lnBo7CLIghJuHdW+s2CMBJPUOGOC89ncos"
// Expected signature: "KxwGjPSDEtvnFgU00fwFz+l6d2pJM6XBIaMEn81SXPTRl16AqLAYqfIReFGZlHi5KLjAWbOoMszkwsQma+lYAg"
SCENARIO("Spec crypto test vector: minimal event content hash matches spec",
         "[conformance][signing][spec-vector][content-hash]")
{
    GIVEN("the minimally-sized spec test event")
    {
        // Exactly as given in the spec (unsorted keys, includes unsigned/hashes/signatures).
        auto const event_json = std::string{
            R"({"room_id":"!x:domain","sender":"@a:domain","origin":"domain",)"
            R"("origin_server_ts":1000000,"signatures":{},"hashes":{},)"
            R"("type":"X","content":{},"prev_events":[],"auth_events":[],"depth":3,)"
            R"("unsigned":{"age_ts":1000000}})"};

        auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the content hash is computed")
        {
            auto const hash = merovingian::events::make_content_hash(parsed.value);

            THEN("the hash matches the spec test vector exactly")
            {
                REQUIRE(hash.error.empty());
                // Spec MUST: this exact hash must result from the spec event.
                // Content hash = SHA-256(canonical JSON with unsigned/signatures/hashes removed).
                // Uses standard (not URL-safe) unpadded base64.
                // Do NOT change the expected value — it is taken verbatim from the spec.
                REQUIRE(hash.sha256 == "5jM4wQpv6lnBo7CLIghJuHdW+s2CMBJPUOGOC89ncos");
            }
        }
    }
}

// Spec: Event Signing Test Vector — content-bearing event
// Input event: {"content":{"body":"Here is the message content"},"event_id":"$0:domain",
//               "origin":"domain","origin_server_ts":1000000,"type":"m.room.message",
//               "room_id":"!r:domain","sender":"@u:domain","signatures":{},"unsigned":{"age_ts":1000000}}
// Expected content hash: "onLKD1bGljeBWQhWZ1kaP9SorVmRQNdN5aM2JYU2n/g"
SCENARIO("Spec crypto test vector: content-bearing event content hash matches spec",
         "[conformance][signing][spec-vector][content-hash]")
{
    GIVEN("the content-bearing spec test event")
    {
        auto const event_json = std::string{
            R"({"content":{"body":"Here is the message content"},"event_id":"$0:domain",)"
            R"("origin":"domain","origin_server_ts":1000000,"type":"m.room.message",)"
            R"("room_id":"!r:domain","sender":"@u:domain","signatures":{},"unsigned":{"age_ts":1000000}})"};

        auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("the content hash is computed")
        {
            auto const hash = merovingian::events::make_content_hash(parsed.value);

            THEN("the hash matches the spec test vector exactly")
            {
                REQUIRE(hash.error.empty());
                // Spec MUST: this exact hash must result from the spec event.
                // Do NOT change the expected value — it is taken verbatim from the spec.
                REQUIRE(hash.sha256 == "onLKD1bGljeBWQhWZ1kaP9SorVmRQNdN5aM2JYU2n/g");
            }
        }
    }
}
