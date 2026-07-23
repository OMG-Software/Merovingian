// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <sodium.h>

namespace merovingian::federation::test
{

struct SigningKeypair final
{
    std::string public_key{}; // raw 32-byte Ed25519 public key
    std::string secret_key{}; // raw 64-byte Ed25519 secret key
};

// Derives a deterministic Ed25519 keypair from a seed string. Tests pair a
// signed federation request (signed with secret_key) against the remote key
// record that verifies it (carrying public_key), so both sides must come from
// the same seed. Real federation uses randomly generated keys; the seed only
// keeps test expectations reproducible.
[[nodiscard]] inline auto keypair_from_seed(std::string_view seed_text) -> SigningKeypair
{
    static_cast<void>(sodium_init());
    auto seed = std::array<unsigned char, crypto_sign_SEEDBYTES>{};
    crypto_generichash(seed.data(), seed.size(), reinterpret_cast<unsigned char const*>(seed_text.data()),
                       seed_text.size(), nullptr, 0U);
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    crypto_sign_seed_keypair(public_key.data(), secret_key.data(), seed.data());
    return {
        std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()},
        std::string{reinterpret_cast<char const*>(secret_key.data()), secret_key.size()}
    };
}

// Returns the unpadded Matrix base64 encoding of the keypair's public key,
// ready to be stored in the "ed25519:DEVICE_ID" field of a device_keys upload.
[[nodiscard]] inline auto pubkey_b64(SigningKeypair const& kp) -> std::string
{
    return merovingian::events::matrix_base64_from_bytes(kp.public_key);
}

// Returns a non-owning span over the keypair's raw 64-byte Ed25519 secret key.
// The caller MUST keep `kp` alive for as long as the span is used — e.g. across
// a synchronous build_outbound_request call where the OutboundCall borrows it.
// Used by tests that wire OutboundCall::secret_key (now a span) without
// materialising an unpinned std::string copy of the key.
[[nodiscard]] inline auto secret_key_span(SigningKeypair const& kp) -> std::span<std::uint8_t const>
{
    return {reinterpret_cast<std::uint8_t const*>(kp.secret_key.data()), kp.secret_key.size()};
}

// Copies the keypair's raw 64-byte Ed25519 secret key into an owning, mlocked,
// zeroised SecretBuffer — the shape production uses for DispatchWorkerConfig and
// the runtime signing key. The caller no longer needs to keep `kp` alive after
// this returns, because the SecretBuffer holds its own copy of the bytes.
[[nodiscard]] inline auto secret_key_buffer(SigningKeypair const& kp) -> core::SecretBuffer
{
    return core::SecretBuffer{secret_key_span(kp)};
}

// Signs `payload` with the Ed25519 secret key and returns the unpadded base64
// encoded signature. Suitable for constructing OTK / fallback key payloads.
[[nodiscard]] inline auto sign_payload_b64(std::string_view payload, std::string const& secret_key_bytes) -> std::string
{
    auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<unsigned char const*>(payload.data()), payload.size(),
                         reinterpret_cast<unsigned char const*>(secret_key_bytes.data()));
    return merovingian::events::matrix_base64_from_bytes(
        {reinterpret_cast<char const*>(sig.data()), crypto_sign_BYTES});
}

// Builds a complete signed_curve25519 OTK JSON value (no wrapping key-id object).
// The signature covers the canonical JSON payload {"key":"key_value"}.
// Use the same keypair's public key (via pubkey_b64()) in the device_keys upload.
[[nodiscard]] inline auto make_signed_otk_json(std::string_view user_id, std::string_view device_id,
                                               std::string_view key_value, std::string const& secret_key_bytes)
    -> std::string
{
    auto const payload = std::string{R"({"key":")"} + std::string{key_value} + R"("})";
    auto const sig_b64 = sign_payload_b64(payload, secret_key_bytes);
    return std::string{R"({"key":")"} + std::string{key_value} + R"(","signatures":{")" + std::string{user_id} +
           R"(":{"ed25519:)" + std::string{device_id} + R"(":")" + sig_b64 + R"("}}})";
}

// Builds a complete signed fallback key JSON value (includes "fallback":true).
// The signature covers {"fallback":true,"key":"key_value"} (canonical field order).
// Use the same keypair's public key in the device_keys upload.
[[nodiscard]] inline auto make_signed_fallback_key_json(std::string_view user_id, std::string_view device_id,
                                                        std::string_view key_value, std::string const& secret_key_bytes)
    -> std::string
{
    // "fallback" sorts before "key" in canonical JSON.
    auto const payload = std::string{R"({"fallback":true,"key":")"} + std::string{key_value} + R"("})";
    auto const sig_b64 = sign_payload_b64(payload, secret_key_bytes);
    return std::string{R"({"fallback":true,"key":")"} + std::string{key_value} + R"(","signatures":{")" +
           std::string{user_id} + R"(":{"ed25519:)" + std::string{device_id} + R"(":")" + sig_b64 + R"("}}})";
}

// +-------------------------------------------------------------------------+
// |  Event signing helpers for PDU verification tests                        |
// |                                                                         |
// |  sign_event_for_server requires a SigningKeyStore and an Ed25519Provider.|
// |  These test implementations derive the keypair from the same seed used   |
// |  to build the remote's FederationKeyRecord, so the signature verifies    |
// |  against the key the runtime holds.                                     |
// |  sign_event_for_server also computes and attaches the content hash, so   |
// |  the resulting event passes verify_pdu_content_hash.                    |
// +-------------------------------------------------------------------------+
class TestSigningKeyStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit TestSigningKeyStore(merovingian::crypto::SigningKeyRecord key)
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
    merovingian::crypto::SigningKeyRecord key_;
};

class TestEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    explicit TestEd25519Provider(std::string key_material)
        : key_material_{std::move(key_material)}
    {
    }

    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const&, std::string_view message)
        -> merovingian::crypto::SignatureResult override
    {
        auto kp = keypair_from_seed(key_material_);
        auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
        crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<unsigned char const*>(message.data()),
                             message.size(), reinterpret_cast<unsigned char const*>(kp.secret_key.data()));
        return {
            merovingian::crypto::Ed25519Signature{std::string{reinterpret_cast<char const*>(sig.data()), sig.size()}},
            {}};
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

// Builds a fully signed PDU event JSON: computes and attaches the content
// hash, then signs the result with Ed25519. The resulting JSON has valid
// hashes.sha256 and signatures fields, so it passes both
// verify_pdu_content_hash and authorize_federation_pdu when the remote's
// signing_key was built from the same key_seed.
//
// sign_event_for_server() only signs whatever event is handed to it — it
// does NOT compute or attach hashes.sha256 (see event_signer.cpp). Production
// code (room_service.cpp: compose_event/handle_send_join/handle_send_leave)
// always calls events::make_content_hash() and attaches the "hashes" member
// as an explicit prior step before signing; this helper mirrors that exact
// sequence so a "properly signed" test PDU is indistinguishable from a
// production one.
//
// Parameters:
//   unsigned_event_json — the event JSON WITHOUT signatures or hashes fields.
//   server_name         — the signing server's name (must match the remote's).
//   key_id              — the signing key ID (e.g. "ed25519:auto").
//   key_seed            — the seed string used to derive the keypair; the same
//                         seed must be used to build the FederationKeyRecord.
//   room_version        — room version string (e.g. "12") for signing rules.
[[nodiscard]] inline auto make_signed_event_json(std::string_view unsigned_event_json, std::string_view server_name,
                                                 std::string_view key_id, std::string_view key_seed,
                                                 std::string_view room_version = "12") -> std::string
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(unsigned_event_json);
    if (parsed.error != merovingian::canonicaljson::ParseError::none)
    {
        return {};
    }
    auto const* policy = merovingian::rooms::find_room_version_policy(std::string{room_version});
    if (policy == nullptr)
    {
        return {};
    }
    auto const* event_object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    if (event_object == nullptr)
    {
        return {};
    }
    auto const content_hash = merovingian::events::make_content_hash(parsed.value);
    if (!content_hash.error.empty())
    {
        return {};
    }
    auto hashed_object = *event_object;
    auto hashes = merovingian::canonicaljson::Object{};
    hashes.push_back(
        merovingian::canonicaljson::make_member("sha256", merovingian::canonicaljson::Value{content_hash.sha256}));
    hashed_object.push_back(
        merovingian::canonicaljson::make_member("hashes", merovingian::canonicaljson::Value{std::move(hashes)}));
    auto const hashed_event = merovingian::canonicaljson::Value{std::move(hashed_object)};

    auto const kp = keypair_from_seed(key_seed);
    auto store = TestSigningKeyStore{
        merovingian::crypto::SigningKeyRecord{std::string{server_name}, std::string{key_id},
                                              merovingian::crypto::Ed25519PublicKey{kp.public_key}, true}
    };
    auto provider = TestEd25519Provider{std::string{key_seed}};
    auto const signed_event =
        merovingian::events::sign_event_for_server(hashed_event, *policy, store, provider, std::string{server_name});
    return signed_event.event_json;
}

} // namespace merovingian::federation::test
