// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "SigningKeypair.hpp"
#include "TestEd25519Provider.hpp"
#include "TestSigningKeyStore.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/crypto/Ed25519PublicKey.hpp"
#include "merovingian/crypto/SigningKeyRecord.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/events/EventSigner.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <sodium.h>

#include <array>
#include <string>
#include <string_view>

namespace merovingian::federation::test
{

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

// make_signed_event_json signs with a TestSigningKeyStore and a
// TestEd25519Provider built from the same seed as the remote's
// FederationKeyRecord, so the signature verifies against the key the runtime
// holds. It also computes and attaches the content hash, so the resulting
// event passes verify_pdu_content_hash.
//
// Builds a fully signed PDU event JSON: computes and attaches the content
// hash, then signs the result with Ed25519. The resulting JSON has valid
// hashes.sha256 and signatures fields, so it passes both
// verify_pdu_content_hash and authorize_federation_pdu when the remote's
// signing_key was built from the same key_seed.
//
// sign_event_for_server() only signs whatever event is handed to it — it
// does NOT compute or attach hashes.sha256 (see EventSigner.cpp). Production
// code (RoomService.cpp: compose_event/handle_send_join/handle_send_leave)
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

// The event ID a signed event really has: "$" + the reference hash of the
// redacted event, per the room version's rules. An inbound /invite is filed
// under the {eventId} in its URL, which the server now requires to equal this
// (audit FED-5), so a test that sends one must use this value in the path.
// Returns an empty string for JSON that does not parse or a version that is
// not supported.
[[nodiscard]] inline auto reference_hash_event_id(std::string_view signed_event_json, std::string_view room_version)
    -> std::string
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(signed_event_json);
    if (parsed.error != merovingian::canonicaljson::ParseError::none)
    {
        return {};
    }
    auto const* policy = merovingian::rooms::find_room_version_policy(std::string{room_version});
    if (policy == nullptr)
    {
        return {};
    }
    return merovingian::events::make_reference_hash_event_id(parsed.value, *policy).event_id;
}

} // namespace merovingian::federation::test
