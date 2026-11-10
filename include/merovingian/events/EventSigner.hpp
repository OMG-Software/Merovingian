// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/SerializeResult.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/crypto/Ed25519Provider.hpp"
#include "merovingian/crypto/Ed25519PublicKey.hpp"
#include "merovingian/crypto/SigningKeyStore.hpp"
#include "merovingian/events/EventSigningDiagnosticField.hpp"
#include "merovingian/events/SignatureVerificationResult.hpp"
#include "merovingian/events/SignedEventResult.hpp"
#include "merovingian/events/SigningKeyId.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::events
{

// A key ID is valid only if it names a signing algorithm this server implements.
// Spec: Matrix Server-Server API v1.19 — "The object's key is the algorithm and
// version combined (`ed25519` being the algorithm ...). Together, this forms the
// Key ID." Ed25519 is the only algorithm Matrix defines, so the shape check is
// delegated to the crypto boundary's `crypto::ed25519_key_id_is_valid`.
[[nodiscard]] auto signing_key_id_is_valid(SigningKeyId const& key_id) noexcept -> bool;

// The fields logged when `sign_event_for_server` accepts a signing request.
// Built as data, and used by the production log call, so the logging policy is
// directly assertable: `src/observability/AGENTS.md` forbids logging full
// request or event bodies, so neither the signing payload nor the signed event
// JSON may appear here. Operators triaging a peer's BadSignatureError compare
// the reported byte counts and SHA-256 digests instead of the raw bytes.
[[nodiscard]] auto sign_event_accepted_diagnostic_fields(SigningKeyId const& key_id, std::string_view signature,
                                                         std::string_view signing_payload, std::string_view signed_json)
    -> std::vector<EventSigningDiagnosticField>;
[[nodiscard]] auto matrix_base64_from_bytes(std::string_view bytes) -> std::string;
[[nodiscard]] auto matrix_bytes_from_base64(std::string_view encoded) -> std::string;
[[nodiscard]] auto make_event_signing_payload(canonicaljson::Value const& event) -> canonicaljson::SerializeResult;
[[nodiscard]] auto make_event_signing_payload(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> canonicaljson::SerializeResult;
[[nodiscard]] auto attach_event_signature(canonicaljson::Value const& event, SigningKeyId const& key_id,
                                          std::string_view signature) -> canonicaljson::SerializeResult;
[[nodiscard]] auto sign_event_for_server(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy,
                                         crypto::SigningKeyStore& key_store, crypto::Ed25519Provider& provider,
                                         std::string_view server_name) -> SignedEventResult;
[[nodiscard]] auto verify_event_signature_presence(canonicaljson::Value const& event, SigningKeyId const& key_id)
    -> SignatureVerificationResult;
[[nodiscard]] auto verify_event_signature(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy,
                                          SigningKeyId const& key_id, crypto::Ed25519PublicKey const& public_key,
                                          crypto::Ed25519Provider& provider) -> SignatureVerificationResult;

} // namespace merovingian::events
