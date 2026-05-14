// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <string>
#include <string_view>

namespace merovingian::events
{

struct SigningKeyId final
{
    std::string server_name{};
    std::string key_id{};
};

struct SignatureVerificationResult final
{
    bool valid{false};
    std::string error{};
};

struct SignedEventResult final
{
    std::string event_json{};
    std::string server_name{};
    std::string key_id{};
    std::string signature{};
    std::string error{};
};

[[nodiscard]] auto signing_key_id_is_valid(SigningKeyId const& key_id) noexcept -> bool;
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
