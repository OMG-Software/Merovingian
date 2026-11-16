// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/TokenHmacKey.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

// The length of every OAuth 2.0 client ID: a 32-byte BLAKE2b digest in unpadded URL-safe base64.
inline constexpr auto oauth_client_id_chars = std::size_t{43U};

// The OAuth 2.0 client ID of the accepted client metadata `canonical_metadata` (oauth::ClientMetadata::canonical_bytes,
// plan P2, ADR-0779): BLAKE2b-256 keyed with `key` (derive_oauth_client_id_key), in unpadded URL-safe base64, so
// exactly `oauth_client_id_chars` characters of A-Z a-z 0-9 - _, safe in a form field, a URL query and a log line.
// The same metadata and key always give the same ID; without the key no one can compute the ID of given metadata.
// nullopt only when libsodium fails.
[[nodiscard]] auto oauth_client_id(std::string_view canonical_metadata, TokenHmacKey const& key)
    -> std::optional<std::string>;

} // namespace merovingian::crypto
