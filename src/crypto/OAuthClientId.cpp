// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/OAuthClientId.hpp"

#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/GenericHash.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

auto oauth_client_id(std::string_view canonical_metadata, TokenHmacKey const& key) -> std::optional<std::string>
{
    auto const pieces = std::array<std::string_view, 1U>{canonical_metadata};
    auto const digest = generic_hash_bytes(pieces, std::span<std::uint8_t const>{key.bytes.data(), key.bytes.size()});
    if (!digest.has_value())
    {
        return std::nullopt;
    }
    auto encoded =
        base64_urlsafe_encode(std::string_view{reinterpret_cast<char const*>(digest->data()), digest->size()});
    if (!encoded.has_value() || encoded->size() != oauth_client_id_chars)
    {
        return std::nullopt;
    }
    return encoded;
}

} // namespace merovingian::crypto
