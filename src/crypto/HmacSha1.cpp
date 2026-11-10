// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/crypto/HmacSha1.hpp"

#include <limits>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace merovingian::crypto
{

auto hmac_sha1(std::span<std::uint8_t const> key, std::span<std::uint8_t const> message)
    -> std::optional<std::array<std::uint8_t, hmac_sha1_bytes>>
{
    constexpr auto max_int = static_cast<std::size_t>(std::numeric_limits<int>::max());
    if (key.empty() || key.size() > max_int)
    {
        return std::nullopt;
    }
    auto digest = std::array<std::uint8_t, hmac_sha1_bytes>{};
    auto length = static_cast<unsigned int>(digest.size());
    // HMAC() returns null on failure; it writes at most EVP_MAX_MD_SIZE bytes and SHA-1 gives 20, the size of `digest`.
    if (HMAC(EVP_sha1(), // NOSONAR(cpp:S4790): coturn's REST API fixes this algorithm for its keyed MAC (ADR-0480).
             key.data(), static_cast<int>(key.size()), message.data(), message.size(), digest.data(),
             &length) == nullptr ||
        length != digest.size())
    {
        return std::nullopt;
    }
    return digest;
}

} // namespace merovingian::crypto
