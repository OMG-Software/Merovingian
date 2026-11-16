// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/Sha256.hpp"

#include <sodium.h>

namespace merovingian::crypto
{

static_assert(sha256_digest_bytes == crypto_hash_sha256_BYTES);

auto sha256(std::string_view input) -> std::optional<std::string>
{
    if (sodium_init() < 0)
    {
        return std::nullopt;
    }
    auto digest = std::string(sha256_digest_bytes, '\0');
    if (crypto_hash_sha256(reinterpret_cast<unsigned char*>(digest.data()),
                           reinterpret_cast<unsigned char const*>(input.data()), input.size()) != 0)
    {
        return std::nullopt;
    }
    return digest;
}

} // namespace merovingian::crypto
