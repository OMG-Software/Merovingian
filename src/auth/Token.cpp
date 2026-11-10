// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/Token.hpp"

#include "merovingian/crypto/TokenHmacKey.hpp"
#include "merovingian/crypto/ConstantTime.hpp"
#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/GenericHash.hpp"

#include <sodium.h>

#include <array>
#include <string>
#include <vector>

namespace merovingian::auth
{
namespace
{

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    [[nodiscard]] auto keyed_hash_to_hex(std::string_view token, merovingian::crypto::TokenHmacKey const& key)
        -> std::optional<std::string>
    {
        if (!sodium_is_ready())
        {
            return std::nullopt;
        }
        auto digest = std::array<unsigned char, crypto_generichash_BYTES>{};
        if (crypto_generichash(digest.data(), digest.size(), reinterpret_cast<unsigned char const*>(token.data()),
                               static_cast<unsigned long long>(token.size()), key.bytes.data(), key.bytes.size()) != 0)
        {
            return std::nullopt;
        }
        auto const encoded = crypto::to_hex(std::span<unsigned char const>{digest.data(), digest.size()});
        if (!encoded.has_value())
        {
            return std::nullopt;
        }
        return *encoded;
    }

} // namespace

auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool
{
    // Delegates to the crypto module's libsodium-backed comparison so every
    // constant-time secret comparison shares one hardened implementation and
    // libsodium calls stay confined to src/crypto/ (see the crypto-boundary rule).
    return crypto::constant_time_equal(left, right);
}

auto constant_time_equal_variable_length(std::string_view left, std::string_view right) noexcept -> bool
{
    // Variable-length secrets (e.g. plaintext registration tokens, typed passwords)
    // must not be compared with a length check first because that leaks whether the
    // presented length matches the expected length. Hash first, compare fixed-size.
    return crypto::constant_time_equal_variable_length(left, right);
}

auto hash_access_token_v2(std::string_view token) -> std::optional<std::string>
{
    if (token.empty())
    {
        return std::nullopt;
    }
    auto const digest = crypto::hash_bytes_to_hex(token);
    if (!digest.has_value())
    {
        return std::nullopt;
    }
    return "token-hash:v2:" + *digest;
}

auto hash_access_token_v3(std::string_view token, merovingian::crypto::TokenHmacKey const& key)
    -> std::optional<std::string>
{
    if (token.empty())
    {
        return std::nullopt;
    }
    auto const digest = keyed_hash_to_hex(token, key);
    if (!digest.has_value())
    {
        return std::nullopt;
    }
    return "token-hash:v3:" + *digest;
}

auto hash_access_token_v4(std::string_view token, merovingian::crypto::TokenHmacKey const& key)
    -> std::optional<std::string>
{
    if (token.empty())
    {
        return std::nullopt;
    }
    auto const digest = keyed_hash_to_hex(token, key);
    if (!digest.has_value())
    {
        return std::nullopt;
    }
    return "token-hash:v4:" + *digest;
}

} // namespace merovingian::auth
