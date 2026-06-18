// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/token_key.hpp"

#include <string>

#include <sodium.h>

namespace merovingian::crypto
{
namespace
{

    // Domain separation label for deriving the access-token HMAC key from the
    // operator's master key material. Using a distinct label from the
    // signing-secret encryption key prevents key reuse across cryptographic
    // purposes.
    constexpr auto k_context = std::string_view{"merovingian:access-token-hmac:1"};

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

} // namespace

auto derive_token_hmac_key(std::span<std::uint8_t const> master_key_material) noexcept -> std::optional<TokenHmacKey>
{
    if (!sodium_is_ready() || master_key_material.empty())
    {
        return std::nullopt;
    }

    auto key = TokenHmacKey{};
    if (crypto_generichash(key.bytes.data(), key.bytes.size(), master_key_material.data(), master_key_material.size(),
                           reinterpret_cast<unsigned char const*>(k_context.data()), k_context.size()) != 0)
    {
        return std::nullopt;
    }
    return key;
}

} // namespace merovingian::crypto
