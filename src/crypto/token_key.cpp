// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/token_key.hpp"

#include <string>

#include <sodium.h>

namespace merovingian::crypto
{
namespace
{

    // Domain separation labels for deriving access-token HMAC keys from the
    // operator's master key material. The v4 label is the current scheme; the
    // v3 label is used only to validate legacy tokens after the key-separation
    // fix (issue #322), which moved the legacy v3 key off the Ed25519 signing
    // seed onto a master-key-derived key with a distinct label. Using distinct
    // labels from the signing-secret encryption key (and from each other)
    // prevents key reuse across cryptographic purposes.
    constexpr auto k_context_v4 = std::string_view{"merovingian:access-token-hmac:1"};
    constexpr auto k_context_v3 = std::string_view{"merovingian:access-token-hmac:legacy-v3:1"};

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    // Shared derivation core parameterised by the domain-separation label so
    // v3 (legacy) and v4 (current) share identical crypto and differ only in
    // the label, guaranteeing the two keys are independent.
    [[nodiscard]] auto derive_with_label(std::span<std::uint8_t const> master_key_material,
                                         std::string_view label) noexcept -> std::optional<TokenHmacKey>
    {
        if (!sodium_is_ready() || master_key_material.empty())
        {
            return std::nullopt;
        }
        auto key = TokenHmacKey{};
        if (crypto_generichash(key.bytes.data(), key.bytes.size(), master_key_material.data(),
                               master_key_material.size(), reinterpret_cast<unsigned char const*>(label.data()),
                               label.size()) != 0)
        {
            return std::nullopt;
        }
        return key;
    }

} // namespace

auto derive_token_hmac_key(std::span<std::uint8_t const> master_key_material) noexcept -> std::optional<TokenHmacKey>
{
    return derive_with_label(master_key_material, k_context_v4);
}

auto derive_token_hmac_key_v3(std::span<std::uint8_t const> master_key_material) noexcept -> std::optional<TokenHmacKey>
{
    return derive_with_label(master_key_material, k_context_v3);
}

} // namespace merovingian::crypto
