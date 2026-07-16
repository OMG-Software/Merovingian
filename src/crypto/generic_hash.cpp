// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/generic_hash.hpp"

#include <array>

#include <sodium.h>

namespace merovingian::crypto
{
namespace
{

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

} // namespace

auto generic_hash(std::span<std::string_view const> pieces, std::span<std::uint8_t const> key)
    -> std::optional<std::string>
{
    if (!sodium_is_ready())
    {
        return std::nullopt;
    }
    auto state = crypto_generichash_state{};
    auto const key_data = key.empty() ? nullptr : reinterpret_cast<unsigned char const*>(key.data());
    auto const key_len = key.empty() ? 0ULL : static_cast<unsigned long long>(key.size());
    if (crypto_generichash_init(&state, key_data, key_len, crypto_generichash_BYTES) != 0)
    {
        return std::nullopt;
    }
    for (auto const& piece : pieces)
    {
        if (crypto_generichash_update(&state, reinterpret_cast<unsigned char const*>(piece.data()), piece.size()) != 0)
        {
            return std::nullopt;
        }
        auto const separator = static_cast<unsigned char>(0U);
        if (crypto_generichash_update(&state, &separator, 1U) != 0)
        {
            return std::nullopt;
        }
    }
    auto digest = std::array<unsigned char, crypto_generichash_BYTES>{};
    if (crypto_generichash_final(&state, digest.data(), digest.size()) != 0)
    {
        return std::nullopt;
    }
    auto output = std::string(digest.size() * 2U + 1U, '\0');
    if (sodium_bin2hex(output.data(), output.size(), digest.data(), digest.size()) == nullptr)
    {
        return std::nullopt;
    }
    output.pop_back();
    return output;
}

auto hash_bytes_to_hex(std::string_view input) -> std::optional<std::string>
{
    if (!sodium_is_ready())
    {
        return std::nullopt;
    }
    auto digest = std::array<unsigned char, crypto_generichash_BYTES>{};
    if (crypto_generichash(digest.data(), digest.size(), reinterpret_cast<unsigned char const*>(input.data()),
                           static_cast<unsigned long long>(input.size()), nullptr, 0U) != 0)
    {
        return std::nullopt;
    }
    auto output = std::string(digest.size() * 2U + 1U, '\0');
    if (sodium_bin2hex(output.data(), output.size(), digest.data(), digest.size()) == nullptr)
    {
        return std::nullopt;
    }
    output.pop_back();
    return output;
}

} // namespace merovingian::crypto
