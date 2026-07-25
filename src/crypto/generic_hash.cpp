// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/generic_hash.hpp"

#include <array>
#include <vector>

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

    // Shared libsodium generichash core: updates the state with each piece
    // followed by a NUL separator, then writes the digest into the caller-owned
    // buffer. Returns false on any libsodium failure.
    [[nodiscard]] auto generichash_pieces_to_bytes(std::span<std::string_view const> pieces,
                                                   std::span<std::uint8_t const> key,
                                                   std::span<unsigned char> digest) noexcept -> bool
    {
        if (!sodium_is_ready())
        {
            return false;
        }
        auto state = crypto_generichash_state{};
        auto const key_data = key.empty() ? nullptr : reinterpret_cast<unsigned char const*>(key.data());
        auto const key_len = key.empty() ? 0ULL : static_cast<unsigned long long>(key.size());
        if (crypto_generichash_init(&state, key_data, key_len, digest.size()) != 0)
        {
            return false;
        }
        for (auto const& piece : pieces)
        {
            if (crypto_generichash_update(&state, reinterpret_cast<unsigned char const*>(piece.data()), piece.size()) !=
                0)
            {
                return false;
            }
            auto const separator = static_cast<unsigned char>(0U);
            if (crypto_generichash_update(&state, &separator, 1U) != 0)
            {
                return false;
            }
        }
        return crypto_generichash_final(&state, digest.data(), digest.size()) == 0;
    }

} // namespace

auto generic_hash(std::span<std::string_view const> pieces, std::span<std::uint8_t const> key)
    -> std::optional<std::string>
{
    auto digest = std::array<unsigned char, crypto_generichash_BYTES>{};
    if (!generichash_pieces_to_bytes(pieces, key, digest))
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

auto generic_hash_bytes(std::span<std::string_view const> pieces, std::span<std::uint8_t const> key)
    -> std::optional<std::vector<std::uint8_t>>
{
    auto digest = std::array<unsigned char, crypto_generichash_BYTES>{};
    if (!generichash_pieces_to_bytes(pieces, key, digest))
    {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>{digest.begin(), digest.end()};
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
