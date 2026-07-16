// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/password.hpp"

#include <array>
#include <cstddef>

#include <sodium.h>

namespace merovingian::auth
{
namespace
{

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

} // namespace

auto hash_password(std::string_view password) -> std::optional<std::string>
{
    if (!sodium_is_ready())
    {
        return std::nullopt;
    }
    auto output = std::array<char, crypto_pwhash_STRBYTES>{};
    if (crypto_pwhash_str(output.data(), password.data(), static_cast<unsigned long long>(password.size()),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        return std::nullopt;
    }
    return std::string{"password-hash:v2:"} + std::string{output.data()};
}

auto password_matches(std::string_view password_hash, std::string_view password) noexcept -> bool
{
    if (!sodium_is_ready() || password_hash.empty() || password.empty())
    {
        return false;
    }
    auto constexpr prefix = std::string_view{"password-hash:v2:"};
    auto const payload = password_hash.starts_with(prefix) ? password_hash.substr(prefix.size()) : password_hash;
    return crypto_pwhash_str_verify(payload.data(), password.data(),
                                    static_cast<unsigned long long>(password.size())) == 0;
}

auto hash_registration_token(std::span<std::uint8_t const> token) -> std::optional<std::string>
{
    if (!sodium_is_ready() || token.empty())
    {
        return std::nullopt;
    }
    auto output = std::array<char, crypto_pwhash_STRBYTES>{};
    if (crypto_pwhash_str(output.data(), reinterpret_cast<char const*>(token.data()),
                          static_cast<unsigned long long>(token.size()), crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        return std::nullopt;
    }
    return std::string{output.data()};
}

auto registration_token_matches(std::string_view expected_hash, std::string_view presented) noexcept -> bool
{
    if (!sodium_is_ready() || expected_hash.empty() || presented.empty())
    {
        return false;
    }
    return crypto_pwhash_str_verify(expected_hash.data(), presented.data(),
                                    static_cast<unsigned long long>(presented.size())) == 0;
}

} // namespace merovingian::auth
