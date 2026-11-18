// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/Pkce.hpp"

#include "merovingian/crypto/ConstantTime.hpp"
#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/Sha256.hpp"

#include <algorithm>

namespace merovingian::oauth
{
namespace
{

    [[nodiscard]] auto is_ascii_alnum(char value) noexcept -> bool
    {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9');
    }

    [[nodiscard]] auto is_base64url(char value) noexcept -> bool
    {
        return is_ascii_alnum(value) || value == '-' || value == '_';
    }

    // RFC 3986 section 2.3 unreserved, the code_verifier alphabet.
    [[nodiscard]] auto is_unreserved(char value) noexcept -> bool
    {
        return is_ascii_alnum(value) || value == '-' || value == '.' || value == '_' || value == '~';
    }

    // 43 characters carry 258 bits; a 256-bit digest leaves the last character's two low bits zero. These are the
    // base64url characters whose 6-bit value is a multiple of 4.
    [[nodiscard]] auto is_canonical_final_character(char value) noexcept -> bool
    {
        constexpr auto canonical = std::string_view{"AEIMQUYcgkosw048"};
        return canonical.find(value) != std::string_view::npos;
    }

} // namespace

auto pkce_challenge_is_valid(std::string_view challenge) noexcept -> bool
{
    return challenge.size() == pkce_challenge_chars && std::ranges::all_of(challenge, is_base64url) &&
           is_canonical_final_character(challenge.back());
}

auto pkce_verifier_is_valid(std::string_view verifier) noexcept -> bool
{
    return verifier.size() >= pkce_verifier_min_chars && verifier.size() <= pkce_verifier_max_chars &&
           std::ranges::all_of(verifier, is_unreserved);
}

auto pkce_s256_matches(std::string_view verifier, std::string_view challenge) -> bool
{
    if (!pkce_verifier_is_valid(verifier) || !pkce_challenge_is_valid(challenge))
    {
        return false;
    }
    auto const digest = crypto::sha256(verifier);
    if (!digest.has_value())
    {
        return false;
    }
    auto const encoded = crypto::base64_urlsafe_encode(*digest);
    if (!encoded.has_value())
    {
        return false;
    }
    // Both are 43 characters here, a public length.
    return crypto::constant_time_equal(*encoded, challenge);
}

} // namespace merovingian::oauth
