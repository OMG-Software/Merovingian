// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/token.hpp"

#include <algorithm>
#include <cstddef>
#include <string>

namespace merovingian::auth
{

auto token_secret_has_required_entropy(std::string_view token_secret) noexcept -> bool
{
    return token_secret.size() >= 32U && token_secret.size() <= 4096U;
}

auto token_hash_is_persistable(TokenHash const& token_hash) noexcept -> bool
{
    return !token_hash.algorithm.empty() && !token_hash.value.empty()
        && token_hash.value.size() >= 32U && token_hash.value.size() <= 4096U;
}

auto token_is_active(AccessTokenRecord const& token, std::chrono::system_clock::time_point now) -> TokenPolicyDecision
{
    if (token.revoked)
    {
        return {false, "token revoked"};
    }
    if (token.expires_at <= now)
    {
        return {false, "token expired"};
    }
    if (!token_hash_is_persistable(token.token_hash))
    {
        return {false, "token hash is not persistable"};
    }

    return {true, {}};
}

auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool
{
    auto difference = left.size() ^ right.size();
    auto const compared_size = std::max(left.size(), right.size());

    for (std::size_t index = 0; index < compared_size; ++index)
    {
        auto const left_byte = index < left.size() ? static_cast<unsigned char>(left[index]) : 0U;
        auto const right_byte = index < right.size() ? static_cast<unsigned char>(right[index]) : 0U;
        difference |= left_byte ^ right_byte;
    }

    return difference == 0U;
}

auto redacted_token_for_log(std::string_view token_secret) -> std::string
{
    if (token_secret.empty())
    {
        return "[redacted-token:empty]";
    }

    return "[redacted-token:length=" + std::to_string(token_secret.size()) + ']';
}

} // namespace merovingian::auth
