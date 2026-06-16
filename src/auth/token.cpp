// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/token.hpp"

#include "merovingian/crypto/constant_time.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <vector>

namespace merovingian::auth
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("token", event, std::move(fields)));
    }

} // namespace

auto token_secret_has_required_entropy(std::string_view token_secret) noexcept -> bool
{
    return token_secret.size() >= 32U && token_secret.size() <= 4096U;
}

auto token_hash_is_persistable(TokenHash const& token_hash) noexcept -> bool
{
    return !token_hash.algorithm.empty() && !token_hash.value.empty() && token_hash.value.size() >= 32U &&
           token_hash.value.size() <= 4096U;
}

auto token_is_active(AccessTokenRecord const& token, std::chrono::system_clock::time_point now) -> TokenPolicyDecision
{
    auto result = [&]() -> TokenPolicyDecision {
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
    }();
    log_diagnostic(result.accepted ? "token.active" : "token.rejected",
                   {{"reason", result.reason, false}});
    return result;
}

auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool
{
    // Delegates to the crypto module's libsodium-backed comparison so every
    // constant-time secret comparison shares one hardened implementation and
    // libsodium calls stay confined to src/crypto/ (see the crypto-boundary rule).
    return crypto::constant_time_equal(left, right);
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
