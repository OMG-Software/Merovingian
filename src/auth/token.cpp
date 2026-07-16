// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/token.hpp"

#include "merovingian/crypto/constant_time.hpp"
#include "merovingian/crypto/encoding.hpp"
#include "merovingian/crypto/generic_hash.hpp"
#include "merovingian/crypto/token_key.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <array>
#include <string>
#include <vector>

#include <sodium.h>

namespace merovingian::auth
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("token", event, fields, severity);
    }

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
    log_diagnostic(result.accepted ? "token.active" : "token.rejected", {
                                                                            {"reason", result.reason, false}
    });
    return result;
}

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

auto redacted_token_for_log(std::string_view token_secret) -> std::string
{
    if (token_secret.empty())
    {
        return "[redacted-token:empty]";
    }

    return "[redacted-token:length=" + std::to_string(token_secret.size()) + ']';
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
