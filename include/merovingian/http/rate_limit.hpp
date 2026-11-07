// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/generic_hash.hpp"
#include "merovingian/http/RateLimitConfig.hpp"
#include "merovingian/http/RateLimitPolicy.hpp"
#include "merovingian/http/RateLimitTier.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iterator>
#include <list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::http
{


[[nodiscard]] auto rate_limit_tier_for(std::string_view target) noexcept -> RateLimitTier;
[[nodiscard]] auto rate_limit_tier_name(RateLimitTier tier) noexcept -> std::string_view;
// Inverse of rate_limit_tier_name(); std::nullopt for an unknown tier name.
// Used by the config parser so a typo in client_rate_limits.tier.<name>
// becomes a parse finding instead of a silently ignored key.
[[nodiscard]] auto rate_limit_tier_from_name(std::string_view name) noexcept -> std::optional<RateLimitTier>;
[[nodiscard]] auto rate_limit_tier_default(RateLimitTier tier) noexcept -> RateLimitPolicy;

[[nodiscard]] auto rate_limit_policy_is_valid(RateLimitPolicy const& policy) noexcept -> bool;
[[nodiscard]] auto endpoint_default_rate_limit(std::string_view method, std::string_view target) noexcept
    -> RateLimitPolicy;
[[nodiscard]] auto rate_limit_summary(RateLimitPolicy const& policy) -> std::string;

[[nodiscard]] auto default_client_rate_limit_config() noexcept -> RateLimitConfig;

} // namespace merovingian::http
