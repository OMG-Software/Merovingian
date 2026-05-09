// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::http
{

struct RequestLimits final
{
    std::uint32_t max_start_line_bytes{8192U};
    std::uint32_t max_header_bytes{32768U};
    std::uint32_t max_header_count{100U};
    std::uint64_t max_body_bytes{1048576U};
};

struct RequestLimitFinding final
{
    std::string field{};
    std::string message{};
};

[[nodiscard]] auto validate_request_limits(RequestLimits const& limits) -> std::vector<RequestLimitFinding>;
[[nodiscard]] auto request_limits_are_valid(RequestLimits const& limits) -> bool;
[[nodiscard]] auto method_token_is_valid(std::string_view method) noexcept -> bool;
[[nodiscard]] auto request_target_is_valid(std::string_view target) noexcept -> bool;
[[nodiscard]] auto request_line_is_within_limit(
    std::string_view method,
    std::string_view target,
    RequestLimits const& limits
) noexcept -> bool;
[[nodiscard]] auto request_limits_summary(RequestLimits const& limits) -> std::string;

} // namespace merovingian::http
