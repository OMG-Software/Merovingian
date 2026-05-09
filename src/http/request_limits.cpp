// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/request_limits.hpp>

#include <string>

namespace merovingian::http
{
namespace
{

[[nodiscard]] auto is_tchar(char value) noexcept -> bool
{
    return (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '!' || value == '#'
        || value == '$' || value == '%' || value == '&' || value == '\'' || value == '*' || value == '+'
        || value == '-' || value == '.' || value == '^' || value == '_' || value == '`' || value == '|'
        || value == '~';
}

[[nodiscard]] auto contains_control_or_space(std::string_view value) noexcept -> bool
{
    for (auto const character : value)
    {
        auto const byte = static_cast<unsigned char>(character);
        if (byte <= 0x20U || byte == 0x7FU)
        {
            return true;
        }
    }

    return false;
}

} // namespace

auto validate_request_limits(RequestLimits const& limits) -> std::vector<RequestLimitFinding>
{
    auto findings = std::vector<RequestLimitFinding>{};

    if (limits.max_start_line_bytes == 0U || limits.max_start_line_bytes > 8192U)
    {
        findings.push_back({"http.max_start_line_bytes", "start line limit must be between 1 and 8192 bytes"});
    }

    if (limits.max_header_bytes == 0U || limits.max_header_bytes > 65536U)
    {
        findings.push_back({"http.max_header_bytes", "header byte limit must be between 1 and 65536 bytes"});
    }

    if (limits.max_header_count == 0U || limits.max_header_count > 200U)
    {
        findings.push_back({"http.max_header_count", "header count limit must be between 1 and 200"});
    }

    if (limits.max_body_bytes > 67108864U)
    {
        findings.push_back({"http.max_body_bytes", "body byte limit must not exceed 64MiB"});
    }

    return findings;
}

auto request_limits_are_valid(RequestLimits const& limits) -> bool
{
    return validate_request_limits(limits).empty();
}

auto method_token_is_valid(std::string_view method) noexcept -> bool
{
    if (method.empty())
    {
        return false;
    }

    for (auto const character : method)
    {
        if (!is_tchar(character))
        {
            return false;
        }
    }

    return true;
}

auto request_target_is_valid(std::string_view target) noexcept -> bool
{
    return !target.empty() && !contains_control_or_space(target);
}

auto request_line_is_within_limit(
    std::string_view method,
    std::string_view target,
    RequestLimits const& limits
) noexcept -> bool
{
    if (!method_token_is_valid(method) || !request_target_is_valid(target))
    {
        return false;
    }

    auto const request_line_bytes = method.size() + 1U + target.size() + 1U + std::string_view{"HTTP/1.1"}.size();
    return request_line_bytes <= limits.max_start_line_bytes;
}

auto request_limits_summary(RequestLimits const& limits) -> std::string
{
    return "HTTP request limits: max_start_line_bytes=" + std::to_string(limits.max_start_line_bytes)
        + " max_header_bytes=" + std::to_string(limits.max_header_bytes)
        + " max_header_count=" + std::to_string(limits.max_header_count)
        + " max_body_bytes=" + std::to_string(limits.max_body_bytes);
}

} // namespace merovingian::http
