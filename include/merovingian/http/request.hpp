// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::http
{

enum class RequestErrorCode : std::uint8_t
{
    none,
    malformed_request_line,
    invalid_method,
    invalid_target,
    start_line_too_large,
    headers_too_large,
    too_many_headers,
    duplicate_content_length,
    invalid_content_length,
    body_too_large,
    unsupported_transfer_encoding,
};

struct Header final
{
    std::string name{};
    std::string value{};
};

struct RequestHead final
{
    std::string method{};
    std::string target{};
    std::vector<Header> headers{};
    std::uint64_t content_length{0U};
    bool has_content_length{false};
};

struct RequestParseResult final
{
    RequestHead request{};
    RequestErrorCode error{RequestErrorCode::none};
};

[[nodiscard]] auto request_error_name(RequestErrorCode code) noexcept -> char const*;
[[nodiscard]] auto request_error_status(RequestErrorCode code) noexcept -> std::uint16_t;
[[nodiscard]] auto header_name_is_valid(std::string_view name) noexcept -> bool;
[[nodiscard]] auto header_value_is_valid(std::string_view value) noexcept -> bool;
[[nodiscard]] auto parse_request_head(std::string_view input) -> RequestParseResult;

} // namespace merovingian::http
