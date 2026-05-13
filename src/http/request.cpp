// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/request.hpp"

#include "merovingian/http/request_limits.hpp"

#include <limits>
#include <string>
#include <string_view>

namespace merovingian::http
{
namespace
{

    [[nodiscard]] auto is_tchar(char value) noexcept -> bool
    {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
               value == '!' || value == '#' || value == '$' || value == '%' || value == '&' || value == '\'' ||
               value == '*' || value == '+' || value == '-' || value == '.' || value == '^' || value == '_' ||
               value == '`' || value == '|' || value == '~';
    }

    [[nodiscard]] auto is_optional_whitespace(char value) noexcept -> bool
    {
        return value == ' ' || value == '\t';
    }

    [[nodiscard]] auto trim_optional_whitespace(std::string_view value) noexcept -> std::string_view
    {
        auto begin = std::size_t{0U};
        auto end = value.size();
        while (begin < end && is_optional_whitespace(value[begin]))
        {
            ++begin;
        }
        while (end > begin && is_optional_whitespace(value[end - 1U]))
        {
            --end;
        }

        return value.substr(begin, end - begin);
    }

    [[nodiscard]] auto equals_ascii_case_insensitive(std::string_view lhs, std::string_view rhs) noexcept -> bool
    {
        if (lhs.size() != rhs.size())
        {
            return false;
        }

        for (auto index = std::size_t{0U}; index < lhs.size(); ++index)
        {
            auto left = lhs[index];
            auto right = rhs[index];
            if (left >= 'A' && left <= 'Z')
            {
                left = static_cast<char>(left - 'A' + 'a');
            }
            if (right >= 'A' && right <= 'Z')
            {
                right = static_cast<char>(right - 'A' + 'a');
            }
            if (left != right)
            {
                return false;
            }
        }

        return true;
    }

    [[nodiscard]] auto parse_u64_decimal(std::string_view value, std::uint64_t& output) noexcept -> bool
    {
        if (value.empty())
        {
            return false;
        }

        auto parsed = std::uint64_t{0U};
        for (auto const character : value)
        {
            if (character < '0' || character > '9')
            {
                return false;
            }

            auto const digit = static_cast<std::uint64_t>(character - '0');
            if (parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
            {
                return false;
            }
            parsed = (parsed * 10U) + digit;
        }

        output = parsed;
        return true;
    }

    auto append_header_or_error(RequestHead& request, Header header, RequestErrorCode& error) -> void
    {
        if (equals_ascii_case_insensitive(header.name, "content-length"))
        {
            auto parsed = std::uint64_t{0U};
            if (!parse_u64_decimal(trim_optional_whitespace(header.value), parsed))
            {
                error = RequestErrorCode::invalid_content_length;
                return;
            }
            if (request.has_content_length && request.content_length != parsed)
            {
                error = RequestErrorCode::duplicate_content_length;
                return;
            }
            request.has_content_length = true;
            request.content_length = parsed;
        }
        else if (equals_ascii_case_insensitive(header.name, "transfer-encoding"))
        {
            error = RequestErrorCode::unsupported_transfer_encoding;
            return;
        }

        request.headers.push_back(std::move(header));
    }

} // namespace

auto request_error_name(RequestErrorCode code) noexcept -> char const*
{
    switch (code)
    {
    case RequestErrorCode::none:
        return "none";
    case RequestErrorCode::malformed_request_line:
        return "malformed_request_line";
    case RequestErrorCode::invalid_method:
        return "invalid_method";
    case RequestErrorCode::invalid_target:
        return "invalid_target";
    case RequestErrorCode::start_line_too_large:
        return "start_line_too_large";
    case RequestErrorCode::headers_too_large:
        return "headers_too_large";
    case RequestErrorCode::too_many_headers:
        return "too_many_headers";
    case RequestErrorCode::duplicate_content_length:
        return "duplicate_content_length";
    case RequestErrorCode::invalid_content_length:
        return "invalid_content_length";
    case RequestErrorCode::body_too_large:
        return "body_too_large";
    case RequestErrorCode::unsupported_transfer_encoding:
        return "unsupported_transfer_encoding";
    }

    return "malformed_request_line";
}

auto request_error_status(RequestErrorCode code) noexcept -> std::uint16_t
{
    switch (code)
    {
    case RequestErrorCode::none:
        return 200U;
    case RequestErrorCode::headers_too_large:
    case RequestErrorCode::too_many_headers:
    case RequestErrorCode::start_line_too_large:
    case RequestErrorCode::body_too_large:
        return 413U;
    case RequestErrorCode::unsupported_transfer_encoding:
        return 501U;
    case RequestErrorCode::malformed_request_line:
    case RequestErrorCode::invalid_method:
    case RequestErrorCode::invalid_target:
    case RequestErrorCode::duplicate_content_length:
    case RequestErrorCode::invalid_content_length:
        return 400U;
    }

    return 400U;
}

auto header_name_is_valid(std::string_view name) noexcept -> bool
{
    if (name.empty())
    {
        return false;
    }

    for (auto const character : name)
    {
        if (!is_tchar(character))
        {
            return false;
        }
    }

    return true;
}

auto header_value_is_valid(std::string_view value) noexcept -> bool
{
    for (auto const character : value)
    {
        auto const byte = static_cast<unsigned char>(character);
        if ((byte < 0x20U && character != '\t') || byte == 0x7FU)
        {
            return false;
        }
    }

    return true;
}

auto parse_request_head(std::string_view input) -> RequestParseResult
{
    auto result = RequestParseResult{};
    auto const limits = RequestLimits{};

    auto const request_line_end = input.find("\r\n");
    if (request_line_end == std::string_view::npos)
    {
        result.error = RequestErrorCode::malformed_request_line;
        return result;
    }
    if (request_line_end > limits.max_start_line_bytes)
    {
        result.error = RequestErrorCode::start_line_too_large;
        return result;
    }

    auto const request_line = input.substr(0U, request_line_end);
    auto const first_space = request_line.find(' ');
    auto const second_space =
        first_space == std::string_view::npos ? std::string_view::npos : request_line.find(' ', first_space + 1U);
    if (first_space == std::string_view::npos || second_space == std::string_view::npos ||
        second_space + 1U >= request_line.size())
    {
        result.error = RequestErrorCode::malformed_request_line;
        return result;
    }

    auto const method = request_line.substr(0U, first_space);
    auto const target = request_line.substr(first_space + 1U, second_space - first_space - 1U);
    auto const version = request_line.substr(second_space + 1U);
    if (version != "HTTP/1.1")
    {
        result.error = RequestErrorCode::malformed_request_line;
        return result;
    }
    if (!method_token_is_valid(method))
    {
        result.error = RequestErrorCode::invalid_method;
        return result;
    }
    if (!request_target_is_valid(target))
    {
        result.error = RequestErrorCode::invalid_target;
        return result;
    }

    result.request.method = std::string{method};
    result.request.target = std::string{target};

    auto remaining = input.substr(request_line_end + 2U);
    auto total_header_bytes = std::size_t{0U};
    while (true)
    {
        auto const line_end = remaining.find("\r\n");
        if (line_end == std::string_view::npos)
        {
            result.error = RequestErrorCode::malformed_request_line;
            return result;
        }
        if (line_end == 0U)
        {
            break;
        }

        total_header_bytes += line_end + 2U;
        if (total_header_bytes > limits.max_header_bytes)
        {
            result.error = RequestErrorCode::headers_too_large;
            return result;
        }
        if (result.request.headers.size() >= limits.max_header_count)
        {
            result.error = RequestErrorCode::too_many_headers;
            return result;
        }

        auto const line = remaining.substr(0U, line_end);
        auto const separator = line.find(':');
        if (separator == std::string_view::npos)
        {
            result.error = RequestErrorCode::malformed_request_line;
            return result;
        }

        auto const name = line.substr(0U, separator);
        auto const value = trim_optional_whitespace(line.substr(separator + 1U));
        if (!header_name_is_valid(name) || !header_value_is_valid(value))
        {
            result.error = RequestErrorCode::malformed_request_line;
            return result;
        }

        auto error = RequestErrorCode::none;
        append_header_or_error(result.request, Header{std::string{name}, std::string{value}}, error);
        if (error != RequestErrorCode::none)
        {
            result.error = error;
            return result;
        }

        remaining = remaining.substr(line_end + 2U);
    }

    if (result.request.content_length > limits.max_body_bytes)
    {
        result.error = RequestErrorCode::body_too_large;
    }

    return result;
}

} // namespace merovingian::http
