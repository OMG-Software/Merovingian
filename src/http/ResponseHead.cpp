// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/ResponseHead.hpp"

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/http/Request.hpp"

#include <array>

namespace merovingian::http
{

namespace
{

    // Framing belongs to the transport: a handler's copy would be a second, contradicting line (response splitting
    // toward a proxy that believes the first).
    constexpr auto transport_framing_headers = std::array<std::string_view, 4U>{
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Keep-Alive",
    };

    [[nodiscard]] auto refused(char const* reason) -> core::Error
    {
        return core::Error{core::ErrorCode::invalid_argument, reason};
    }

} // namespace

auto reason_phrase(std::uint16_t status) noexcept -> std::string_view
{
    switch (status)
    {
    case 200U:
        return "OK";
    case 201U:
        return "Created";
    case 202U:
        return "Accepted";
    case 302U:
        return "Found";
    case 303U:
        return "See Other";
    case 400U:
        return "Bad Request";
    case 401U:
        return "Unauthorized";
    case 403U:
        return "Forbidden";
    case 404U:
        return "Not Found";
    case 405U:
        return "Method Not Allowed";
    case 408U:
        return "Request Timeout";
    case 409U:
        return "Conflict";
    case 413U:
        return "Payload Too Large";
    case 415U:
        return "Unsupported Media Type";
    case 429U:
        return "Too Many Requests";
    case 451U:
        return "Unavailable For Legal Reasons";
    case 500U:
        return "Internal Server Error";
    case 501U:
        return "Not Implemented";
    case 502U:
        return "Bad Gateway";
    case 503U:
        return "Service Unavailable";
    case 504U:
        return "Gateway Timeout";
    case 507U:
        return "Insufficient Storage";
    default:
        return "";
    }
}

auto format_response_head(std::uint16_t status, std::uint64_t body_length,
                          std::vector<std::pair<std::string, std::string>> const& headers,
                          ConnectionPreference connection, std::uint32_t keep_alive_timeout_seconds)
    -> std::variant<std::string, core::Error>
{
    if (status < 200U || status > 599U)
    {
        return refused("response status is outside 200-599");
    }
    auto response = std::string{};
    response.reserve(128U + 256U * headers.size());
    response.append("HTTP/1.1 ");
    response.append(std::to_string(status));
    response.push_back(' ');
    response.append(reason_phrase(status));
    // Per-response headers (CORS, Vary: Origin, a page's security headers) come first, in the handler's order.
    auto has_nosniff = false;
    auto has_content_type = false;
    auto content_type = std::string_view{};
    for (auto const& [name, value] : headers)
    {
        if (!header_name_is_valid(name) || !header_value_is_valid(value))
        {
            return refused("response header name or value is not valid");
        }
        for (auto const framing : transport_framing_headers)
        {
            if (header_names_equal(name, framing))
            {
                return refused("response header frames the message, which only the transport may do");
            }
        }
        if (header_names_equal(name, "X-Content-Type-Options"))
        {
            if (has_nosniff || !header_names_equal(value, "nosniff"))
            {
                return refused("response X-Content-Type-Options is repeated or is not nosniff");
            }
            has_nosniff = true;
        }
        if (header_names_equal(name, "Content-Type"))
        {
            if (has_content_type)
            {
                return refused("response has more than one Content-Type");
            }
            has_content_type = true;
            content_type = value;
            continue;
        }
        response.append("\r\n");
        response.append(name);
        response.append(": ");
        response.append(value);
    }
    if (!has_nosniff)
    {
        response.append("\r\nX-Content-Type-Options: nosniff");
    }
    response.append("\r\nContent-Length: ");
    response.append(std::to_string(body_length));
    response.append("\r\nContent-Type: ");
    response.append(content_type.empty() ? std::string_view{"application/json"} : content_type);
    if (connection == ConnectionPreference::keep_alive)
    {
        response.append("\r\nConnection: keep-alive");
        // Hint, not a promise: the server still closes early when the parked-connection cap is reached or shutdown
        // begins.
        response.append("\r\nKeep-Alive: timeout=");
        response.append(std::to_string(keep_alive_timeout_seconds));
    }
    else
    {
        response.append("\r\nConnection: close");
    }
    response.append("\r\n\r\n");
    return response;
}

auto format_response(std::uint16_t status, std::string_view body,
                     std::vector<std::pair<std::string, std::string>> const& headers, ConnectionPreference connection,
                     std::uint32_t keep_alive_timeout_seconds) -> std::variant<std::string, core::Error>
{
    auto head = format_response_head(status, body.size(), headers, connection, keep_alive_timeout_seconds);
    if (auto* text = std::get_if<std::string>(&head))
    {
        text->append(body);
    }
    return head;
}

} // namespace merovingian::http
