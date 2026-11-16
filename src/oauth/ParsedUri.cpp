// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/ParsedUri.hpp"

#include "merovingian/core/ErrorCode.hpp"

#include <algorithm>

namespace merovingian::oauth
{
namespace
{

    constexpr auto max_host_bytes = std::size_t{253U};
    constexpr auto max_label_bytes = std::size_t{63U};
    // `[` + the longest IPv6 text form (45: eight groups with an embedded IPv4) + `]`.
    constexpr auto max_ipv6_literal_bytes = std::size_t{47U};

    [[nodiscard]] auto parse_error(char const* message) -> core::Error
    {
        return core::Error{core::ErrorCode::parse_failure, message};
    }

    [[nodiscard]] auto is_alpha(char value) noexcept -> bool
    {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
    }

    [[nodiscard]] auto is_digit(char value) noexcept -> bool
    {
        return value >= '0' && value <= '9';
    }

    [[nodiscard]] auto is_hex_digit(char value) noexcept -> bool
    {
        return is_digit(value) || (value >= 'A' && value <= 'F') || (value >= 'a' && value <= 'f');
    }

    [[nodiscard]] auto is_scheme_char(char value) noexcept -> bool
    {
        return is_alpha(value) || is_digit(value) || value == '+' || value == '-' || value == '.';
    }

    // RFC 3986 unreserved / sub-delims / ":" / "@": pchar without the percent escape.
    [[nodiscard]] auto is_pchar_literal(char value) noexcept -> bool
    {
        constexpr auto others = std::string_view{"-._~!$&'()*+,;=:@"};
        return is_alpha(value) || is_digit(value) || others.find(value) != std::string_view::npos;
    }

    // Path (`extra` = "/") or query (`extra` = "/?") characters, with `%XX` escapes checked.
    [[nodiscard]] auto component_is_valid(std::string_view component, std::string_view extra) noexcept -> bool
    {
        for (auto index = std::size_t{0U}; index < component.size(); ++index)
        {
            auto const value = component[index];
            if (value == '%')
            {
                if (index + 2U >= component.size() || !is_hex_digit(component[index + 1U]) ||
                    !is_hex_digit(component[index + 2U]))
                {
                    return false;
                }
                index += 2U;
                continue;
            }
            if (!is_pchar_literal(value) && extra.find(value) == std::string_view::npos)
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto label_is_valid(std::string_view label) noexcept -> bool
    {
        return !label.empty() && label.size() <= max_label_bytes && label.front() != '-' && label.back() != '-' &&
               std::ranges::all_of(label, [](char value) noexcept {
                   return is_alpha(value) || is_digit(value) || value == '-';
               });
    }

    [[nodiscard]] auto reg_name_is_valid(std::string_view host) noexcept -> bool
    {
        if (host.empty() || host.size() > max_host_bytes)
        {
            return false;
        }
        auto rest = host;
        while (true)
        {
            auto const dot = rest.find('.');
            if (!label_is_valid(rest.substr(0U, dot)))
            {
                return false;
            }
            if (dot == std::string_view::npos)
            {
                return true;
            }
            rest = rest.substr(dot + 1U);
        }
    }

    [[nodiscard]] auto ipv6_literal_is_valid(std::string_view host) noexcept -> bool
    {
        if (host.size() < 4U || host.size() > max_ipv6_literal_bytes || host.front() != '[' || host.back() != ']')
        {
            return false;
        }
        auto const inner = host.substr(1U, host.size() - 2U);
        return inner.find(':') != std::string_view::npos && std::ranges::all_of(inner, [](char value) noexcept {
                   return is_hex_digit(value) || value == ':' || value == '.';
               });
    }

    // 1 to 5 digits, no leading zero, 1..65535.
    [[nodiscard]] auto parse_port(std::string_view digits) noexcept -> std::optional<std::uint16_t>
    {
        if (digits.empty() || digits.size() > 5U || digits.front() == '0' || !std::ranges::all_of(digits, is_digit))
        {
            return std::nullopt;
        }
        auto value = std::uint32_t{0U};
        for (auto const digit : digits)
        {
            value = value * 10U + static_cast<std::uint32_t>(digit - '0');
        }
        if (value > 65535U)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(value);
    }

} // namespace

auto ParsedUri::read(std::string_view text) -> std::variant<ParsedUri, core::Error>
{
    if (text.size() > max_uri_bytes)
    {
        return core::Error{core::ErrorCode::invalid_argument, "The URI is too long."};
    }
    if (text.empty())
    {
        return parse_error("The URI is empty.");
    }
    if (!std::ranges::all_of(text, [](char value) noexcept {
            auto const byte = static_cast<unsigned char>(value);
            return byte >= 0x21U && byte <= 0x7EU;
        }))
    {
        return parse_error("The URI holds a byte outside printable ASCII.");
    }
    if (text.find('#') != std::string_view::npos)
    {
        return parse_error("The URI has a fragment.");
    }

    auto const colon = text.find(':');
    if (colon == std::string_view::npos || colon == 0U)
    {
        return parse_error("The URI has no scheme.");
    }
    auto const scheme = text.substr(0U, colon);
    if (scheme.size() > max_scheme_bytes)
    {
        return core::Error{core::ErrorCode::invalid_argument, "The URI scheme is too long."};
    }
    if (!is_alpha(scheme.front()) || !std::ranges::all_of(scheme, is_scheme_char))
    {
        return parse_error("The URI scheme is malformed.");
    }

    auto uri = ParsedUri{};
    uri.m_text = std::string{text};
    uri.m_scheme = std::string{scheme};

    auto rest = text.substr(colon + 1U);
    if (rest.starts_with("//"))
    {
        rest.remove_prefix(2U);
        auto const authority_end = rest.find_first_of("/?");
        auto const authority = rest.substr(0U, authority_end);
        rest = authority_end == std::string_view::npos ? std::string_view{} : rest.substr(authority_end);
        if (authority.find('@') != std::string_view::npos)
        {
            return parse_error("The URI has userinfo.");
        }

        auto host = std::string_view{};
        auto port_text = std::optional<std::string_view>{};
        if (authority.starts_with('['))
        {
            auto const close = authority.find(']');
            if (close == std::string_view::npos)
            {
                return parse_error("The URI host is malformed.");
            }
            host = authority.substr(0U, close + 1U);
            auto const after = authority.substr(close + 1U);
            if (!after.empty())
            {
                if (after.front() != ':')
                {
                    return parse_error("The URI host is malformed.");
                }
                port_text = after.substr(1U);
            }
            if (!ipv6_literal_is_valid(host))
            {
                return parse_error("The URI host is malformed.");
            }
        }
        else
        {
            auto const port_colon = authority.find(':');
            host = authority.substr(0U, port_colon);
            if (port_colon != std::string_view::npos)
            {
                port_text = authority.substr(port_colon + 1U);
            }
            if (!reg_name_is_valid(host))
            {
                return parse_error("The URI host is malformed.");
            }
        }
        if (port_text.has_value())
        {
            auto const port = parse_port(*port_text);
            if (!port.has_value())
            {
                return parse_error("The URI port is malformed.");
            }
            uri.m_port = port;
        }
        uri.m_has_authority = true;
        uri.m_host = std::string{host};
    }

    auto const question = rest.find('?');
    auto const path = rest.substr(0U, question);
    if (!component_is_valid(path, "/"))
    {
        return parse_error("The URI path holds a character it cannot.");
    }
    uri.m_path = std::string{path};
    if (question != std::string_view::npos)
    {
        auto const query = rest.substr(question + 1U);
        if (!component_is_valid(query, "/?"))
        {
            return parse_error("The URI query holds a character it cannot.");
        }
        uri.m_has_query = true;
        uri.m_query = std::string{query};
    }
    return uri;
}

auto ParsedUri::text() const noexcept -> std::string const&
{
    return m_text;
}

auto ParsedUri::scheme() const noexcept -> std::string const&
{
    return m_scheme;
}

auto ParsedUri::has_authority() const noexcept -> bool
{
    return m_has_authority;
}

auto ParsedUri::host() const noexcept -> std::string const&
{
    return m_host;
}

auto ParsedUri::port() const noexcept -> std::optional<std::uint16_t>
{
    return m_port;
}

auto ParsedUri::path() const noexcept -> std::string const&
{
    return m_path;
}

auto ParsedUri::has_query() const noexcept -> bool
{
    return m_has_query;
}

auto ParsedUri::query() const noexcept -> std::string const&
{
    return m_query;
}

auto ParsedUri::csp_source() const -> std::string
{
    auto source = m_scheme;
    source.push_back(':');
    if (!m_has_authority)
    {
        return source;
    }
    source.append("//");
    source.append(m_host);
    if (m_port.has_value())
    {
        source.push_back(':');
        source.append(std::to_string(*m_port));
    }
    return source;
}

} // namespace merovingian::oauth
