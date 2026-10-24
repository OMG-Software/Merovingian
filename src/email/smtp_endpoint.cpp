// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/email/smtp_endpoint.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace merovingian::email
{

namespace
{

    constexpr auto implicit_tls_port = std::uint16_t{465U};
    constexpr auto submission_port = std::uint16_t{587U};

    [[nodiscard]] auto to_lower_ascii(std::string_view text) -> std::string
    {
        auto lowered = std::string{text};
        std::ranges::transform(lowered, lowered.begin(), [](char byte) {
            return (byte >= 'A' && byte <= 'Z') ? static_cast<char>(byte - 'A' + 'a') : byte;
        });
        return lowered;
    }

    // Bytes that may appear anywhere in host[:port]: printable ASCII except the delimiters of the
    // URL parts this parser refuses, and except percent-encoding.
    [[nodiscard]] auto authority_byte_is_allowed(char byte) noexcept -> bool
    {
        auto const value = static_cast<unsigned char>(byte);
        if (value <= 0x20U || value >= 0x7FU)
        {
            return false;
        }
        constexpr auto refused = std::string_view{"/?#@%\\"};
        return refused.find(byte) == std::string_view::npos;
    }

    [[nodiscard]] auto is_host_name(std::string_view host) noexcept -> bool
    {
        if (host.empty() || host.front() == '.' || host.back() == '.' || host.front() == '-' ||
            host.find("..") != std::string_view::npos)
        {
            return false;
        }
        return std::ranges::all_of(host, [](char byte) {
            return (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '-' || byte == '.';
        });
    }

    [[nodiscard]] auto parse_port(std::string_view digits) noexcept -> std::optional<std::uint16_t>
    {
        constexpr auto max_port_digits = std::size_t{5U};
        constexpr auto max_port = std::uint32_t{65535U};
        if (digits.empty() || digits.size() > max_port_digits)
        {
            return std::nullopt;
        }
        auto value = std::uint32_t{0U};
        for (auto const byte : digits)
        {
            if (byte < '0' || byte > '9')
            {
                return std::nullopt;
            }
            value = value * 10U + static_cast<std::uint32_t>(byte - '0');
        }
        if (value == 0U || value > max_port)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(value);
    }

    [[nodiscard]] auto ipv4_is_loopback(std::string const& host) noexcept -> bool
    {
        auto address = ::in_addr{};
        if (::inet_pton(AF_INET, host.c_str(), &address) != 1)
        {
            return false;
        }
        auto bytes = std::array<unsigned char, sizeof(address)>{};
        std::memcpy(bytes.data(), &address, bytes.size());
        constexpr auto loopback_first_octet = static_cast<unsigned char>(127U);
        return bytes.front() == loopback_first_octet;
    }

} // namespace

auto parse_smtp_url(std::string_view url) -> std::optional<SmtpEndpoint>
{
    auto const separator = url.find("://");
    if (separator == std::string_view::npos)
    {
        return std::nullopt;
    }
    auto endpoint = SmtpEndpoint{};
    auto const scheme = to_lower_ascii(url.substr(0U, separator));
    if (scheme == "smtps")
    {
        endpoint.implicit_tls = true;
    }
    else if (scheme != "smtp")
    {
        return std::nullopt;
    }

    auto authority = url.substr(separator + 3U);
    if (!authority.empty() && authority.back() == '/')
    {
        authority.remove_suffix(1U);
    }
    if (authority.empty() || !std::ranges::all_of(authority, authority_byte_is_allowed))
    {
        return std::nullopt;
    }

    auto port_text = std::optional<std::string_view>{};
    if (authority.front() == '[')
    {
        auto const close = authority.find(']');
        if (close == std::string_view::npos)
        {
            return std::nullopt;
        }
        auto const literal = std::string{authority.substr(1U, close - 1U)};
        auto address = ::in6_addr{};
        if (::inet_pton(AF_INET6, literal.c_str(), &address) != 1)
        {
            return std::nullopt;
        }
        endpoint.host = to_lower_ascii(authority.substr(0U, close + 1U));
        endpoint.loopback_literal = std::memcmp(&address, &in6addr_loopback, sizeof(address)) == 0;
        auto const rest = authority.substr(close + 1U);
        if (!rest.empty())
        {
            if (rest.front() != ':')
            {
                return std::nullopt;
            }
            port_text = rest.substr(1U);
        }
    }
    else
    {
        auto const colon = authority.find(':');
        endpoint.host = to_lower_ascii(authority.substr(0U, colon));
        if (!is_host_name(endpoint.host))
        {
            return std::nullopt;
        }
        endpoint.loopback_literal = ipv4_is_loopback(endpoint.host);
        if (colon != std::string_view::npos)
        {
            port_text = authority.substr(colon + 1U);
        }
    }

    if (port_text.has_value())
    {
        auto const port = parse_port(*port_text);
        if (!port.has_value())
        {
            return std::nullopt;
        }
        endpoint.port = *port;
    }
    else
    {
        endpoint.port = endpoint.implicit_tls ? implicit_tls_port : submission_port;
    }
    return endpoint;
}

} // namespace merovingian::email
