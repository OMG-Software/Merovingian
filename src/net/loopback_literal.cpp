// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/net/loopback_literal.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <cstring>
#include <string>
#include <string_view>

namespace merovingian::net
{

auto is_loopback_ip_literal(std::string_view host) noexcept -> bool
{
    try
    {
        if (host.size() >= 2U && host.front() == '[' && host.back() == ']')
        {
            host = host.substr(1U, host.size() - 2U);
        }
        if (host.empty() || host.find('\0') != std::string_view::npos)
        {
            return false;
        }
        auto const text = std::string{host};

        auto v4 = ::in_addr{};
        if (::inet_pton(AF_INET, text.c_str(), &v4) == 1)
        {
            auto bytes = std::array<unsigned char, sizeof(v4)>{};
            std::memcpy(bytes.data(), &v4, bytes.size());
            constexpr auto loopback_first_octet = static_cast<unsigned char>(127U);
            return bytes.front() == loopback_first_octet;
        }

        auto v6 = ::in6_addr{};
        if (::inet_pton(AF_INET6, text.c_str(), &v6) == 1)
        {
            // ::1 as bytes. Compared as a byte array, not with memcmp over the struct, whose padding and
            // members the standard leaves to the platform.
            constexpr auto loopback_v6 =
                std::array<unsigned char, 16U>{0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};
            static_assert(sizeof(v6) == loopback_v6.size());
            auto bytes = std::array<unsigned char, sizeof(v6)>{};
            std::memcpy(bytes.data(), &v6, bytes.size());
            return bytes == loopback_v6;
        }
        return false;
    }
    catch (...)
    {
        return false;
    }
}

} // namespace merovingian::net
