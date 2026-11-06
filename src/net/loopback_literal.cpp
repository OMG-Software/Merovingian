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
            return std::memcmp(&v6, &in6addr_loopback, sizeof(v6)) == 0;
        }
        return false;
    }
    catch (...)
    {
        return false;
    }
}

} // namespace merovingian::net
