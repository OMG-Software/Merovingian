// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/http/client_address.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace merovingian::http
{

namespace
{

    [[nodiscard]] auto ipv4_text(in_addr const& address) -> std::string
    {
        auto buffer = std::array<char, INET_ADDRSTRLEN>{};
        if (::inet_ntop(AF_INET, &address, buffer.data(), static_cast<socklen_t>(buffer.size())) == nullptr)
        {
            return {};
        }
        return std::string{buffer.data()};
    }

} // namespace

auto client_address_key(std::string_view address, std::uint8_t ipv6_prefix_length) -> std::string
{
    // inet_pton needs a NUL-terminated string.
    auto const text = std::string{address};

    auto ipv4 = in_addr{};
    if (::inet_pton(AF_INET, text.c_str(), &ipv4) == 1)
    {
        auto const canonical = ipv4_text(ipv4);
        return canonical.empty() ? text : canonical;
    }

    auto ipv6 = in6_addr{};
    if (::inet_pton(AF_INET6, text.c_str(), &ipv6) != 1)
    {
        return text;
    }

    if (IN6_IS_ADDR_V4MAPPED(&ipv6))
    {
        auto mapped = in_addr{};
        std::memcpy(&mapped, &ipv6.s6_addr[12], sizeof(mapped));
        auto const canonical = ipv4_text(mapped);
        return canonical.empty() ? text : canonical;
    }

    auto const prefix = static_cast<unsigned>(std::clamp<unsigned>(ipv6_prefix_length, 1U, 128U));
    auto network = in6_addr{};
    for (auto byte = 0U; byte < 16U; ++byte)
    {
        auto const bits_before = byte * 8U;
        auto const mask = [&]() -> unsigned {
            if (bits_before + 8U <= prefix)
            {
                return 0xFFU;
            }
            if (bits_before >= prefix)
            {
                return 0x00U;
            }
            return (0xFFU << (8U - (prefix - bits_before))) & 0xFFU;
        }();
        network.s6_addr[byte] = static_cast<std::uint8_t>(ipv6.s6_addr[byte] & mask);
    }

    auto buffer = std::array<char, INET6_ADDRSTRLEN>{};
    if (::inet_ntop(AF_INET6, &network, buffer.data(), static_cast<socklen_t>(buffer.size())) == nullptr)
    {
        return text;
    }
    return std::string{buffer.data()} + "/" + std::to_string(prefix);
}

} // namespace merovingian::http
