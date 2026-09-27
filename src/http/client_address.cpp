// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/http/client_address.hpp"

#include <tuple>

namespace merovingian::http
{

auto client_address_key(std::string_view address, std::uint8_t ipv6_prefix_length) -> std::string
{
    std::ignore = ipv6_prefix_length;
    return std::string{address};
}

} // namespace merovingian::http
