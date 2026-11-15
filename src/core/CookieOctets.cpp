// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/CookieOctets.hpp"

#include <algorithm>

namespace merovingian::core
{

auto cookie_octets_are_valid(std::string_view value) noexcept -> bool
{
    return std::ranges::all_of(value, [](char character) {
        auto const byte = static_cast<unsigned char>(character);
        return byte == 0x21U || (byte >= 0x23U && byte <= 0x2BU) || (byte >= 0x2DU && byte <= 0x3AU) ||
               (byte >= 0x3CU && byte <= 0x5BU) || (byte >= 0x5DU && byte <= 0x7EU);
    });
}

} // namespace merovingian::core
