// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/AsciiCase.hpp"

namespace merovingian::oauth
{

auto ascii_lower(std::string_view text) -> std::string
{
    auto lower = std::string{text};
    for (auto& value : lower)
    {
        if (value >= 'A' && value <= 'Z')
        {
            value = static_cast<char>(value - 'A' + 'a');
        }
    }
    return lower;
}

} // namespace merovingian::oauth
