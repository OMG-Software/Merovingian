// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/HttpToken.hpp"

#include <algorithm>

namespace merovingian::core
{

namespace
{

    [[nodiscard]] auto is_token_character(char value) noexcept -> bool
    {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
               value == '!' || value == '#' || value == '$' || value == '%' || value == '&' || value == '\'' ||
               value == '*' || value == '+' || value == '-' || value == '.' || value == '^' || value == '_' ||
               value == '`' || value == '|' || value == '~';
    }

} // namespace

auto http_token_is_valid(std::string_view text) noexcept -> bool
{
    return !text.empty() && std::ranges::all_of(text, is_token_character);
}

} // namespace merovingian::core
