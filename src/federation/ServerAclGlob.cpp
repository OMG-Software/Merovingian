// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/ServerAclGlob.hpp"

#include <cctype>
#include <cstddef>
#include <optional>
#include <string_view>

namespace merovingian::federation
{
namespace
{

    [[nodiscard]] auto to_lower_ascii(char character) noexcept -> char
    {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }

} // namespace

auto server_acl_glob_match(std::string_view pattern, std::string_view text, std::size_t& steps_left) noexcept
    -> std::optional<bool>
{
    auto const pattern_length = pattern.size();
    auto const text_length = text.size();
    auto pattern_index = std::size_t{0U};
    auto text_index = std::size_t{0U};
    auto star_pattern = std::string_view::npos;
    auto star_text = std::size_t{0U};

    while (text_index < text_length)
    {
        if (steps_left == 0U)
        {
            return std::nullopt;
        }
        --steps_left;

        if (pattern_index < pattern_length && pattern[pattern_index] == '*')
        {
            star_pattern = pattern_index;
            star_text = text_index;
            ++pattern_index;
        }
        else if (pattern_index < pattern_length &&
                 (pattern[pattern_index] == '?' ||
                  to_lower_ascii(pattern[pattern_index]) == to_lower_ascii(text[text_index])))
        {
            ++pattern_index;
            ++text_index;
        }
        else if (star_pattern != std::string_view::npos)
        {
            // Let the last '*' absorb one more character and retry what follows it.
            pattern_index = star_pattern + 1U;
            ++star_text;
            text_index = star_text;
        }
        else
        {
            return false;
        }
    }

    while (pattern_index < pattern_length && pattern[pattern_index] == '*')
    {
        if (steps_left == 0U)
        {
            return std::nullopt;
        }
        --steps_left;
        ++pattern_index;
    }
    return pattern_index == pattern_length;
}

} // namespace merovingian::federation
