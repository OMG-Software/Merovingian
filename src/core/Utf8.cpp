// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/Utf8.hpp"

#include <cstddef>
#include <cstdint>

namespace merovingian::core
{

auto utf8_is_valid(std::string_view value) noexcept -> bool
{
    auto index = std::size_t{0U};
    while (index < value.size())
    {
        auto const first = static_cast<unsigned char>(value[index]);
        if (first <= 0x7FU)
        {
            ++index;
            continue;
        }

        auto length = std::size_t{0U};
        auto min_codepoint = std::uint32_t{0U};
        auto codepoint = std::uint32_t{0U};
        if ((first & 0xE0U) == 0xC0U)
        {
            length = 2U;
            min_codepoint = 0x80U;
            codepoint = first & 0x1FU;
        }
        else if ((first & 0xF0U) == 0xE0U)
        {
            length = 3U;
            min_codepoint = 0x800U;
            codepoint = first & 0x0FU;
        }
        else if ((first & 0xF8U) == 0xF0U)
        {
            length = 4U;
            min_codepoint = 0x10000U;
            codepoint = first & 0x07U;
        }
        else
        {
            return false;
        }

        if (index + length > value.size())
        {
            return false;
        }
        for (auto offset = std::size_t{1U}; offset < length; ++offset)
        {
            auto const next = static_cast<unsigned char>(value[index + offset]);
            if ((next & 0xC0U) != 0x80U)
            {
                return false;
            }
            codepoint = (codepoint << 6U) | (next & 0x3FU);
        }
        if (codepoint < min_codepoint || codepoint > 0x10FFFFU || (codepoint >= 0xD800U && codepoint <= 0xDFFFU))
        {
            return false;
        }
        index += length;
    }

    return true;
}

} // namespace merovingian::core
