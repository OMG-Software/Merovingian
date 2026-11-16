// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/DisplayText.hpp"

#include "merovingian/core/Utf8.hpp"

#include <cstddef>

namespace merovingian::oauth
{

auto display_text_is_safe(std::string_view text) noexcept -> bool
{
    if (!core::utf8_is_valid(text))
    {
        return false;
    }
    // The text is valid UTF-8 here, so a lead byte is always followed by its continuation bytes.
    for (auto index = std::size_t{0U}; index < text.size(); ++index)
    {
        auto const byte = static_cast<unsigned char>(text[index]);
        if (byte < 0x20U || byte == 0x7FU)
        {
            return false;
        }
        if (byte == 0xC2U)
        {
            // U+0080..U+009F: C2 80..C2 9F.
            auto const next = static_cast<unsigned char>(text[index + 1U]);
            if (next >= 0x80U && next <= 0x9FU)
            {
                return false;
            }
        }
        else if (byte == 0xD8U)
        {
            // U+061C ARABIC LETTER MARK: D8 9C.
            if (static_cast<unsigned char>(text[index + 1U]) == 0x9CU)
            {
                return false;
            }
        }
        else if (byte == 0xE2U)
        {
            auto const second = static_cast<unsigned char>(text[index + 1U]);
            auto const third = static_cast<unsigned char>(text[index + 2U]);
            // U+200E, U+200F: E2 80 8E/8F. U+2028..U+202E: E2 80 A8..AE. U+2066..U+2069: E2 81 A6..A9.
            if (second == 0x80U && (third == 0x8EU || third == 0x8FU || (third >= 0xA8U && third <= 0xAEU)))
            {
                return false;
            }
            if (second == 0x81U && third >= 0xA6U && third <= 0xA9U)
            {
                return false;
            }
        }
    }
    return true;
}

} // namespace merovingian::oauth
