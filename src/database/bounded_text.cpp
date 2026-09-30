// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/bounded_text.hpp"

#include <cstdint>

namespace merovingian::database
{

namespace
{

    constexpr auto replacement_character = std::string_view{"\xEF\xBF\xBD"}; // U+FFFD

    // Length in bytes of the well-formed UTF-8 character at the start of
    // `text`, or 0 when the bytes there are not a valid, non-control character.
    [[nodiscard]] auto valid_character_length(std::string_view text) noexcept -> std::size_t
    {
        auto const first = static_cast<unsigned char>(text.front());
        if (first < 0x80U)
        {
            return (first < 0x20U || first == 0x7FU) ? 0U : 1U;
        }

        auto length = std::size_t{0U};
        auto codepoint = std::uint32_t{0U};
        auto minimum = std::uint32_t{0U};
        if ((first & 0xE0U) == 0xC0U)
        {
            length = 2U;
            codepoint = first & 0x1FU;
            minimum = 0x80U;
        }
        else if ((first & 0xF0U) == 0xE0U)
        {
            length = 3U;
            codepoint = first & 0x0FU;
            minimum = 0x800U;
        }
        else if ((first & 0xF8U) == 0xF0U)
        {
            length = 4U;
            codepoint = first & 0x07U;
            minimum = 0x10000U;
        }
        else
        {
            return 0U;
        }
        if (text.size() < length)
        {
            return 0U;
        }
        for (auto offset = std::size_t{1U}; offset < length; ++offset)
        {
            auto const next = static_cast<unsigned char>(text[offset]);
            if ((next & 0xC0U) != 0x80U)
            {
                return 0U;
            }
            codepoint = (codepoint << 6U) | (next & 0x3FU);
        }
        auto const overlong = codepoint < minimum;
        auto const surrogate = codepoint >= 0xD800U && codepoint <= 0xDFFFU;
        auto const out_of_range = codepoint > 0x10FFFFU;
        return (overlong || surrogate || out_of_range) ? 0U : length;
    }

} // namespace

auto bounded_utf8(std::string_view value, std::size_t max_bytes) -> std::string
{
    auto output = std::string{};
    output.reserve(value.size() < max_bytes ? value.size() : max_bytes);
    auto index = std::size_t{0U};
    while (index < value.size() && output.size() < max_bytes)
    {
        auto const remaining = value.substr(index);
        auto const length = valid_character_length(remaining);
        auto const piece = length == 0U ? replacement_character : remaining.substr(0U, length);
        if (output.size() + piece.size() > max_bytes)
        {
            break;
        }
        output.append(piece);
        // An invalid byte is consumed one at a time so that the bytes after it
        // are still examined on their own.
        index += length == 0U ? 1U : length;
    }
    return output;
}

} // namespace merovingian::database
