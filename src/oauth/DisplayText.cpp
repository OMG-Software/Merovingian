// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/DisplayText.hpp"

#include "merovingian/core/Utf8.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace merovingian::oauth
{
namespace
{

    // Inclusive code point ranges a displayed name may not hold. See DisplayText.hpp for what each is.
    constexpr auto refused_ranges = std::array<std::pair<std::uint32_t, std::uint32_t>, 14>{
        {
         {0x0000U, 0x001FU},   // C0 controls
            {0x007FU, 0x009FU},   // DEL and the C1 controls
            {0x00ADU, 0x00ADU},   // soft hyphen
            {0x061CU, 0x061CU},   // ARABIC LETTER MARK
            {0x180EU, 0x180EU},   // MONGOLIAN VOWEL SEPARATOR
            {0x200BU, 0x200DU},   // zero width space, non-joiner, joiner
            {0x200EU, 0x200FU},   // LEFT-TO-RIGHT MARK, RIGHT-TO-LEFT MARK
            {0x2028U, 0x2029U},   // line and paragraph separators
            {0x202AU, 0x202EU},   // bidirectional embeddings and overrides
            {0x2060U, 0x2064U},   // word joiner and the invisible operators
            {0x2066U, 0x2069U},   // bidirectional isolates
            {0xFEFFU, 0xFEFFU},   // zero width no-break space (byte order mark)
            {0xFFF9U, 0xFFFBU},   // interlinear annotation characters
            {0xE0000U, 0xE007FU}, // tag characters
        }
    };

    [[nodiscard]] auto is_refused(std::uint32_t code_point) noexcept -> bool
    {
        for (auto const& [first, last] : refused_ranges)
        {
            if (code_point >= first && code_point <= last)
            {
                return true;
            }
        }
        return false;
    }

} // namespace

auto display_text_is_safe(std::string_view text) noexcept -> bool
{
    if (!core::utf8_is_valid(text))
    {
        return false;
    }
    // The text is valid UTF-8 here, so a lead byte is always followed by its continuation bytes.
    constexpr auto continuation_bits = 6U;
    constexpr auto continuation_mask = 0x3FU;
    auto index = std::size_t{0U};
    while (index < text.size())
    {
        auto const lead = static_cast<unsigned char>(text[index]);
        auto length = std::size_t{1U};
        auto code_point = static_cast<std::uint32_t>(lead);
        if (lead >= 0xF0U)
        {
            length = 4U;
            code_point = lead & 0x07U;
        }
        else if (lead >= 0xE0U)
        {
            length = 3U;
            code_point = lead & 0x0FU;
        }
        else if (lead >= 0xC0U)
        {
            length = 2U;
            code_point = lead & 0x1FU;
        }
        for (auto offset = std::size_t{1U}; offset < length; ++offset)
        {
            code_point = (code_point << continuation_bits) |
                         (static_cast<unsigned char>(text[index + offset]) & continuation_mask);
        }
        if (is_refused(code_point))
        {
            return false;
        }
        index += length;
    }
    return true;
}

} // namespace merovingian::oauth
