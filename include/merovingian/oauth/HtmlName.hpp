// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <stdexcept>
#include <string_view>

namespace merovingian::oauth
{

// A form control name, button value or `autocomplete` token fixed at compile time: 1 to 64 characters of
// `A-Z a-z 0-9 _ -`. The constructor is consteval, so a name that breaks the rule, or is not a constant expression,
// does not compile (ADR-0772). It is also used to build an element `id`, so it never needs escaping.
class HtmlName final
{
public:
    static constexpr std::size_t max_chars = 64U;

    // Implicit on purpose: a literal converts where page text is wanted.
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    consteval HtmlName(char const* text)
        : m_text{text}
    {
        if (m_text.empty() || m_text.size() > max_chars)
        {
            throw std::logic_error{"an HtmlName must be 1 to 64 characters"};
        }
        for (auto const value : m_text)
        {
            auto const allowed = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
                                 (value >= '0' && value <= '9') || value == '_' || value == '-';
            if (!allowed)
            {
                throw std::logic_error{"an HtmlName holds a character outside A-Z a-z 0-9 _ -"};
            }
        }
    }

    [[nodiscard]] constexpr auto view() const noexcept -> std::string_view
    {
        return m_text;
    }

private:
    std::string_view m_text;
};

} // namespace merovingian::oauth
