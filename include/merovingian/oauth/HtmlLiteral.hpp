// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::oauth
{

// Page text fixed at compile time: a string literal of printable ASCII (space to `~`) holding none of `& < > " '`,
// so it needs no escaping. The constructor is consteval: a value that is not a constant expression, or that breaks
// the rule, does not compile (ADR-0772). Text known only at run time goes through HtmlText::escape. Clang 18 does not
// apply this in a default member initialiser, where the check runs at run time instead; such initialisers are refused
// by a tooling test (ADR-0800). The same holds for HtmlName and PagePath.
class HtmlLiteral final
{
public:
    // Implicit on purpose: a literal converts where page text is wanted.
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    consteval HtmlLiteral(char const* text)
        : m_text{text}
    {
        if (m_text.empty())
        {
            throw "an HtmlLiteral must not be empty";
        }
        for (auto const value : m_text)
        {
            if (value < ' ' || value > '~' || value == '&' || value == '<' || value == '>' || value == '"' ||
                value == '\'')
            {
                throw "an HtmlLiteral holds a character that would need escaping";
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
