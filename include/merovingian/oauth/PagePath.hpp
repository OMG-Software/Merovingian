// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::oauth
{

// A path on this server that a page form posts to, fixed at compile time: `/` followed by `A-Z a-z 0-9 / _ - .`,
// no `//` and no `..`, so it can never name another origin or carry a query. The constructor is consteval: anything
// else does not compile (ADR-0772).
class PagePath final
{
public:
    // Implicit on purpose: a literal converts where page text is wanted.
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    consteval PagePath(char const* text)
        : m_text{text}
    {
        if (!m_text.starts_with('/') || m_text.find("//") != std::string_view::npos ||
            m_text.find("..") != std::string_view::npos)
        {
            throw "a PagePath must start with one / and hold no // or ..";
        }
        for (auto const value : m_text)
        {
            auto const allowed = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
                                 (value >= '0' && value <= '9') || value == '/' || value == '_' || value == '-' ||
                                 value == '.';
            if (!allowed)
            {
                throw "a PagePath holds a character outside A-Z a-z 0-9 / _ - .";
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
