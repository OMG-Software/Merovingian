// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/HtmlText.hpp"

#include "merovingian/oauth/DisplayText.hpp"

#include <utility>

namespace merovingian::oauth
{

HtmlText::HtmlText(HtmlLiteral literal)
    : m_html{literal.view()}
{
}

HtmlText::HtmlText(std::in_place_t /*tag*/, std::string html)
    : m_html{std::move(html)}
{
}

auto HtmlText::escape(std::string_view text) -> std::optional<HtmlText>
{
    if (text.empty() || text.size() > max_text_bytes || !display_text_is_safe(text))
    {
        return std::nullopt;
    }
    auto html = std::string{};
    html.reserve(text.size());
    for (auto const value : text)
    {
        switch (value)
        {
        case '&':
            html.append("&amp;");
            break;
        case '<':
            html.append("&lt;");
            break;
        case '>':
            html.append("&gt;");
            break;
        case '"':
            html.append("&quot;");
            break;
        case '\'':
            html.append("&#39;");
            break;
        default:
            html.push_back(value);
            break;
        }
    }
    return HtmlText{std::in_place, std::move(html)};
}

auto HtmlText::html() const noexcept -> std::string const&
{
    return m_html;
}

} // namespace merovingian::oauth
