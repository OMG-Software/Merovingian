// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/Page.hpp"

#include "merovingian/oauth/PageHeaders.hpp"
#include "merovingian/oauth/ParsedUri.hpp"

#include <utility>
#include <variant>

namespace merovingian::oauth
{

Page::Page(HtmlText title)
    : m_title{std::move(title)}
{
}

auto Page::paragraph(HtmlText const& text) -> void
{
    m_body.append("<p>");
    m_body.append(text.html());
    m_body.append("</p>\n");
}

auto Page::notice(HtmlText const& text) -> void
{
    m_body.append("<p class=\"notice\">");
    m_body.append(text.html());
    m_body.append("</p>\n");
}

auto Page::error(HtmlText const& text) -> void
{
    m_body.append("<p class=\"error\" role=\"alert\">");
    m_body.append(text.html());
    m_body.append("</p>\n");
}

auto Page::details(std::span<PageDetail const> details) -> void
{
    m_body.append("<dl>\n");
    for (auto const& detail : details)
    {
        m_body.append("<dt>");
        m_body.append(detail.label.html());
        m_body.append("</dt>\n<dd><bdi>");
        m_body.append(detail.value.html());
        m_body.append("</bdi></dd>\n");
    }
    m_body.append("</dl>\n");
}

auto Page::link(HtmlText const& label, std::string_view target) -> bool
{
    auto parsed = ParsedUri::read(target);
    auto const* uri = std::get_if<ParsedUri>(&parsed);
    if (uri == nullptr || uri->scheme() != "https" || !uri->has_authority())
    {
        return false;
    }
    auto href = HtmlText::escape(uri->text());
    if (!href.has_value())
    {
        return false;
    }
    m_body.append("<p><a href=\"");
    m_body.append(href->html());
    m_body.append("\" rel=\"noopener noreferrer\">");
    m_body.append(label.html());
    m_body.append("</a></p>\n");
    return true;
}

auto Page::form(PageForm const& form) -> bool
{
    if (!form.has_button())
    {
        return false;
    }
    m_body.append(form.html());
    return true;
}

auto Page::render() const -> std::string
{
    auto html = std::string{"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
                            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                            "<meta name=\"referrer\" content=\"same-origin\">\n<title>"};
    html.append(m_title.html());
    html.append("</title>\n<style>");
    html.append(page_style());
    html.append("</style>\n</head>\n<body>\n<main>\n<h1>");
    html.append(m_title.html());
    html.append("</h1>\n");
    html.append(m_body);
    html.append("</main>\n</body>\n</html>\n");
    return html;
}

} // namespace merovingian::oauth
