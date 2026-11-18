// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/PageDetail.hpp"
#include "merovingian/oauth/PageForm.hpp"

#include <span>
#include <string>
#include <string_view>

namespace merovingian::oauth
{

// The one renderer of every HTML page the server serves (ADR-0815, ADR-0772). A page is a title, used as the
// document title and the heading, and parts in the order they are added. Every part takes HtmlText or a
// compile-time value, so unescaped text cannot reach the output. The page holds no `<script>`, no event-handler
// attribute, no `style=` attribute, no `javascript:` or `data:` address and nothing from another origin; its only
// style is the fixed block page_style() returns, which page_headers() allows by hash.
//
// The parts a page has are chosen by server code, not by a request, so their number needs no cap; each piece of text
// is capped by HtmlText::max_text_bytes.
class Page final
{
public:
    explicit Page(HtmlText title);

    auto paragraph(HtmlText const& text) -> void;
    // A highlighted notice, such as "Registration is closed on this server".
    auto notice(HtmlText const& text) -> void;
    // An error box, announced to assistive technology (`role="alert"`).
    auto error(HtmlText const& text) -> void;
    // A list of labelled details.
    auto details(std::span<PageDetail const> details) -> void;
    // A link to `target`. False, and nothing added, unless `target` passes ParsedUri::read with the scheme `https`
    // (lower case) and an authority: no other scheme, `javascript:` and `data:` included, can become an `href`.
    [[nodiscard]] auto link(HtmlText const& label, std::string_view target) -> bool;
    // A form. False, and nothing added, when it has no submit button.
    [[nodiscard]] auto form(PageForm const& form) -> bool;

    // The whole document, UTF-8.
    [[nodiscard]] auto render() const -> std::string;

private:
    HtmlText m_title;
    std::string m_body{};
};

} // namespace merovingian::oauth
