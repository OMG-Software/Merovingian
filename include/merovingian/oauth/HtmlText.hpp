// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/HtmlLiteral.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::oauth
{

// Text that is safe to put into a page, as element content or inside a double-quoted attribute (ADR-0772). A value
// exists only through escape() or from an HtmlLiteral, so text that has not been escaped cannot reach a page: every
// page part takes HtmlText (or a compile-time HtmlName, HtmlLiteral or PagePath), never a string.
class HtmlText final
{
public:
    // The longest text escaped, in bytes before escaping: a redirect URI (2048) and a device ID (255) are the
    // longest values a page shows; 4096 bounds a page whatever a caller passes.
    static constexpr std::size_t max_text_bytes = 4096U;

    // Compile-time text, which needs no escaping.
    // Implicit on purpose: a literal converts where page text is wanted.
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    HtmlText(HtmlLiteral literal);

    // `text` with `&`, `<`, `>`, `"` and `'` replaced by their character references, or std::nullopt when it is
    // empty, longer than max_text_bytes, or fails display_text_is_safe (invalid UTF-8, NUL, a control character, a
    // bidirectional formatting character). Nothing is stripped or replaced: the caller decides what to show instead.
    [[nodiscard]] static auto escape(std::string_view text) -> std::optional<HtmlText>;

    // The escaped HTML.
    [[nodiscard]] auto html() const noexcept -> std::string const&;

private:
    // Tagged so that a string literal can never pick this constructor over the HtmlLiteral one.
    HtmlText(std::in_place_t tag, std::string html);

    std::string m_html;
};

} // namespace merovingian::oauth
