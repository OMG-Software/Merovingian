// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::oauth
{

// The `Content-Type` an OAuth 2.0 form body must carry: `application/x-www-form-urlencoded`, in any ASCII case (RFC
// 9110 section 8.3.1). Anything else is refused rather than guessed at: the body is read as a form and nothing else.

// A page's form post: the type alone, with no parameter, which is what an HTML form sends.
[[nodiscard]] auto page_form_content_type_is_accepted(std::string_view content_type) noexcept -> bool;

// A token or revocation request: the type alone, or with the one parameter `charset=utf-8` (quoted or not, any ASCII
// case, optional spaces around the `;`), which a browser's `fetch` with `URLSearchParams` sends (ADR-0791). RFC 6749
// appendix B makes the form UTF-8 in any case, so the parameter changes nothing; any other parameter is refused.
[[nodiscard]] auto api_form_content_type_is_accepted(std::string_view content_type) noexcept -> bool;

} // namespace merovingian::oauth
