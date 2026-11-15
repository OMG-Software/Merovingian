// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::core
{

// True when `text` is an RFC 9110 section 5.6.2 `token`: one or more of the letters, digits and
// ``!#$%&'*+-.^_`|~``. An HTTP header name and an RFC 6265 cookie name are tokens.
[[nodiscard]] auto http_token_is_valid(std::string_view text) noexcept -> bool;

} // namespace merovingian::core
