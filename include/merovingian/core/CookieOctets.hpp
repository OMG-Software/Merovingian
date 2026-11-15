// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::core
{

// True when every byte of `value` is an RFC 6265 section 4.1.1 `cookie-octet` (0x21, 0x23-0x2B, 0x2D-0x3A,
// 0x3C-0x5B, 0x5D-0x7E: printable ASCII without space, `"`, `,`, `;` and `\`). An empty value is valid. The
// unquoted form of `cookie-value`; the quoted form is never accepted or produced here.
[[nodiscard]] auto cookie_octets_are_valid(std::string_view value) noexcept -> bool;

} // namespace merovingian::core
