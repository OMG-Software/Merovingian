// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::core
{

// True when `value` is well-formed UTF-8: no overlong form, no surrogate (U+D800..U+DFFF), nothing above U+10FFFF,
// no truncated sequence. NUL (U+0000) is valid UTF-8; a caller that refuses it checks separately. The one validator:
// canonicaljson::utf8_is_valid and the form and cookie parsers call this.
[[nodiscard]] auto utf8_is_valid(std::string_view value) noexcept -> bool;

} // namespace merovingian::core
