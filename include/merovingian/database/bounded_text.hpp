// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace merovingian::database
{

// AUTH-1 (security-audit-report-2026-09-29.md): the longest an attacker-
// controlled audit field (actor, target, reason) may be once it is stored or
// logged. Matches the Matrix identifier ceiling of 255 bytes, so a legitimate
// user ID, room ID or device ID is never cut.
inline constexpr auto max_audit_field_bytes = std::size_t{255U};

// Returns `value` as well-formed UTF-8 of at most `max_bytes` bytes.
//
//  - Valid UTF-8 is copied unchanged, and the cut always falls between two
//    characters, so a multi-byte sequence is never split.
//  - Every invalid byte (lone continuation byte, truncated, overlong or
//    surrogate sequence, out-of-range lead byte) is replaced by U+FFFD.
//  - ASCII control characters (U+0000-U+001F and U+007F) are replaced by U+FFFD
//    so a value cannot forge a log line or smuggle a NUL into a text column.
//
// Work is proportional to `max_bytes`, not to `value.size()`: a 64 KiB input is
// abandoned as soon as the output is full.
[[nodiscard]] auto bounded_utf8(std::string_view value, std::size_t max_bytes) -> std::string;

} // namespace merovingian::database
