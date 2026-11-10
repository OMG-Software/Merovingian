// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string_view>

namespace merovingian::email
{

// RFC 5321 section 4.5.3.1: a path is at most 256 octets including its angle brackets, so an
// address is at most 254; a local part is at most 64 octets and a domain at most 255 (253 as
// written without the root label).
inline constexpr auto max_mailbox_address_bytes = std::size_t{254U};
inline constexpr auto max_mailbox_local_part_bytes = std::size_t{64U};
inline constexpr auto max_mailbox_domain_bytes = std::size_t{253U};

// Whether `address` may be written into an SMTP command (`MAIL FROM:<...>`, `RCPT TO:<...>`) and
// an RFC 5322 header as it stands. Deliberately narrower than RFC 5322's addr-spec: exactly one
// '@'; a non-empty local part of RFC 5322 atext and single dots (no quoted strings, no leading,
// trailing or doubled dot); a domain of LDH labels separated by single dots (no address literals,
// no non-ASCII). Anything else is refused rather than escaped, because each byte outside those
// sets is either a way to end the command or header early (CR, LF, NUL, '>') or one an SMTP relay
// may parse differently from this server. Pure; no I/O.
[[nodiscard]] auto is_safe_mailbox_address(std::string_view address) noexcept -> bool;

} // namespace merovingian::email
