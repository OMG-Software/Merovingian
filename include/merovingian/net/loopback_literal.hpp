// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::net
{

// True when `host` is an IP literal that names the local machine: an IPv4 dotted quad inside 127.0.0.0/8,
// or the IPv6 address ::1 in any form inet_pton accepts, with or without the surrounding brackets (libcurl
// returns an IPv6 host without them). A name such as `localhost` is not a literal and is never loopback
// here, because a name can be made to resolve elsewhere. Short IPv4 forms such as `127.1`, a port, a zone
// id and an IPv4-mapped IPv6 address are refused. Shared by the SMTP relay check (ADR-0220) and the
// appservice cleartext rule (ADR-0515).
[[nodiscard]] auto is_loopback_ip_literal(std::string_view host) noexcept -> bool;

} // namespace merovingian::net
