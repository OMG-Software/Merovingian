// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::email
{

// The SMTP relay named by server.email.smtp_url.
struct SmtpEndpoint final
{
    // smtps:// (TLS from the first byte) rather than smtp:// (STARTTLS, or cleartext).
    bool implicit_tls{false};
    // As written in the URL; an IPv6 literal keeps its brackets.
    std::string host{};
    // From the URL, else 465 for smtps:// and 587 for smtp://.
    std::uint16_t port{0U};
    // The host is an IPv4 loopback literal (127.0.0.0/8) or [::1]. A name such as "localhost" is
    // never loopback here: DNS decides where a name goes, and a cleartext relay must be on this
    // machine whatever DNS says.
    bool loopback_literal{false};
};

// Parses `smtps://host[:port]` or `smtp://host[:port]`, with an optional single trailing '/'.
// Refuses any other scheme, userinfo, a path, query or fragment, whitespace and control bytes,
// percent-encoding, an empty host, a host of anything but letters, digits, '-' and '.' (or a
// bracketed IPv6 literal), and a port outside 1-65535. Scheme and host are case-insensitive and
// returned lower-case. Pure; no I/O.
[[nodiscard]] auto parse_smtp_url(std::string_view url) -> std::optional<SmtpEndpoint>;

} // namespace merovingian::email
