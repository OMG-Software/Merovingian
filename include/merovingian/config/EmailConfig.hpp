// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::config
{

// Outbound email for kind "email" pushers (ADR-0219, ADR-0220). Off while smtp_url is empty, and
// POST /pushers/set then refuses kind "email". Independent of server.push.enabled, which governs
// Push Gateway API delivery only. Every key requires a restart.
struct EmailConfig final
{
    // smtps://host[:port] (TLS from the first byte; port 465 by default) or smtp://host[:port]
    // (STARTTLS, required unless require_tls is false; port 587 by default). See
    // email::parse_smtp_url for what else is refused.
    std::string smtp_url{};
    // false allows a cleartext smtp:// relay, and only one at a loopback IP literal (a local MTA),
    // never with credentials.
    bool require_tls{true};
    // Envelope sender and From: header. Required when smtp_url is set.
    std::string from{};
    // SMTP AUTH: both or neither. The password is read from password_file, an owner-only secret
    // file, for each email and not kept in memory between them.
    std::string username{};
    std::string password_file{};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{30U};
    // How long after a notification an email is sent. If the user has read everything by then
    // (a read receipt on another device), none is sent.
    std::uint32_t notification_delay_seconds{600U};
    // The least time between two emails to one address.
    std::uint32_t notification_throttle_seconds{3600U};
};

} // namespace merovingian::config
