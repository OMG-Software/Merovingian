// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/email/SmtpTestResolution.hpp"
#include "merovingian/email/smtp_endpoint.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::email
{

// How to reach the relay (ADR-0220). Built from config::EmailConfig by the homeserver.
struct SmtpSettings final
{
    SmtpEndpoint endpoint{};
    // When true, a smtp:// relay must accept STARTTLS before anything else is sent. When false
    // the session is cleartext; config validation allows that only for a loopback IP literal.
    // TLS is always verified: peer certificate and host name.
    bool require_tls{true};
    // Envelope sender. Must pass is_safe_mailbox_address.
    std::string from{};
    // SMTP AUTH. Both empty means no AUTH. The password is read from password_file (owner-only,
    // as every secret file) for each send.
    std::string username{};
    std::string password_file{};
    // The name this server gives in EHLO; an empty or unusable one leaves libcurl's default.
    std::string helo_domain{};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{30U};
    std::optional<SmtpTestResolution> test_resolution{};
};

} // namespace merovingian::email
