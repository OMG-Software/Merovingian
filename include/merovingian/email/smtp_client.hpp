// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/email/smtp_endpoint.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::email
{

// Test-only: connect to these addresses instead of resolving the relay's host, and trust this PEM
// instead of the system CA store. Never set in production.
struct SmtpTestResolution final
{
    std::vector<std::string> pinned_addresses{};
    std::string trusted_ca_pem{};
};

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

enum class SmtpSendResult : std::uint8_t
{
    sent,
    // The recipient or sender failed is_safe_mailbox_address, or settings are unusable; resending
    // the same message cannot succeed.
    refused_locally,
    // The libcurl this server runs on was built without the relay's protocol.
    protocol_unavailable,
    // password_file could not be read as a secret file.
    credentials_unavailable,
    // The relay could not be reached, would not start TLS, failed verification, refused AUTH, a
    // command, or the message, or did not answer in time.
    failed,
};

struct SmtpSendOutcome final
{
    SmtpSendResult result{SmtpSendResult::failed};
    // For logs: libcurl's error name, or why it was refused locally. Never a secret.
    std::string detail{};
};

// Whether the libcurl in use can speak smtps:// (`implicit_tls`) or smtp://.
[[nodiscard]] auto smtp_protocol_available(bool implicit_tls) noexcept -> bool;

// Sends `message` (a complete RFC 5322 message, CRLF line endings) to `recipient` through the relay
// in `settings`, in one SMTP session. Blocking, bounded by the settings' timeouts; call it with no
// lock held. Never follows a redirect, never uses a proxy, never reuses a connection.
[[nodiscard]] auto send_smtp_message(SmtpSettings const& settings, std::string_view recipient, std::string_view message)
    -> SmtpSendOutcome;

} // namespace merovingian::email
