// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/email/SmtpSendOutcome.hpp"    // split-shim
#include "merovingian/email/SmtpSendResult.hpp"     // split-shim
#include "merovingian/email/SmtpSettings.hpp"       // split-shim
#include "merovingian/email/SmtpTestResolution.hpp" // split-shim

#include <string_view>

namespace merovingian::email
{

// Whether the libcurl in use can speak smtps:// (`implicit_tls`) or smtp://.
[[nodiscard]] auto smtp_protocol_available(bool implicit_tls) noexcept -> bool;

// Sends `message` (a complete RFC 5322 message, CRLF line endings) to `recipient` through the relay
// in `settings`, in one SMTP session. Blocking, bounded by the settings' timeouts; call it with no
// lock held. Never follows a redirect, never uses a proxy, never reuses a connection.
[[nodiscard]] auto send_smtp_message(SmtpSettings const& settings, std::string_view recipient, std::string_view message)
    -> SmtpSendOutcome;

} // namespace merovingian::email
