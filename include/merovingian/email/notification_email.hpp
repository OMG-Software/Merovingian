// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/email/PasswordResetEmail.hpp"      // split-shim
#include "merovingian/email/UnreadNotificationEmail.hpp" // split-shim

#include <optional>
#include <string>

namespace merovingian::email
{

[[nodiscard]] auto build_password_reset_email(PasswordResetEmail const& email) -> std::optional<std::string>;

// The RFC 5322 message for `email`: US-ASCII, CRLF line endings, a text/plain body. Returns nullopt
// when any input could not be written safely (an unsafe address, a server name or token outside
// the documented forms, or an unread count of zero): the caller sends nothing rather than a
// repaired message. Pure; no I/O.
[[nodiscard]] auto build_unread_notification_email(UnreadNotificationEmail const& email) -> std::optional<std::string>;

} // namespace merovingian::email
