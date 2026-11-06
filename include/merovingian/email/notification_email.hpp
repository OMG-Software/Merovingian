// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::email
{

// What one notification email says (ADR-0219): how many notifications are unread on this server,
// and nothing else. No room, sender or message text appears in it, so nothing a user was sent
// passes through a mail relay or sits in a mailbox.
struct UnreadNotificationEmail final
{
    // Both must pass is_safe_mailbox_address.
    std::string from{};
    std::string to{};
    // The Matrix server name (host, optional :port; an IPv6 literal in brackets). Names the server
    // in the text and is the right-hand side of the Message-ID, without its port.
    std::string server_name{};
    std::uint32_t unread_count{0U};
    std::chrono::system_clock::time_point sent_at{};
    // 16 to 64 lowercase hex characters, unique per email: the left-hand side of the Message-ID.
    std::string message_id_token{};
};

// The RFC 5322 message for `email`: US-ASCII, CRLF line endings, a text/plain body. Returns nullopt
// when any input could not be written safely (an unsafe address, a server name or token outside
// the documented forms, or an unread count of zero): the caller sends nothing rather than a
// repaired message. Pure; no I/O.
// The message that carries a password-reset token (ADR-0481). It holds the token, the server name and nothing
// else: no link, no account name, no address of the person it is for beyond the envelope.
struct PasswordResetEmail final
{
    // Both must pass is_safe_mailbox_address.
    std::string from{};
    std::string to{};
    std::string server_name{};
    // 8 to 32 characters of A-Z and 2-9 (see password_reset_token_alphabet): anything else is refused, so a
    // token can never carry a line break into the message.
    std::string token{};
    std::chrono::system_clock::time_point sent_at{};
    // As UnreadNotificationEmail::message_id_token.
    std::string message_id_token{};
};

[[nodiscard]] auto build_password_reset_email(PasswordResetEmail const& email) -> std::optional<std::string>;

[[nodiscard]] auto build_unread_notification_email(UnreadNotificationEmail const& email) -> std::optional<std::string>;

} // namespace merovingian::email
