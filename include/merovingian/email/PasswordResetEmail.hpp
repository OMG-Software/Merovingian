// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <string>

namespace merovingian::email
{

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

} // namespace merovingian::email
