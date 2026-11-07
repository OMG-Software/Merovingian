// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>
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

} // namespace merovingian::email
