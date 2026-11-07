// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Pending to-device message. Sender pushes the row at send time; the
// recipient's /sync drain advances `stream_id` past the row and the row
// is then removed. `stream_id` is monotonic across the server and reused
// as the sync next_batch token field for to-device.
struct PersistentToDeviceMessage final
{
    std::uint64_t stream_id{0U};
    std::string sender_user_id{};
    std::string target_user_id{};
    std::string target_device_id{};
    std::string message_type{};
    std::string content_json{};
    // CSAZ-10: epoch milliseconds when the row was enqueued. Used to enforce the
    // per-recipient TTL independently of sync acknowledgement.
    std::uint64_t created_at_ms{0U};
};

} // namespace merovingian::database
