// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Presence state for a Matrix user. Stored as the latest authoritative
// snapshot; the sync stream surfaces rows whose `stream_id` exceeds the
// caller's since-token.
struct PersistentPresence final
{
    std::uint64_t stream_id{0U};
    std::string user_id{};
    std::string presence{"offline"};
    std::string status_msg{};
    // Milliseconds since `observed_at_ms`, as of that moment.
    std::int64_t last_active_ago{0};
    bool currently_active{false};
    // Wall-clock milliseconds since the Unix epoch at which `last_active_ago` was true. It is what
    // lets a read report "how long ago" up to date rather than as of the write. Never persisted: a
    // row loaded from the database has 0 and reports `last_active_ago` as stored.
    std::int64_t observed_at_ms{0};
};

} // namespace merovingian::database
