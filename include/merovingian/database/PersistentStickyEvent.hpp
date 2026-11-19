// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Migration 005 (ADR-0854): one sticky event (`sticky_events`, MSC4354) this server accepted. `received_at_ms` is when
// this server first saw the event (for a locally composed event, the `origin_server_ts` it stamped); `expires_at_ms`
// is `min(received_at_ms, origin_server_ts) + min(duration_ms, 3600000)`. Both are wall-clock milliseconds since the
// Unix epoch. A row is sticky only while `expires_at_ms` is after the clock. A row never changes except through
// `StickyEventTable`.
struct PersistentStickyEvent final
{
    std::string event_id{};
    std::string room_id{};
    std::string sender{};
    std::int64_t received_at_ms{0};
    std::int64_t expires_at_ms{0};
};

} // namespace merovingian::database
