// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/StickyEventCaps.hpp"
#include "merovingian/database/StickyEventRecordOutcome.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace merovingian::database
{

struct PersistentStore;

// The sticky events of migration 005 (ADR-0854). Every function here reads or writes
// `PersistentStore::sticky_events` and, for a write, the database in one transaction with bound parameters only.
// Memory changes only after the commit returns true. None takes a lock; in main the caller holds `runtime.mutex`.
// The caps are in StickyEventTable.hpp.

// Records `row` as a sticky event of its sender. In one transaction the row is inserted and the sender's oldest
// unexpired rows (earliest `expires_at_ms`, ties by event ID) are deleted so that afterwards the sender holds at most
// `caps.max_per_sender` unexpired rows; then, while the room would hold more than `caps.max_per_room`, the oldest row
// of the server holding the most rows in the room is deleted (the new row's server when it is tied for most, else the
// smallest server name; ADR-0857). The new row takes part in both orderings: when it is itself the one chosen it is
// not stored and the other rows are kept. True when the row is recorded, and also when nothing is to be written:
// `row.expires_at_ms <= now_ms` (an expired event is not sticky, ADR-0854; judged first) or a row with the same event
// ID is already held (a no-op). False, writing nothing, when the row is not storable (`sticky_event_is_storable`), a
// cap is 0, or the commit fails, with memory unchanged. That answer is the outcome's `recorded`; its `other_rooms`
// names the rooms other than `row.room_id` that lost a row to the sender cap, which the caller must report to the
// federation worker as changed (ADR-0862).
[[nodiscard]] auto record_sticky_event(PersistentStore& store, PersistentStickyEvent row, StickyEventCaps caps,
                                       std::int64_t now_ms) -> StickyEventRecordOutcome;

// Deletes the row of `event_id` (the event was redacted). True when the row is gone, also when there was none; false
// only when the commit fails, with memory unchanged.
[[nodiscard]] auto delete_sticky_event(PersistentStore& store, std::string_view event_id) -> bool;

// Deletes every row whose sender is `user_id` (account deactivation). Always runs the DELETE, even when memory holds no
// row for the user: a row that hydration skipped is in the database and must not survive. False only when the commit
// fails, with memory unchanged.
[[nodiscard]] auto delete_sticky_events_of_user(PersistentStore& store, std::string_view user_id) -> bool;

// Deletes every row with `expires_at_ms <= now_ms`, those in memory and those only in the database (rows that were
// expired when hydration ran are not in memory), and the `delayed_event_sticky_durations` rows whose delayed event is
// missing or no longer scheduled, in one transaction. True when done; false only when the commit fails, with memory
// unchanged.
[[nodiscard]] auto prune_expired_sticky_events(PersistentStore& store, std::int64_t now_ms) -> bool;

} // namespace merovingian::database
