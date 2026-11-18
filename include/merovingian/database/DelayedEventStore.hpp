// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/DelayedEventOutcomeResult.hpp"
#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/PersistentDelayedEvent.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::database
{

struct PersistentStore;

// The delayed events of migration 003 (ADR-0824, ADR-0825). Every function here reads or writes
// `PersistentStore::delayed_events` and, for a write, the database in one transaction with bound parameters only.
// Memory changes only after the commit returns true, with the one stated exception of
// `record_delayed_event_outcome`. None takes a lock; in main the caller holds `runtime.mutex`. Nothing here logs a
// row's `content_json`.

// Caps on what one row holds, enforced where the row is stored as well as where a request is parsed: an oversized row
// is refused, never truncated.
inline constexpr auto max_delayed_event_id_bytes = std::size_t{64U};
// The event size limit (65,536 bytes serialised): content larger than this could never be sent.
inline constexpr auto max_delayed_event_content_bytes = std::size_t{65'536U};
// A standard error object, which carries an errcode and a reason of at most 255 bytes.
inline constexpr auto max_delayed_event_error_bytes = std::size_t{1024U};
// The user, device, room, event, event type, state key and transaction IDs.
inline constexpr auto max_delayed_event_field_bytes = std::size_t{255U};
// The longest delay a row may hold: 31 days. The configured maximum is never above it.
inline constexpr auto max_delayed_event_delay_ms = std::uint64_t{2'678'400'000U};

// Stores a new scheduled row. False, writing nothing, when `delay_id`, `user_id`, `room_id`, `event_type` or
// `content_json` is empty, a field is over its cap, `delay_ms` is 0 or over `max_delayed_event_delay_ms`, the status is
// not `scheduled` (or the row carries a finalised time, event ID or error), the delay ID is already held, the
// transaction ID is already held for the same (user, device, room, event type), or the commit fails. It does NOT
// enforce the per-user cap: the caller does, because it must compute `Retry-After` from the user's rows.
[[nodiscard]] auto store_delayed_event(PersistentStore& store, PersistentDelayedEvent row) -> bool;

// Sets `delayed_since_ms` of a scheduled row to `now_ms` (a restart). False when the row is absent, not scheduled,
// being sent, or the commit fails; then nothing changed.
[[nodiscard]] auto restart_delayed_event(PersistentStore& store, std::string_view delay_id, std::uint64_t now_ms)
    -> bool;

// Finalises a scheduled row as `cancelled` at `now_ms` (the owner's cancel). False when the row is absent, not
// scheduled, being sent, or the commit fails; then nothing changed. In the same transaction the user's oldest
// finalised rows are deleted so the user holds at most `max_finalised_per_user` finalised rows afterwards (the row
// finalised counts and is never the one evicted; callers pass 1 to 1000).
[[nodiscard]] auto cancel_delayed_event(PersistentStore& store, std::string_view delay_id, std::uint64_t now_ms,
                                        std::size_t max_finalised_per_user) -> bool;

// Records the outcome of an attempt to send a scheduled row: `outcome` is `sent` with the event's `event_id`, or
// `failed` with a standard error object `error_json` (the other field empty). Finalises at `now_ms` and evicts as
// `cancel_delayed_event` does, in one transaction. A row marked as being sent is the expected case. If the commit fails
// the in-memory row is STILL finalised and `commit_failed` is returned: this is the one place memory changes without
// a commit (ADR-0825). See the definition for why.
[[nodiscard]] auto record_delayed_event_outcome(PersistentStore& store, std::string_view delay_id,
                                                DelayedEventStatus outcome, std::uint64_t now_ms, std::string event_id,
                                                std::string error_json, std::size_t max_finalised_per_user)
    -> DelayedEventOutcomeResult;

// Deletes every row of `user_id`, scheduled and finalised, in one `DELETE ... WHERE user_id = $1`, which always runs
// (a row hydration skipped is in the database only). True when the rows are gone, then memory is erased; false when the
// commit fails, with memory unchanged.
[[nodiscard]] auto delete_delayed_events_of_user(PersistentStore& store, std::string_view user_id) -> bool;

// Deletes finalised rows whose `finalised_at_ms` is below `cutoff_ms`, oldest first, at most `max_rows`, in one
// transaction. Returns how many were deleted, or nullopt when the commit failed (memory unchanged).
[[nodiscard]] auto prune_finalised_delayed_events(PersistentStore& store, std::uint64_t cutoff_ms, std::size_t max_rows)
    -> std::optional<std::size_t>;

} // namespace merovingian::database
