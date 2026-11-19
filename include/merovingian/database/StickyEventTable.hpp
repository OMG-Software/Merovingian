// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

// The most bytes of an event ID, room ID or sender a stored row holds, enforced where the row is stored and where it is
// read back: an oversized row is refused, never truncated.
inline constexpr auto max_sticky_event_field_bytes = std::size_t{255U};

// Whether `row` may be stored: the three text fields non-empty, within `max_sticky_event_field_bytes` and free of NUL
// (PostgreSQL TEXT cannot hold one), and both times not negative.
[[nodiscard]] auto sticky_event_is_storable(PersistentStickyEvent const& row) noexcept -> bool;

// The in-memory copy of `sticky_events` (migration 005, ADR-0854). The class owns the rows and shows them read-only, so
// a writer that bypasses it does not compile and its indexes cannot drift from the rows. Indexes: by event ID (hash);
// by room, and by sender, each ordered by (`expires_at_ms`, event ID); and every row by (`expires_at_ms`, event ID) for
// pruning. Every reader takes the clock and never returns an expired row (`expires_at_ms <= now_ms`), whether or not a
// prune has removed it yet, except `expired_at`, which exists to return them. No reader scans the table: a reader costs
// the rows it returns, plus the expired rows at the front of the ordering it walks. The table has no lock: a reader
// needs exclusion from writers (in main, `runtime.mutex`). A pointer it returns is valid until the next write. The
// defaulted copy and move keep every index valid: the indexes hold keys, never positions or pointers.
class StickyEventTable final
{
public:
    // The unexpired row for `event_id`, or nullptr (absent or expired).
    [[nodiscard]] auto find(std::string_view event_id, std::int64_t now_ms) const -> PersistentStickyEvent const*;
    // Whether a row for `event_id` is held at all, expired or not (the store's duplicate check).
    [[nodiscard]] auto contains(std::string_view event_id) const -> bool;
    // The unexpired rows of `room_id`, ordered by (`expires_at_ms`, event ID).
    [[nodiscard]] auto unexpired_of_room(std::string_view room_id, std::int64_t now_ms) const
        -> std::vector<PersistentStickyEvent const*>;
    // How many unexpired rows `sender` holds.
    [[nodiscard]] auto unexpired_count_of_sender(std::string_view sender, std::int64_t now_ms) const -> std::size_t;
    // At most `max` of `sender`'s unexpired rows, the oldest first (earliest `expires_at_ms`, ties by event ID).
    [[nodiscard]] auto oldest_unexpired_of_sender(std::string_view sender, std::int64_t now_ms, std::size_t max) const
        -> std::vector<PersistentStickyEvent const*>;
    // At most `max` rows with `expires_at_ms <= now_ms`, the earliest first. For the prune and tests.
    [[nodiscard]] auto expired_at(std::int64_t now_ms, std::size_t max) const
        -> std::vector<PersistentStickyEvent const*>;
    // Every row held, expired or not.
    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        return m_rows.size();
    }

    // The remaining members are for the store functions (StickyEventStore.hpp) and hydration only.

    // Adds `row`. False, and nothing changes, when it is not storable (`sticky_event_is_storable`) or its event ID is
    // held.
    auto insert(PersistentStickyEvent row) -> bool;
    // Removes the row for `event_id`. False when absent.
    auto erase(std::string_view event_id) -> bool;
    // Removes every row whose sender is `sender`, returning how many.
    auto erase_sender(std::string_view sender) -> std::size_t;
    // Removes every row whose room is `room_id`, returning how many. For `apply_room_snapshot` (ADR-0858).
    auto erase_room(std::string_view room_id) -> std::size_t;
    // Removes every row with `expires_at_ms <= now_ms`, returning how many.
    auto erase_expired(std::int64_t now_ms) -> std::size_t;
    // Removes every row, for hydration.
    auto clear() noexcept -> void;

    // Rows every reader above looked at over the table's life, for tests that prove cost.
    [[nodiscard]] auto rows_examined() const noexcept -> std::uint64_t
    {
        return m_rows_examined.value();
    }

private:
    template <typename Value>
    using KeyedBy = std::unordered_map<std::string, Value, detail::StateGroupKeyHash, std::equal_to<>>;
    using OrderKey = std::pair<std::int64_t, std::string>;
    using Ordering = std::set<OrderKey>;

    auto unindex(PersistentStickyEvent const& row) -> void;
    // Removes every row `book` (a room's or a sender's ordering) names, returning how many.
    auto erase_book(Ordering const& book) -> std::size_t;

    KeyedBy<PersistentStickyEvent> m_rows{};
    KeyedBy<Ordering> m_by_room{};
    KeyedBy<Ordering> m_by_sender{};
    Ordering m_by_expiry{};
    ExaminedRows m_rows_examined{};
};

} // namespace merovingian::database
