// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentDelayedEvent.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

// The in-memory copy of `delayed_events` (migration 003, ADR-0824). The class owns the rows and shows them read-only,
// so a writer that bypasses it does not compile and its indexes cannot drift from the rows: every mutation unindexes
// the row, changes it and indexes it again. Indexes: by delay ID (hash); per user, the scheduled rows by due time and
// the finalised rows by finalised time; every scheduled row that is not being sent by due time (`delayed_since_ms +
// delay_ms`, then delay ID), so the earliest due is O(1) and a restart O(log n); by (user, device, room, event type,
// transaction ID) for idempotency, only for rows with a transaction ID; by event ID for sent rows; and every
// finalised row by finalised time (the age prune). No reader scans the table. Nothing here is a secret, so keys are
// plain text. The table has no lock: a reader needs exclusion from writers (in main, `runtime.mutex`). A pointer it
// returns is valid until the next write. The defaulted copy and move keep every index valid: the indexes hold keys,
// never positions or pointers.
class DelayedEventTable final
{
public:
    // The row for `delay_id`, or nullptr. Does not check the owner: the management routes use `find_owned`.
    [[nodiscard]] auto find(std::string_view delay_id) const -> PersistentDelayedEvent const*;
    // The row for `delay_id` only when it belongs to `user_id`, else nullptr. The one place the ownership rule lives:
    // another user's row and a row that does not exist are the same answer.
    [[nodiscard]] auto find_owned(std::string_view user_id, std::string_view delay_id) const
        -> PersistentDelayedEvent const*;
    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        return m_rows.size();
    }

    // How many scheduled (not finalised) rows `user_id` holds, a being-sent row included.
    [[nodiscard]] auto scheduled_count(std::string_view user_id) const -> std::size_t;
    // The due time of the earliest-due scheduled row of `user_id` (a being-sent row included, for `Retry-After`), or
    // nullopt when the user holds none.
    [[nodiscard]] auto earliest_due_ms_of_user(std::string_view user_id) const -> std::optional<std::uint64_t>;
    // The scheduled row due first overall that is not marked as being sent, or nullptr. The order is `delayed_since_ms
    // + delay_ms`, then delay ID. The caller compares its due time (`delayed_event_due_ms`) with the clock.
    [[nodiscard]] auto earliest_due() const -> PersistentDelayedEvent const*;
    // The row of (`user_id`, `device_id`, `room_id`, `event_type`, `txn_id`) of any status, or nullptr. Rows with no
    // transaction ID are not in this index, so an empty `txn_id` finds nothing.
    [[nodiscard]] auto find_by_transaction(std::string_view user_id, std::string_view device_id,
                                           std::string_view room_id, std::string_view event_type,
                                           std::string_view txn_id) const -> PersistentDelayedEvent const*;
    // The sent row whose event is `event_id`, or nullptr.
    [[nodiscard]] auto find_sent_by_event_id(std::string_view event_id) const -> PersistentDelayedEvent const*;

    // How many finalised rows `user_id` holds.
    [[nodiscard]] auto finalised_count(std::string_view user_id) const -> std::size_t;
    // At most `max` of `user_id`'s finalised rows, oldest first (by `finalised_at_ms`, then delay ID).
    [[nodiscard]] auto finalised_of_user(std::string_view user_id, std::size_t max) const
        -> std::vector<PersistentDelayedEvent const*>;
    // At most `max` finalised rows of every user whose `finalised_at_ms` is below `cutoff_ms`, oldest first (by
    // `finalised_at_ms`, then delay ID). Costs the rows returned.
    [[nodiscard]] auto finalised_before(std::uint64_t cutoff_ms, std::size_t max) const
        -> std::vector<PersistentDelayedEvent const*>;
    // Whether `delay_id` is a row marked as being sent.
    [[nodiscard]] auto is_being_sent(std::string_view delay_id) const -> bool;

    // Adds `row`, indexing it by its status. False, and nothing changes, when its delay ID is held, or it has a
    // transaction ID and another row already holds the same (user, device, room, event type, transaction ID), or it is
    // `sent` and another sent row already claims its event ID.
    auto insert(PersistentDelayedEvent row) -> bool;
    // Sets `delayed_since_ms` of a scheduled row, moving it in the due order. False when the row is absent or not
    // scheduled.
    auto restart(std::string_view delay_id, std::uint64_t delayed_since_ms) -> bool;
    // Finalises a scheduled row: `status` (sent, cancelled or failed; scheduled is refused) with `finalised_at_ms`,
    // `event_id` and `error_json`. Any being-sent mark of the row goes, and so does its sticky duration. False when the row is absent or not scheduled.
    auto finalise(std::string_view delay_id, DelayedEventStatus status, std::uint64_t finalised_at_ms,
                  std::string event_id, std::string error_json) -> bool;
    // Sets `sticky_duration_ms` of a scheduled row (hydration of `delayed_event_sticky_durations`). False when the row
    // is absent or not scheduled, or `duration_ms` is below 1.
    auto attach_sticky_duration(std::string_view delay_id, std::int64_t duration_ms) -> bool;
    // Removes one row. False when absent.
    auto erase(std::string_view delay_id) -> bool;
    // Removes every row of `user_id`, returning how many.
    auto erase_user(std::string_view user_id) -> std::size_t;
    // Marks a scheduled row as being sent (memory only): it is not offered by `earliest_due`. False when the row is
    // absent, not scheduled or already marked.
    auto mark_being_sent(std::string_view delay_id) -> bool;
    // Removes the mark; the row is offered again when still scheduled. False when it was not marked.
    auto clear_being_sent(std::string_view delay_id) -> bool;
    // Removes every row and mark, for hydration.
    auto clear() noexcept -> void;

    // Rows every reader above looked at over the table's life, for tests that prove cost.
    [[nodiscard]] auto rows_examined() const noexcept -> std::uint64_t
    {
        return m_rows_examined.value();
    }

private:
    template <typename Value>
    using KeyedBy = std::unordered_map<std::string, Value, detail::StateGroupKeyHash, std::equal_to<>>;
    using OrderKey = std::pair<std::uint64_t, std::string>;

    // One user's rows: the scheduled ones by due time and the finalised ones by finalised time.
    struct UserBook final
    {
        std::set<OrderKey> scheduled{};
        std::set<OrderKey> finalised{};
    };

    auto index_row(PersistentDelayedEvent const& row) -> void;
    auto unindex_row(PersistentDelayedEvent const& row) -> void;

    KeyedBy<PersistentDelayedEvent> m_rows{};
    KeyedBy<UserBook> m_users{};
    // Every scheduled row not being sent, by (due time, delay ID).
    std::set<OrderKey> m_due{};
    // Every finalised row, by (finalised time, delay ID).
    std::set<OrderKey> m_finalised{};
    // (user NUL device NUL room NUL type NUL txn) -> delay ID, rows with a transaction ID only.
    KeyedBy<std::string> m_by_transaction{};
    // Event ID -> delay ID of the sent row.
    KeyedBy<std::string> m_by_event_id{};
    KeyedBy<bool> m_being_sent{};
    ExaminedRows m_rows_examined{};
};

// The time a scheduled row is due: `delayed_since_ms + delay_ms`, saturating at the largest value. The store caps
// the delay at 31 days, so the sum cannot overflow for any real clock, but a row read from a database or built by a
// test is never trusted to be within it.
[[nodiscard]] auto delayed_event_due_ms(PersistentDelayedEvent const& row) noexcept -> std::uint64_t;

} // namespace merovingian::database
