// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/DelayedEventStore.hpp"

#include "merovingian/database/BoundValue.hpp"
#include "merovingian/database/DelayedEventStatusText.hpp"
#include "merovingian/database/DelayedEventTable.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PreparedStatement.hpp"

#include <algorithm>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::database
{
namespace
{

    // A prepared statement takes at most 128 parameters, so a longer list of IDs is several DELETEs in the one
    // transaction, never one statement per row.
    constexpr auto delete_ids_per_statement = std::size_t{128U};

    [[nodiscard]] auto text(std::string_view value) -> BoundValue
    {
        return {std::string{value}, false};
    }

    [[nodiscard]] auto number(std::uint64_t value) -> BoundValue
    {
        return text(std::to_string(value));
    }

    // Booleans are stored as the text "true" and "false", as users.deactivated is.
    [[nodiscard]] auto flag(bool value) -> BoundValue
    {
        return text(value ? "true" : "false");
    }

    [[nodiscard]] auto within(std::string_view value, std::size_t cap) noexcept -> bool
    {
        return value.size() <= cap;
    }

    // PostgreSQL TEXT cannot hold a NUL byte and the table's transaction key joins its parts with one, so a field
    // holding one is refused, never stored.
    [[nodiscard]] auto has_nul(std::string_view value) noexcept -> bool
    {
        return value.find('\0') != std::string_view::npos;
    }

    [[nodiscard]] auto row_is_storable(PersistentDelayedEvent const& row) noexcept -> bool
    {
        return !has_nul(row.delay_id) && !has_nul(row.user_id) && !has_nul(row.device_id) && !has_nul(row.room_id) &&
               !has_nul(row.event_type) && !has_nul(row.state_key) && !has_nul(row.txn_id) &&
               !has_nul(row.content_json) && !row.delay_id.empty() && !row.user_id.empty() && !row.room_id.empty() &&
               !row.event_type.empty() && !row.content_json.empty() &&
               within(row.delay_id, max_delayed_event_id_bytes) &&
               within(row.content_json, max_delayed_event_content_bytes) &&
               within(row.user_id, max_delayed_event_field_bytes) &&
               within(row.device_id, max_delayed_event_field_bytes) &&
               within(row.room_id, max_delayed_event_field_bytes) &&
               within(row.event_type, max_delayed_event_field_bytes) &&
               within(row.state_key, max_delayed_event_field_bytes) &&
               within(row.txn_id, max_delayed_event_field_bytes) && row.delay_ms != 0U &&
               row.delay_ms <= max_delayed_event_delay_ms && row.status == DelayedEventStatus::scheduled &&
               row.finalised_at_ms == 0U && row.event_id.empty() && row.error_json.empty();
    }

    [[nodiscard]] auto delete_rows_statement(std::vector<std::string> const& delay_ids, std::size_t first,
                                             std::size_t count) -> PreparedStatement
    {
        auto sql = std::string{"DELETE FROM delayed_events WHERE delay_id IN ("};
        auto parameters = std::vector<BoundValue>{};
        parameters.reserve(count);
        for (auto index = first; index < first + count; ++index)
        {
            sql += parameters.empty() ? "$" : ", $";
            sql += std::to_string(parameters.size() + 1U);
            parameters.push_back(text(delay_ids[index]));
        }
        sql += ")";
        return {"delete_delayed_events", std::move(sql), std::move(parameters)};
    }

    // Appends the DELETEs for `delay_ids`, batched.
    auto append_delete_statements(std::vector<PreparedStatement>& statements, std::vector<std::string> const& delay_ids)
        -> void
    {
        for (auto first = std::size_t{0U}; first < delay_ids.size(); first += delete_ids_per_statement)
        {
            statements.push_back(
                delete_rows_statement(delay_ids, first, std::min(delete_ids_per_statement, delay_ids.size() - first)));
        }
    }

    // The delay IDs of the oldest finalised rows of `user_id` to delete so that, once one more row is finalised, the
    // user holds at most `bound` finalised rows. The row being finalised is still scheduled, so it is never among them.
    [[nodiscard]] auto evictions_for(DelayedEventTable const& table, std::string_view user_id, std::size_t bound)
        -> std::vector<std::string>
    {
        auto doomed = std::vector<std::string>{};
        auto const held = table.finalised_count(user_id);
        if (held + 1U <= bound)
        {
            return doomed;
        }
        auto const excess = held + 1U - bound;
        for (auto const* row : table.finalised_of_user(user_id, std::min(excess, held)))
        {
            doomed.push_back(row->delay_id);
        }
        return doomed;
    }

    // The UPDATE that finalises one row.
    [[nodiscard]] auto finalise_statement(std::string_view delay_id, DelayedEventStatus status,
                                          std::uint64_t finalised_at_ms, std::string_view event_id,
                                          std::string_view error_json) -> PreparedStatement
    {
        return {
            "finalise_delayed_event",
            "UPDATE delayed_events SET status = $1, finalised_at_ms = $2, event_id = $3, error_json = $4 WHERE "
            "delay_id = $5",
            {text(delayed_event_status_text(status)), number(finalised_at_ms), text(event_id), text(error_json),
              text(delay_id)}
        };
    }

} // namespace

auto store_delayed_event(PersistentStore& store, PersistentDelayedEvent row) -> bool
{
    if (!row_is_storable(row) || store.delayed_events.find(row.delay_id) != nullptr ||
        store.delayed_events.find_by_transaction(row.user_id, row.device_id, row.room_id, row.event_type, row.txn_id) !=
            nullptr)
    {
        return false;
    }
    auto const statement = PreparedStatement{
        "insert_delayed_event",
        "INSERT INTO delayed_events (delay_id, user_id, device_id, room_id, event_type, is_state, state_key, "
        "content_json, txn_id, via_appservice, delay_ms, delayed_since_ms, status, finalised_at_ms, event_id, "
        "error_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
        {text(row.delay_id), text(row.user_id), text(row.device_id), text(row.room_id), text(row.event_type),
          flag(row.is_state), text(row.state_key), text(row.content_json), text(row.txn_id), flag(row.via_appservice),
          number(row.delay_ms), number(row.delayed_since_ms), text(delayed_event_status_text(row.status)),
          number(row.finalised_at_ms), text(row.event_id), text(row.error_json)}
    };
    if (!commit_persistent_transaction(store, {statement}))
    {
        return false;
    }
    return store.delayed_events.insert(std::move(row));
}

auto restart_delayed_event(PersistentStore& store, std::string_view delay_id, std::uint64_t now_ms) -> bool
{
    auto const* row = store.delayed_events.find(delay_id);
    if (row == nullptr || row->status != DelayedEventStatus::scheduled || store.delayed_events.is_being_sent(delay_id))
    {
        return false;
    }
    auto const statement = PreparedStatement{
        "restart_delayed_event",
        "UPDATE delayed_events SET delayed_since_ms = $1 WHERE delay_id = $2",
        {number(now_ms), text(delay_id)}
    };
    if (!commit_persistent_transaction(store, {statement}))
    {
        return false;
    }
    return store.delayed_events.restart(delay_id, now_ms);
}

auto cancel_delayed_event(PersistentStore& store, std::string_view delay_id, std::uint64_t now_ms,
                          std::size_t max_finalised_per_user) -> bool
{
    auto const* row = store.delayed_events.find(delay_id);
    if (row == nullptr || row->status != DelayedEventStatus::scheduled || store.delayed_events.is_being_sent(delay_id))
    {
        return false;
    }
    auto const doomed = evictions_for(store.delayed_events, row->user_id, max_finalised_per_user);
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(finalise_statement(delay_id, DelayedEventStatus::cancelled, now_ms, {}, {}));
    append_delete_statements(statements, doomed);
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    for (auto const& evicted : doomed)
    {
        std::ignore = store.delayed_events.erase(evicted);
    }
    return store.delayed_events.finalise(delay_id, DelayedEventStatus::cancelled, now_ms, {}, {});
}

auto record_delayed_event_outcome(PersistentStore& store, std::string_view delay_id, DelayedEventStatus outcome,
                                  std::uint64_t now_ms, std::string event_id, std::string error_json,
                                  std::size_t max_finalised_per_user) -> DelayedEventOutcomeResult
{
    auto const* row = store.delayed_events.find(delay_id);
    auto const shape_is_right = (outcome == DelayedEventStatus::sent && !event_id.empty() && error_json.empty()) ||
                                (outcome == DelayedEventStatus::failed && event_id.empty() && !error_json.empty());
    if (row == nullptr || row->status != DelayedEventStatus::scheduled || !shape_is_right ||
        !within(event_id, max_delayed_event_field_bytes) || !within(error_json, max_delayed_event_error_bytes))
    {
        return DelayedEventOutcomeResult::refused;
    }
    auto const doomed = evictions_for(store.delayed_events, row->user_id, max_finalised_per_user);
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(finalise_statement(delay_id, outcome, now_ms, event_id, error_json));
    append_delete_statements(statements, doomed);
    auto const committed = commit_persistent_transaction(store, statements);
    // The one place memory changes without a commit (ADR-0825). By now the send was attempted, and memory must say
    // what happened: leaving the row scheduled would send it again on every run of the job. When the commit failed,
    // the database row still reads "scheduled", so the next start-up sends the event once more, which the
    // at-least-once rule allows; the caller is told, so it can log it. The evictions follow the commit only: a
    // failed commit deleted nothing, so no finalised row leaves memory either.
    if (committed)
    {
        for (auto const& evicted : doomed)
        {
            std::ignore = store.delayed_events.erase(evicted);
        }
    }
    std::ignore = store.delayed_events.finalise(delay_id, outcome, now_ms, std::move(event_id), std::move(error_json));
    return committed ? DelayedEventOutcomeResult::recorded : DelayedEventOutcomeResult::commit_failed;
}

auto delete_delayed_events_of_user(PersistentStore& store, std::string_view user_id) -> bool
{
    if (store.delayed_events.scheduled_count(user_id) == 0U && store.delayed_events.finalised_count(user_id) == 0U)
    {
        return true;
    }
    auto const statement = PreparedStatement{
        "delete_delayed_events_of_user", "DELETE FROM delayed_events WHERE user_id = $1", {text(user_id)}};
    if (!commit_persistent_transaction(store, {statement}))
    {
        return false;
    }
    std::ignore = store.delayed_events.erase_user(user_id);
    return true;
}

auto prune_finalised_delayed_events(PersistentStore& store, std::uint64_t cutoff_ms, std::size_t max_rows)
    -> std::optional<std::size_t>
{
    auto doomed = std::vector<std::string>{};
    for (auto const* row : store.delayed_events.finalised_before(cutoff_ms, max_rows))
    {
        doomed.push_back(row->delay_id);
    }
    if (doomed.empty())
    {
        return std::size_t{0U};
    }
    auto statements = std::vector<PreparedStatement>{};
    append_delete_statements(statements, doomed);
    if (!commit_persistent_transaction(store, statements))
    {
        return std::nullopt;
    }
    for (auto const& delay_id : doomed)
    {
        std::ignore = store.delayed_events.erase(delay_id);
    }
    return doomed.size();
}

} // namespace merovingian::database
