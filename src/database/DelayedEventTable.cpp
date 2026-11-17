// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/DelayedEventTable.hpp"

#include <limits>
#include <tuple>

namespace merovingian::database
{
namespace
{

    // A key made of the parts separated by NUL, which no Matrix identifier, event type or transaction ID may hold, so
    // two different tuples never make the same key.
    [[nodiscard]] auto transaction_key(std::string_view user_id, std::string_view device_id, std::string_view room_id,
                                       std::string_view event_type, std::string_view txn_id) -> std::string
    {
        auto key = std::string{user_id};
        for (auto const part : {device_id, room_id, event_type, txn_id})
        {
            key.push_back('\0');
            key.append(part);
        }
        return key;
    }

    [[nodiscard]] auto transaction_key_of(PersistentDelayedEvent const& row) -> std::string
    {
        return transaction_key(row.user_id, row.device_id, row.room_id, row.event_type, row.txn_id);
    }

} // namespace

auto delayed_event_due_ms(PersistentDelayedEvent const& row) noexcept -> std::uint64_t
{
    // Saturating add: a sum that would wrap is the largest value instead, so a corrupt row is due last, never first.
    constexpr auto largest = std::numeric_limits<std::uint64_t>::max();
    return row.delayed_since_ms > largest - row.delay_ms ? largest : row.delayed_since_ms + row.delay_ms;
}

auto DelayedEventTable::find(std::string_view delay_id) const -> PersistentDelayedEvent const*
{
    auto const found = m_rows.find(delay_id);
    return found == m_rows.end() ? nullptr : &found->second;
}

auto DelayedEventTable::find_owned(std::string_view user_id, std::string_view delay_id) const
    -> PersistentDelayedEvent const*
{
    auto const* row = find(delay_id);
    return row != nullptr && row->user_id == user_id ? row : nullptr;
}

auto DelayedEventTable::scheduled_count(std::string_view user_id) const -> std::size_t
{
    auto const found = m_users.find(user_id);
    return found == m_users.end() ? 0U : found->second.scheduled.size();
}

auto DelayedEventTable::earliest_due_ms_of_user(std::string_view user_id) const -> std::optional<std::uint64_t>
{
    auto const found = m_users.find(user_id);
    if (found == m_users.end() || found->second.scheduled.empty())
    {
        return std::nullopt;
    }
    m_rows_examined.add(1U);
    return found->second.scheduled.begin()->first;
}

auto DelayedEventTable::earliest_due() const -> PersistentDelayedEvent const*
{
    if (m_due.empty())
    {
        return nullptr;
    }
    m_rows_examined.add(1U);
    return find(m_due.begin()->second);
}

auto DelayedEventTable::find_by_transaction(std::string_view user_id, std::string_view device_id,
                                            std::string_view room_id, std::string_view event_type,
                                            std::string_view txn_id) const -> PersistentDelayedEvent const*
{
    if (txn_id.empty())
    {
        return nullptr;
    }
    auto const found = m_by_transaction.find(transaction_key(user_id, device_id, room_id, event_type, txn_id));
    if (found == m_by_transaction.end())
    {
        return nullptr;
    }
    m_rows_examined.add(1U);
    return find(found->second);
}

auto DelayedEventTable::find_sent_by_event_id(std::string_view event_id) const -> PersistentDelayedEvent const*
{
    auto const found = m_by_event_id.find(event_id);
    if (found == m_by_event_id.end())
    {
        return nullptr;
    }
    m_rows_examined.add(1U);
    return find(found->second);
}

auto DelayedEventTable::finalised_count(std::string_view user_id) const -> std::size_t
{
    auto const found = m_users.find(user_id);
    return found == m_users.end() ? 0U : found->second.finalised.size();
}

auto DelayedEventTable::finalised_of_user(std::string_view user_id, std::size_t max) const
    -> std::vector<PersistentDelayedEvent const*>
{
    auto rows = std::vector<PersistentDelayedEvent const*>{};
    auto const found = m_users.find(user_id);
    if (found == m_users.end())
    {
        return rows;
    }
    for (auto const& [finalised_at_ms, delay_id] : found->second.finalised)
    {
        if (rows.size() >= max)
        {
            break;
        }
        rows.push_back(find(delay_id));
    }
    m_rows_examined.add(rows.size());
    return rows;
}

auto DelayedEventTable::finalised_before(std::uint64_t cutoff_ms, std::size_t max) const
    -> std::vector<PersistentDelayedEvent const*>
{
    auto rows = std::vector<PersistentDelayedEvent const*>{};
    for (auto const& [finalised_at_ms, delay_id] : m_finalised)
    {
        if (rows.size() >= max || finalised_at_ms >= cutoff_ms)
        {
            break;
        }
        rows.push_back(find(delay_id));
    }
    m_rows_examined.add(rows.size());
    return rows;
}

auto DelayedEventTable::is_being_sent(std::string_view delay_id) const -> bool
{
    return m_being_sent.contains(delay_id);
}

auto DelayedEventTable::index_row(PersistentDelayedEvent const& row) -> void
{
    auto& book = m_users[row.user_id];
    if (row.status == DelayedEventStatus::scheduled)
    {
        auto const due = OrderKey{delayed_event_due_ms(row), row.delay_id};
        book.scheduled.insert(due);
        if (!m_being_sent.contains(row.delay_id))
        {
            m_due.insert(due);
        }
    }
    else
    {
        auto const finalised = OrderKey{row.finalised_at_ms, row.delay_id};
        book.finalised.insert(finalised);
        m_finalised.insert(finalised);
    }
    if (!row.txn_id.empty())
    {
        m_by_transaction.emplace(transaction_key_of(row), row.delay_id);
    }
    if (row.status == DelayedEventStatus::sent && !row.event_id.empty())
    {
        // The first sent row to name an event keeps the index entry: an event ID belongs to one event, so a second
        // claimant is a corrupt row and the lookup stays with the first.
        m_by_event_id.emplace(row.event_id, row.delay_id);
    }
}

auto DelayedEventTable::unindex_row(PersistentDelayedEvent const& row) -> void
{
    if (auto const book = m_users.find(row.user_id); book != m_users.end())
    {
        book->second.scheduled.erase({delayed_event_due_ms(row), row.delay_id});
        book->second.finalised.erase({row.finalised_at_ms, row.delay_id});
        if (book->second.scheduled.empty() && book->second.finalised.empty())
        {
            m_users.erase(book);
        }
    }
    m_due.erase({delayed_event_due_ms(row), row.delay_id});
    m_finalised.erase({row.finalised_at_ms, row.delay_id});
    if (!row.txn_id.empty())
    {
        if (auto const found = m_by_transaction.find(transaction_key_of(row));
            found != m_by_transaction.end() && found->second == row.delay_id)
        {
            m_by_transaction.erase(found);
        }
    }
    if (!row.event_id.empty())
    {
        if (auto const found = m_by_event_id.find(row.event_id);
            found != m_by_event_id.end() && found->second == row.delay_id)
        {
            m_by_event_id.erase(found);
        }
    }
}

auto DelayedEventTable::insert(PersistentDelayedEvent row) -> bool
{
    // A second `sent` row for an event ID is refused like a duplicate transaction key: the index would name only the
    // first, and erasing it would orphan the second.
    if (m_rows.contains(row.delay_id) || (!row.txn_id.empty() && m_by_transaction.contains(transaction_key_of(row))) ||
        (row.status == DelayedEventStatus::sent && m_by_event_id.contains(row.event_id)))
    {
        return false;
    }
    auto key = row.delay_id;
    auto const [position, inserted] = m_rows.emplace(std::move(key), std::move(row));
    if (inserted)
    {
        index_row(position->second);
    }
    return inserted;
}

auto DelayedEventTable::restart(std::string_view delay_id, std::uint64_t delayed_since_ms) -> bool
{
    auto const found = m_rows.find(delay_id);
    if (found == m_rows.end() || found->second.status != DelayedEventStatus::scheduled)
    {
        return false;
    }
    unindex_row(found->second);
    found->second.delayed_since_ms = delayed_since_ms;
    index_row(found->second);
    return true;
}

auto DelayedEventTable::finalise(std::string_view delay_id, DelayedEventStatus status, std::uint64_t finalised_at_ms,
                                 std::string event_id, std::string error_json) -> bool
{
    auto const found = m_rows.find(delay_id);
    if (found == m_rows.end() || found->second.status != DelayedEventStatus::scheduled ||
        status == DelayedEventStatus::scheduled)
    {
        return false;
    }
    unindex_row(found->second);
    m_being_sent.erase(found->first);
    found->second.status = status;
    found->second.finalised_at_ms = finalised_at_ms;
    found->second.event_id = std::move(event_id);
    found->second.error_json = std::move(error_json);
    index_row(found->second);
    return true;
}

auto DelayedEventTable::erase(std::string_view delay_id) -> bool
{
    auto const found = m_rows.find(delay_id);
    if (found == m_rows.end())
    {
        return false;
    }
    unindex_row(found->second);
    m_being_sent.erase(found->first);
    m_rows.erase(found);
    return true;
}

auto DelayedEventTable::erase_user(std::string_view user_id) -> std::size_t
{
    auto const book = m_users.find(user_id);
    if (book == m_users.end())
    {
        return 0U;
    }
    auto ids = std::vector<std::string>{};
    ids.reserve(book->second.scheduled.size() + book->second.finalised.size());
    for (auto const& [when, delay_id] : book->second.scheduled)
    {
        ids.push_back(delay_id);
    }
    for (auto const& [when, delay_id] : book->second.finalised)
    {
        ids.push_back(delay_id);
    }
    for (auto const& delay_id : ids)
    {
        std::ignore = erase(delay_id);
    }
    return ids.size();
}

auto DelayedEventTable::mark_being_sent(std::string_view delay_id) -> bool
{
    auto const found = m_rows.find(delay_id);
    if (found == m_rows.end() || found->second.status != DelayedEventStatus::scheduled ||
        m_being_sent.contains(delay_id))
    {
        return false;
    }
    m_due.erase({delayed_event_due_ms(found->second), found->second.delay_id});
    m_being_sent.emplace(found->second.delay_id, true);
    return true;
}

auto DelayedEventTable::clear_being_sent(std::string_view delay_id) -> bool
{
    auto const marked = m_being_sent.find(delay_id);
    if (marked == m_being_sent.end())
    {
        return false;
    }
    m_being_sent.erase(marked);
    if (auto const found = m_rows.find(delay_id);
        found != m_rows.end() && found->second.status == DelayedEventStatus::scheduled)
    {
        m_due.insert({delayed_event_due_ms(found->second), found->second.delay_id});
    }
    return true;
}

auto DelayedEventTable::clear() noexcept -> void
{
    m_rows.clear();
    m_users.clear();
    m_due.clear();
    m_finalised.clear();
    m_by_transaction.clear();
    m_by_event_id.clear();
    m_being_sent.clear();
}

} // namespace merovingian::database
