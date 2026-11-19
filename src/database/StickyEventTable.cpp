// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/StickyEventTable.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::database
{
namespace
{

    [[nodiscard]] auto field_is_storable(std::string_view value) noexcept -> bool
    {
        return !value.empty() && value.size() <= max_sticky_event_field_bytes &&
               value.find('\0') == std::string_view::npos;
    }

    // The first key of `ordering` whose expiry is after `now_ms`; every key before it is expired. Event IDs are never
    // empty, so the key (now_ms + 1, "") sorts before every key that expires after `now_ms`.
    template <typename Ordering>
    [[nodiscard]] auto first_unexpired(Ordering const& ordering, std::int64_t now_ms)
    {
        if (now_ms == std::numeric_limits<std::int64_t>::max())
        {
            return ordering.end();
        }
        return ordering.lower_bound({now_ms + 1, std::string{}});
    }

} // namespace

auto sticky_event_is_storable(PersistentStickyEvent const& row) noexcept -> bool
{
    return field_is_storable(row.event_id) && field_is_storable(row.room_id) && field_is_storable(row.sender) &&
           row.received_at_ms >= 0 && row.expires_at_ms >= 0;
}

auto StickyEventTable::find(std::string_view event_id, std::int64_t now_ms) const -> PersistentStickyEvent const*
{
    auto const found = m_rows.find(event_id);
    if (found == m_rows.end())
    {
        return nullptr;
    }
    m_rows_examined.add(1U);
    return found->second.expires_at_ms > now_ms ? &found->second : nullptr;
}

auto StickyEventTable::contains(std::string_view event_id) const -> bool
{
    return m_rows.contains(event_id);
}

auto StickyEventTable::unexpired_of_room(std::string_view room_id, std::int64_t now_ms) const
    -> std::vector<PersistentStickyEvent const*>
{
    auto rows = std::vector<PersistentStickyEvent const*>{};
    auto const book = m_by_room.find(room_id);
    if (book == m_by_room.end())
    {
        return rows;
    }
    for (auto key = first_unexpired(book->second, now_ms); key != book->second.end(); ++key)
    {
        rows.push_back(&m_rows.find(key->second)->second);
    }
    m_rows_examined.add(rows.size());
    return rows;
}

auto StickyEventTable::unexpired_count_of_sender(std::string_view sender, std::int64_t now_ms) const -> std::size_t
{
    auto const book = m_by_sender.find(sender);
    if (book == m_by_sender.end())
    {
        return 0U;
    }
    // Only the expired rows at the front are walked; the unexpired rest is counted by subtraction.
    auto expired = std::size_t{0U};
    auto const stop = first_unexpired(book->second, now_ms);
    for (auto key = book->second.begin(); key != stop; ++key)
    {
        ++expired;
    }
    m_rows_examined.add(expired);
    return book->second.size() - expired;
}

auto StickyEventTable::oldest_unexpired_of_sender(std::string_view sender, std::int64_t now_ms, std::size_t max) const
    -> std::vector<PersistentStickyEvent const*>
{
    auto rows = std::vector<PersistentStickyEvent const*>{};
    auto const book = m_by_sender.find(sender);
    if (book == m_by_sender.end())
    {
        return rows;
    }
    auto walked = std::size_t{0U};
    for (auto key = first_unexpired(book->second, now_ms); key != book->second.end() && rows.size() < max; ++key)
    {
        rows.push_back(&m_rows.find(key->second)->second);
        ++walked;
    }
    m_rows_examined.add(walked);
    return rows;
}

auto StickyEventTable::expired_at(std::int64_t now_ms, std::size_t max) const
    -> std::vector<PersistentStickyEvent const*>
{
    auto rows = std::vector<PersistentStickyEvent const*>{};
    for (auto key = m_by_expiry.begin(); key != m_by_expiry.end() && key->first <= now_ms && rows.size() < max; ++key)
    {
        rows.push_back(&m_rows.find(key->second)->second);
    }
    m_rows_examined.add(rows.size());
    return rows;
}

auto StickyEventTable::insert(PersistentStickyEvent row) -> bool
{
    if (!sticky_event_is_storable(row) || m_rows.contains(row.event_id))
    {
        return false;
    }
    auto const key = OrderKey{row.expires_at_ms, row.event_id};
    m_by_room[row.room_id].insert(key);
    m_by_sender[row.sender].insert(key);
    m_by_expiry.insert(key);
    auto event_id = row.event_id;
    m_rows.emplace(std::move(event_id), std::move(row));
    return true;
}

auto StickyEventTable::unindex(PersistentStickyEvent const& row) -> void
{
    auto const key = OrderKey{row.expires_at_ms, row.event_id};
    m_by_expiry.erase(key);
    auto const drop = [&key](KeyedBy<Ordering>& index, std::string const& owner) {
        if (auto const book = index.find(owner); book != index.end())
        {
            book->second.erase(key);
            if (book->second.empty())
            {
                index.erase(book);
            }
        }
    };
    drop(m_by_room, row.room_id);
    drop(m_by_sender, row.sender);
}

auto StickyEventTable::erase(std::string_view event_id) -> bool
{
    auto const found = m_rows.find(event_id);
    if (found == m_rows.end())
    {
        return false;
    }
    unindex(found->second);
    m_rows.erase(found);
    return true;
}

auto StickyEventTable::erase_sender(std::string_view sender) -> std::size_t
{
    auto const book = m_by_sender.find(sender);
    return book == m_by_sender.end() ? 0U : erase_book(book->second);
}

auto StickyEventTable::erase_room(std::string_view room_id) -> std::size_t
{
    auto const book = m_by_room.find(room_id);
    return book == m_by_room.end() ? 0U : erase_book(book->second);
}

auto StickyEventTable::erase_book(Ordering const& book) -> std::size_t
{
    // Copy the IDs first: erasing unindexes the book being walked, and removes it once it is empty.
    auto ids = std::vector<std::string>{};
    ids.reserve(book.size());
    for (auto const& key : book)
    {
        ids.push_back(key.second);
    }
    for (auto const& id : ids)
    {
        std::ignore = erase(id);
    }
    return ids.size();
}

auto StickyEventTable::erase_expired(std::int64_t now_ms) -> std::size_t
{
    auto ids = std::vector<std::string>{};
    for (auto key = m_by_expiry.begin(); key != m_by_expiry.end() && key->first <= now_ms; ++key)
    {
        ids.push_back(key->second);
    }
    for (auto const& id : ids)
    {
        std::ignore = erase(id);
    }
    return ids.size();
}

auto StickyEventTable::clear() noexcept -> void
{
    m_rows.clear();
    m_by_room.clear();
    m_by_sender.clear();
    m_by_expiry.clear();
}

} // namespace merovingian::database
