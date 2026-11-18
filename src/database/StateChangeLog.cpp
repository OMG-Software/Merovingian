// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/database/StateChangeLog.hpp"

#include <algorithm>
#include <limits>

namespace merovingian::database
{

auto StateChangeLog::start(std::uint64_t floor) -> void
{
    m_active = true;
    m_floor = floor;
    m_served = floor;
    m_rooms.clear();
    m_order.clear();
}

auto StateChangeLog::active() const noexcept -> bool
{
    return m_active;
}

auto StateChangeLog::note_served(std::uint64_t position) noexcept -> void
{
    m_served = std::max(m_served, position);
}

auto StateChangeLog::forget_room(std::string_view room_id) -> void
{
    if (!m_active)
    {
        return;
    }
    auto& room = m_rooms[std::string{room_id}];
    for (auto const& entry : room.changes)
    {
        m_order.erase(entry.first.second);
    }
    room.changes.clear();
    room.horizon = std::max(room.horizon, above_served());
}

auto StateChangeLog::record(std::string_view room_id, std::string_view event_type, std::string_view state_key,
                            std::string_view previous_event_id, std::string_view event_id,
                            std::uint64_t causing_position) -> void
{
    if (!m_active || previous_event_id == event_id)
    {
        return;
    }
    // Above every position a client has been answered at, so no answer already given is changed by this one; a
    // position past the last one representable is never served, and the change is filed there.
    auto const position = std::max(causing_position, above_served());
    auto const sequence = m_next_sequence++;
    auto const room = m_rooms.try_emplace(std::string{room_id}).first;
    room->second.changes.emplace(std::pair{position, sequence},
                                 Change{std::string{event_type}, std::string{state_key}, std::string{previous_event_id},
                                        std::string{event_id}, position});
    m_order.emplace(sequence, std::pair{room->first, position});
    if (room->second.changes.size() > max_changes_per_room)
    {
        drop_oldest_of_room(room->second);
    }
    while (m_order.size() > max_changes)
    {
        drop_oldest();
    }
}

auto StateChangeLog::covers(std::string_view room_id, std::uint64_t position) const -> bool
{
    if (!m_active || position <= m_floor)
    {
        return false;
    }
    auto const room = m_rooms.find(std::string{room_id});
    return room == m_rooms.end() || position >= room->second.horizon;
}

auto StateChangeLog::has_change_after(std::string_view room_id, std::uint64_t position) const -> bool
{
    auto const room = m_rooms.find(std::string{room_id});
    return room != m_rooms.end() && !room->second.changes.empty() &&
           room->second.changes.rbegin()->first.first > position;
}

auto StateChangeLog::changes_after(std::string_view room_id, std::uint64_t position) const -> std::vector<Change const*>
{
    auto found = std::vector<Change const*>{};
    auto const room = m_rooms.find(std::string{room_id});
    if (room == m_rooms.end() || position == std::numeric_limits<std::uint64_t>::max())
    {
        return found;
    }
    auto const& changes = room->second.changes;
    for (auto it = changes.lower_bound(std::pair{position + 1U, std::uint64_t{0U}}); it != changes.end(); ++it)
    {
        found.push_back(&it->second);
    }
    m_rows_examined.add(found.size());
    return found;
}

auto StateChangeLog::size() const noexcept -> std::size_t
{
    return m_order.size();
}

auto StateChangeLog::rows_examined() const noexcept -> ExaminedRows const&
{
    return m_rows_examined;
}

auto StateChangeLog::above_served() const noexcept -> std::uint64_t
{
    // A position past the last one representable is never served, and a change is filed there.
    return m_served == std::numeric_limits<std::uint64_t>::max() ? m_served : m_served + 1U;
}

auto StateChangeLog::drop_oldest_of_room(RoomChanges& room) -> void
{
    auto const oldest = room.changes.begin();
    room.horizon = std::max(room.horizon, oldest->first.first);
    m_order.erase(oldest->first.second);
    room.changes.erase(oldest);
}

auto StateChangeLog::drop_oldest() -> void
{
    auto const oldest = m_order.begin();
    auto const& [room_id, position] = oldest->second;
    if (auto const room = m_rooms.find(room_id); room != m_rooms.end())
    {
        room->second.horizon = std::max(room->second.horizon, position);
        room->second.changes.erase(std::pair{position, oldest->first});
    }
    m_order.erase(oldest);
}

} // namespace merovingian::database
