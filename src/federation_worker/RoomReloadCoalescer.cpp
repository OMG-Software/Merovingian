// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation_worker/RoomReloadCoalescer.hpp"

#include "merovingian/observability/SingleLog.hpp"

#include <algorithm>
#include <exception>

namespace merovingian::federation_worker
{

auto RoomReloadCoalescer::note_changed(std::string_view room_id, std::uint64_t generation) -> bool
{
    auto const lock = std::lock_guard{m_mutex};
    if (auto const found = m_rooms.find(room_id); found != m_rooms.end())
    {
        found->second.newest_generation = std::max(found->second.newest_generation, generation);
        found->second.dirty = true;
        return false;
    }
    m_rooms.emplace(std::string{room_id}, Scheduled{generation, true});
    return true;
}

auto RoomReloadCoalescer::run_round(std::string const& room_id, std::function<void(std::uint64_t)> const& reload)
    -> bool
{
    auto generation = std::uint64_t{0U};
    {
        auto const lock = std::lock_guard{m_mutex};
        auto const found = m_rooms.find(room_id);
        if (found == m_rooms.end())
        {
            return false;
        }
        // Cleared before the read begins: see the invariant in the header.
        found->second.dirty = false;
        generation = found->second.newest_generation;
    }

    try
    {
        reload(generation);
    }
    catch (std::exception const& error)
    {
        LOG_WARNING("Federation worker: room reload threw for room_id=" + room_id + ": " + error.what());
    }
    catch (...)
    {
        LOG_WARNING("Federation worker: room reload threw for room_id=" + room_id);
    }

    auto const lock = std::lock_guard{m_mutex};
    auto const found = m_rooms.find(room_id);
    if (found == m_rooms.end())
    {
        return false;
    }
    if (found->second.dirty)
    {
        return true;
    }
    m_rooms.erase(found);
    return false;
}

auto RoomReloadCoalescer::abandon(std::string_view room_id) -> void
{
    auto const lock = std::lock_guard{m_mutex};
    if (auto const found = m_rooms.find(room_id); found != m_rooms.end())
    {
        m_rooms.erase(found);
    }
}

auto RoomReloadCoalescer::scheduled_rooms() const -> std::size_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_rooms.size();
}

} // namespace merovingian::federation_worker
