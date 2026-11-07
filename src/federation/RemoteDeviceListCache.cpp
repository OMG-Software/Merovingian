// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/RemoteDeviceListCache.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::federation
{

auto RemoteDeviceListCache::begin_resync(std::string_view user_id) -> std::uint64_t
{
    auto entry = m_entries.find(user_id);
    if (entry == m_entries.end())
    {
        if (m_entries.size() >= max_users)
        {
            return 0U;
        }
        entry = m_entries.emplace(std::string{user_id}, Entry{}).first;
    }
    entry->second.stale = true;
    entry->second.ticket = ++m_last_ticket;
    return entry->second.ticket;
}

auto RemoteDeviceListCache::store_snapshot(std::string_view user_id, std::uint64_t ticket, RemoteDeviceList list)
    -> bool
{
    auto const entry = m_entries.find(user_id);
    if (ticket == 0U || entry == m_entries.end() || entry->second.ticket != ticket)
    {
        return false;
    }
    auto const stream_id = list.stream_id;
    entry->second.list = std::move(list);
    if (!account(entry))
    {
        drop(entry);
        return false;
    }
    entry->second.stale = false;
    entry->second.ticket = 0U;
    entry->second.snapshot_stream_id = stream_id;
    entry->second.applied.clear();
    return true;
}

auto RemoteDeviceListCache::apply_update(RemoteDeviceListUpdate const& update) -> RemoteDeviceListOutcome
{
    auto const entry = m_entries.find(update.user_id);
    if (entry == m_entries.end())
    {
        return RemoteDeviceListOutcome::uncached;
    }
    auto& held = entry->second;
    if (held.stale || !held.list.has_value())
    {
        // A fill in flight may have been answered before this update: do not keep it.
        held.ticket = 0U;
        return RemoteDeviceListOutcome::resync_needed;
    }
    // Already in the list: the snapshot covered it, or it was applied (a re-sent transaction).
    if (update.stream_id <= held.list->stream_id)
    {
        return RemoteDeviceListOutcome::unchanged;
    }
    // Spec: an update "which refers to a prev_id it does not recognise" means the list must be fetched again. Every
    // update up to the snapshot's stream_id is in the list; after it, only the applied ones are known. An empty
    // prev_id starts a new sequence, which says nothing about what this list has missed.
    auto const recognised = [&held](std::int64_t prev_id) {
        return prev_id <= held.snapshot_stream_id || std::ranges::find(held.applied, prev_id) != held.applied.end();
    };
    if (update.prev_ids.empty() || !std::ranges::all_of(update.prev_ids, recognised))
    {
        held.stale = true;
        return RemoteDeviceListOutcome::resync_needed;
    }

    auto& devices = held.list->devices;
    auto const existing = devices.find(update.device_id);
    auto changed = false;
    if (update.deleted)
    {
        if (existing != devices.end())
        {
            devices.erase(existing);
            changed = true;
        }
    }
    else if (existing == devices.end())
    {
        devices.emplace(update.device_id, update.device);
        changed = true;
    }
    else if (existing->second != update.device)
    {
        existing->second = update.device;
        changed = true;
    }
    held.list->stream_id = update.stream_id;
    held.applied.push_back(update.stream_id);
    if (held.applied.size() > remembered_stream_ids)
    {
        held.applied.erase(held.applied.begin());
    }
    if (changed && !account(entry))
    {
        // Over a cap: the list is no longer held, and the user is asked for on every query.
        drop(entry);
    }
    return changed ? RemoteDeviceListOutcome::changed : RemoteDeviceListOutcome::unchanged;
}

auto RemoteDeviceListCache::mark_stale(std::string_view user_id) -> void
{
    if (auto const entry = m_entries.find(user_id); entry != m_entries.end())
    {
        entry->second.stale = true;
        entry->second.ticket = 0U;
    }
}

auto RemoteDeviceListCache::erase(std::string_view user_id) -> void
{
    if (auto const entry = m_entries.find(user_id); entry != m_entries.end())
    {
        drop(entry);
    }
}

auto RemoteDeviceListCache::find_current(std::string_view user_id) const -> RemoteDeviceList const*
{
    auto const entry = m_entries.find(user_id);
    if (entry == m_entries.end() || entry->second.stale || !entry->second.list.has_value())
    {
        return nullptr;
    }
    return &*entry->second.list;
}

auto RemoteDeviceListCache::account(Entries::iterator entry) -> bool
{
    auto const& list = entry->second.list;
    auto const bytes = list.has_value() ? entry->first.size() + list->bytes() : 0U;
    if (list.has_value() && (list->devices.size() > max_devices_per_user || bytes > max_bytes_per_user))
    {
        return false;
    }
    auto const others = m_total_bytes - entry->second.bytes;
    if (others + bytes > max_total_bytes)
    {
        return false;
    }
    m_total_bytes = others + bytes;
    entry->second.bytes = bytes;
    return true;
}

auto RemoteDeviceListCache::drop(Entries::iterator entry) -> void
{
    m_total_bytes -= entry->second.bytes;
    m_entries.erase(entry);
}

} // namespace merovingian::federation
