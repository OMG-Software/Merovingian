// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/SlidingSyncConnectionTable.hpp"

namespace merovingian::sync
{

auto SlidingSyncConnectionTable::touch(std::string const& key, std::chrono::steady_clock::time_point now)
    -> SlidingSyncConnectionState&
{
    auto const [it, inserted] = m_states.try_emplace(key);
    if (!inserted)
    {
        m_by_last_used.erase({it->second.last_used, key});
    }
    it->second.last_used = now;
    m_by_last_used.emplace(now, key);
    return it->second;
}

auto SlidingSyncConnectionTable::erase(std::string const& key) -> void
{
    auto const it = m_states.find(key);
    if (it == m_states.end())
    {
        return;
    }
    m_by_last_used.erase({it->second.last_used, key});
    m_states.erase(it);
}

auto SlidingSyncConnectionTable::erase_idle(std::chrono::steady_clock::time_point now,
                                            std::chrono::steady_clock::duration ttl) -> void
{
    while (!m_by_last_used.empty())
    {
        ++m_idle_entries_visited;
        auto const oldest = m_by_last_used.begin();
        if (now - oldest->first <= ttl)
        {
            return;
        }
        m_states.erase(oldest->second);
        m_by_last_used.erase(oldest);
    }
}

auto SlidingSyncConnectionTable::contains(std::string const& key) const -> bool
{
    return m_states.contains(key);
}

auto SlidingSyncConnectionTable::size() const noexcept -> std::size_t
{
    return m_states.size();
}

auto SlidingSyncConnectionTable::empty() const noexcept -> bool
{
    return m_states.empty();
}

auto SlidingSyncConnectionTable::states() const noexcept -> std::map<std::string, SlidingSyncConnectionState> const&
{
    return m_states;
}

auto SlidingSyncConnectionTable::idle_entries_visited() const noexcept -> std::uint64_t
{
    return m_idle_entries_visited;
}

auto SlidingSyncConnectionTable::index_size() const noexcept -> std::size_t
{
    return m_by_last_used.size();
}

} // namespace merovingian::sync
