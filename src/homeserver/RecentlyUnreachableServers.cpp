// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RecentlyUnreachableServers.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace merovingian::homeserver
{

RecentlyUnreachableServers::RecentlyUnreachableServers(Clock::duration ttl, std::size_t capacity) noexcept
    : m_ttl{ttl}
    , m_capacity{capacity}
{
}

auto RecentlyUnreachableServers::contains(std::string_view server, Clock::time_point now) const -> bool
{
    auto const found = m_failed_at.find(std::string{server});
    return found != m_failed_at.end() && now - found->second < m_ttl;
}

auto RecentlyUnreachableServers::remember(std::string_view server, Clock::time_point now) -> void
{
    if (m_capacity == 0U)
    {
        return;
    }
    auto key = std::string{server};
    if (auto const found = m_failed_at.find(key); found != m_failed_at.end())
    {
        found->second = now;
        return;
    }
    make_room(now);
    m_failed_at.emplace(std::move(key), now);
}

auto RecentlyUnreachableServers::forget(std::string_view server) -> void
{
    m_failed_at.erase(std::string{server});
}

auto RecentlyUnreachableServers::size() const noexcept -> std::size_t
{
    return m_failed_at.size();
}

// Leaves room for one more entry. The scan is linear in `capacity`; it runs only on a lookup that has already spent
// a client outbound slot and failed, so it is bounded by that admission.
auto RecentlyUnreachableServers::make_room(Clock::time_point now) -> void
{
    if (m_failed_at.size() < m_capacity)
    {
        return;
    }
    std::erase_if(m_failed_at, [&](auto const& entry) {
        return now - entry.second >= m_ttl;
    });
    if (m_failed_at.size() < m_capacity)
    {
        return;
    }
    auto const oldest = std::ranges::min_element(m_failed_at, {}, [](auto const& entry) {
        return entry.second;
    });
    m_failed_at.erase(oldest);
}

} // namespace merovingian::homeserver
