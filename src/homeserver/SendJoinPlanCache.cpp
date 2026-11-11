// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/SendJoinPlanCache.hpp"

#include <iterator>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto entry_key(std::string_view room_id, bool omit_members) -> std::string
    {
        auto key = std::string{room_id};
        key.push_back(omit_members ? '\1' : '\0');
        return key;
    }

    [[nodiscard]] auto membership_key(std::string_view room_id, std::string_view join_event_id) -> std::string
    {
        auto key = std::string{room_id};
        key.push_back('\0');
        key.append(join_event_id);
        return key;
    }

} // namespace

SendJoinPlanCache::SendJoinPlanCache(std::size_t max_entries, std::uint64_t max_bytes,
                                     std::size_t max_memberships_before) noexcept
    : m_max_entries{max_entries}
    , m_max_bytes{max_bytes}
    , m_max_memberships_before{max_memberships_before}
{
}

auto SendJoinPlanCache::drop_locked(EntryList::iterator position) -> void
{
    m_bytes -= position->bytes;
    m_index.erase(position->key);
    m_entries.erase(position);
}

auto SendJoinPlanCache::with_base(std::string_view room_id, bool omit_members, SendJoinPlanStamp const& stamp,
                                  StillValid const& still_valid, Build const& build, Use const& use) -> void
{
    auto const lock = std::lock_guard{m_mutex};
    auto key = entry_key(room_id, omit_members);
    if (auto const found = m_index.find(key); found != m_index.end())
    {
        if (found->second->stamp == stamp && still_valid(found->second->base))
        {
            m_entries.splice(m_entries.begin(), m_entries, found->second);
            use(m_entries.front().base);
            return;
        }
        drop_locked(found->second);
    }

    auto base = build();
    ++m_builds;
    auto const size = base.estimated_bytes();
    if (size > m_max_bytes || m_max_entries == 0U)
    {
        use(base);
        return;
    }
    while (!m_entries.empty() && (m_entries.size() >= m_max_entries || m_bytes + size > m_max_bytes))
    {
        drop_locked(std::prev(m_entries.end()));
    }
    m_entries.push_front(Entry{key, stamp, std::move(base), size});
    m_index.emplace(std::move(key), m_entries.begin());
    m_bytes += size;
    use(m_entries.front().base);
}

auto SendJoinPlanCache::known_not_to_fit(std::string_view room_id, bool omit_members, SendJoinPlanStamp const& stamp)
    -> bool
{
    auto const lock = std::lock_guard{m_mutex};
    auto const found = m_index.find(entry_key(room_id, omit_members));
    return found != m_index.end() && found->second->stamp == stamp && found->second->base.sizes_only;
}

auto SendJoinPlanCache::membership_before(std::string_view room_id, std::string_view join_event_id)
    -> std::optional<std::string>
{
    auto const lock = std::lock_guard{m_mutex};
    auto const found = m_memberships_before.find(membership_key(room_id, join_event_id));
    if (found == m_memberships_before.end())
    {
        return std::nullopt;
    }
    return found->second;
}

auto SendJoinPlanCache::remember_membership_before(std::string_view room_id, std::string_view join_event_id,
                                                   std::string_view membership_event_id) -> void
{
    auto const lock = std::lock_guard{m_mutex};
    if (m_max_memberships_before == 0U)
    {
        return;
    }
    auto key = membership_key(room_id, join_event_id);
    if (!m_memberships_before.emplace(key, std::string{membership_event_id}).second)
    {
        return;
    }
    m_memberships_order.push_back(std::move(key));
    while (m_memberships_order.size() > m_max_memberships_before)
    {
        m_memberships_before.erase(m_memberships_order.front());
        m_memberships_order.pop_front();
    }
}

auto SendJoinPlanCache::builds() const -> std::uint64_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_builds;
}

auto SendJoinPlanCache::entries() const -> std::size_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_entries.size();
}

auto SendJoinPlanCache::bytes() const -> std::uint64_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_bytes;
}

} // namespace merovingian::homeserver
