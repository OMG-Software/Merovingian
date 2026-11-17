// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/LiveKitDelegationTable.hpp"

#include <algorithm>
#include <utility>

namespace merovingian::database
{
namespace
{

    // A key made of the parts separated by NUL, which a storable row never holds, so two different tuples never make
    // the same key.
    [[nodiscard]] auto delegation_key(std::string_view user_id, std::string_view room_id, std::string_view slot_id,
                                      std::string_view member_id) -> std::string
    {
        auto key = std::string{user_id};
        for (auto const part : {room_id, slot_id, member_id})
        {
            key.push_back('\0');
            key.append(part);
        }
        return key;
    }

    [[nodiscard]] auto has_nul(std::string_view value) noexcept -> bool
    {
        return value.find('\0') != std::string_view::npos;
    }

    [[nodiscard]] auto field_is_storable(std::string_view value, std::size_t cap) noexcept -> bool
    {
        return !value.empty() && value.size() <= cap && !has_nul(value);
    }

} // namespace

auto livekit_delegation_is_storable(PersistentLiveKitDelegation const& row) noexcept -> bool
{
    return field_is_storable(row.delay_id, max_livekit_delegation_delay_id_bytes) &&
           field_is_storable(row.user_id, max_livekit_delegation_field_bytes) &&
           field_is_storable(row.room_id, max_livekit_delegation_field_bytes) &&
           field_is_storable(row.slot_id, max_livekit_delegation_field_bytes) &&
           field_is_storable(row.member_id, max_livekit_delegation_field_bytes);
}

auto LiveKitDelegationTable::find(std::string_view delay_id) const -> PersistentLiveKitDelegation const*
{
    auto const found = m_by_delay_id.find(delay_id);
    return found == m_by_delay_id.end() ? nullptr : &m_rows[found->second];
}

auto LiveKitDelegationTable::find_by_key(std::string_view user_id, std::string_view room_id, std::string_view slot_id,
                                         std::string_view member_id) const -> PersistentLiveKitDelegation const*
{
    auto const found = m_by_key.find(delegation_key(user_id, room_id, slot_id, member_id));
    return found == m_by_key.end() ? nullptr : &m_rows[found->second];
}

auto LiveKitDelegationTable::count_of_user(std::string_view user_id) const -> std::size_t
{
    auto const found = m_user_counts.find(user_id);
    return found == m_user_counts.end() ? 0U : found->second;
}

auto LiveKitDelegationTable::insert(PersistentLiveKitDelegation row) -> bool
{
    if (!livekit_delegation_is_storable(row) || m_by_delay_id.contains(row.delay_id))
    {
        return false;
    }
    auto key = delegation_key(row.user_id, row.room_id, row.slot_id, row.member_id);
    if (m_by_key.contains(key))
    {
        return false;
    }
    auto const position = m_rows.size();
    m_by_delay_id.emplace(row.delay_id, position);
    m_by_key.emplace(std::move(key), position);
    ++m_user_counts[row.user_id];
    m_rows.push_back(std::move(row));
    return true;
}

auto LiveKitDelegationTable::erase(std::string_view delay_id) -> bool
{
    auto const found = m_by_delay_id.find(delay_id);
    if (found == m_by_delay_id.end())
    {
        return false;
    }
    erase_at(found->second);
    return true;
}

auto LiveKitDelegationTable::erase_key(std::string_view user_id, std::string_view room_id, std::string_view slot_id,
                                       std::string_view member_id) -> bool
{
    auto const found = m_by_key.find(delegation_key(user_id, room_id, slot_id, member_id));
    if (found == m_by_key.end())
    {
        return false;
    }
    erase_at(found->second);
    return true;
}

auto LiveKitDelegationTable::erase_user(std::string_view user_id) -> std::size_t
{
    auto const removed = std::erase_if(m_rows, [user_id](PersistentLiveKitDelegation const& row) {
        return row.user_id == user_id;
    });
    if (removed != 0U)
    {
        reindex();
    }
    return removed;
}

auto LiveKitDelegationTable::clear() noexcept -> void
{
    m_rows.clear();
    m_by_delay_id.clear();
    m_by_key.clear();
    m_user_counts.clear();
}

auto LiveKitDelegationTable::erase_at(std::size_t position) -> void
{
    m_rows.erase(m_rows.begin() + static_cast<std::vector<PersistentLiveKitDelegation>::difference_type>(position));
    reindex();
}

auto LiveKitDelegationTable::reindex() -> void
{
    m_by_delay_id.clear();
    m_by_key.clear();
    m_user_counts.clear();
    for (auto position = std::size_t{0U}; position < m_rows.size(); ++position)
    {
        auto const& row = m_rows[position];
        m_by_delay_id.emplace(row.delay_id, position);
        m_by_key.emplace(delegation_key(row.user_id, row.room_id, row.slot_id, row.member_id), position);
        ++m_user_counts[row.user_id];
    }
}

} // namespace merovingian::database
