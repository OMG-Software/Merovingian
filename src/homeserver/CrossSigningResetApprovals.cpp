// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/CrossSigningResetApprovals.hpp"

namespace merovingian::homeserver
{

auto CrossSigningResetApprovals::erase_expired(std::uint64_t now_ms) -> void
{
    while (!m_by_expiry.empty() && m_by_expiry.begin()->first <= now_ms)
    {
        auto const first = m_by_expiry.begin();
        if (auto const user = m_by_user.find(first->second); user != m_by_user.end())
        {
            m_by_user.erase(user);
        }
        m_by_expiry.erase(first);
    }
}

auto CrossSigningResetApprovals::withdraw(std::string_view user_id) -> void
{
    auto const user = m_by_user.find(user_id);
    if (user == m_by_user.end())
    {
        return;
    }
    m_by_expiry.erase(user->second.expiry);
    m_by_user.erase(user);
}

auto CrossSigningResetApprovals::record(std::string_view user_id, std::uint64_t expires_at_ms) -> void
{
    withdraw(user_id);
    auto const expiry = m_by_expiry.emplace(expires_at_ms, std::string{user_id});
    m_by_user.emplace(std::string{user_id}, Approval{expires_at_ms, expiry});
}

auto CrossSigningResetApprovals::approve(std::string_view user_id, std::uint64_t now_ms) -> bool
{
    if (user_id.empty())
    {
        return false;
    }
    erase_expired(now_ms);
    if (!m_by_user.contains(user_id) && m_by_user.size() >= max_approvals)
    {
        return false;
    }
    record(user_id, now_ms + lifetime_ms);
    return true;
}

auto CrossSigningResetApprovals::holds(std::string_view user_id, std::uint64_t now_ms) -> bool
{
    erase_expired(now_ms);
    return m_by_user.contains(user_id);
}

auto CrossSigningResetApprovals::take(std::string_view user_id, std::uint64_t now_ms) -> std::optional<std::uint64_t>
{
    erase_expired(now_ms);
    auto const user = m_by_user.find(user_id);
    if (user == m_by_user.end())
    {
        return std::nullopt;
    }
    auto const expires_at_ms = user->second.expires_at_ms;
    m_by_expiry.erase(user->second.expiry);
    m_by_user.erase(user);
    return expires_at_ms;
}

auto CrossSigningResetApprovals::restore(std::string_view user_id, std::uint64_t expires_at_ms, std::uint64_t now_ms)
    -> void
{
    erase_expired(now_ms);
    if (user_id.empty() || expires_at_ms <= now_ms || m_by_user.contains(user_id) || m_by_user.size() >= max_approvals)
    {
        return;
    }
    record(user_id, expires_at_ms);
}

auto CrossSigningResetApprovals::size() const noexcept -> std::size_t
{
    return m_by_user.size();
}

} // namespace merovingian::homeserver
