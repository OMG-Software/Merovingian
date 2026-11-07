// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/LoginTokenStore.hpp"

#include "merovingian/crypto/constant_time.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace merovingian::homeserver
{

auto LoginTokenStore::sweep(std::uint64_t now_ms) -> void
{
    std::erase_if(m_entries, [now_ms](Entry const& entry) {
        return entry.expires_at_ms <= now_ms;
    });
}

auto LoginTokenStore::issue(std::string_view user_id, std::string token_hash, std::uint64_t now_ms,
                            std::uint64_t lifetime_ms, std::size_t per_user_cap, std::size_t total_cap) -> IssueResult
{
    sweep(now_ms);
    auto user_count = std::size_t{0U};
    auto soonest_for_user = std::numeric_limits<std::uint64_t>::max();
    auto soonest_overall = std::numeric_limits<std::uint64_t>::max();
    for (auto const& entry : m_entries)
    {
        soonest_overall = std::min(soonest_overall, entry.expires_at_ms);
        if (entry.user_id == user_id)
        {
            ++user_count;
            soonest_for_user = std::min(soonest_for_user, entry.expires_at_ms);
        }
    }
    if (user_count >= per_user_cap)
    {
        return {IssueOutcome::user_cap_reached, soonest_for_user - now_ms};
    }
    if (m_entries.size() >= total_cap)
    {
        return {IssueOutcome::total_cap_reached, soonest_overall - now_ms};
    }
    m_entries.push_back({std::string{user_id}, std::move(token_hash), now_ms + lifetime_ms});
    return {IssueOutcome::issued, 0U};
}

auto LoginTokenStore::redeem(std::string_view token_hash, std::uint64_t now_ms) -> std::optional<std::string>
{
    sweep(now_ms);
    // Visit every entry whatever matched, so the work does not depend on which token (if any) was offered.
    auto matched = m_entries.size();
    for (auto index = std::size_t{0U}; index < m_entries.size(); ++index)
    {
        if (crypto::constant_time_equal(m_entries[index].token_hash, token_hash))
        {
            matched = index;
        }
    }
    if (matched == m_entries.size())
    {
        return std::nullopt;
    }
    auto user_id = std::move(m_entries[matched].user_id);
    m_entries.erase(m_entries.begin() + static_cast<std::ptrdiff_t>(matched));
    return user_id;
}

auto LoginTokenStore::erase_user(std::string_view user_id) -> void
{
    std::erase_if(m_entries, [user_id](Entry const& entry) {
        return entry.user_id == user_id;
    });
}

auto LoginTokenStore::size() const noexcept -> std::size_t
{
    return m_entries.size();
}

auto LoginTokenStore::count_for_user(std::string_view user_id) const noexcept -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(m_entries, [user_id](Entry const& entry) {
        return entry.user_id == user_id;
    }));
}

} // namespace merovingian::homeserver
