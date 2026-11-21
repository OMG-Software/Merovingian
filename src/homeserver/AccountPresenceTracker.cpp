// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/AccountPresenceTracker.hpp"

#include <algorithm>
#include <limits>

namespace merovingian::homeserver
{
namespace
{

    // True when a device last seen at `seen_at_ms` still speaks for its account at `now_ms`. A time ahead of `now_ms`
    // (which the clock does not produce) counts as just seen.
    [[nodiscard]] auto device_is_fresh(std::int64_t seen_at_ms, std::int64_t now_ms) noexcept -> bool
    {
        return now_ms <= seen_at_ms || now_ms - seen_at_ms < AccountPresenceTracker::device_fresh_ms;
    }

    // True when a window started at `changed_at_ms` has ended at `now_ms`.
    [[nodiscard]] auto window_has_ended(std::optional<std::int64_t> changed_at_ms, std::int64_t now_ms) noexcept -> bool
    {
        return !changed_at_ms.has_value() ||
               (now_ms > *changed_at_ms && now_ms - *changed_at_ms >= AccountPresenceTracker::change_window_ms);
    }

    // `at_ms + by_ms`, held at the largest value instead of overflowing.
    [[nodiscard]] auto saturating_after(std::int64_t at_ms, std::int64_t by_ms) noexcept -> std::int64_t
    {
        return at_ms > std::numeric_limits<std::int64_t>::max() - by_ms ? std::numeric_limits<std::int64_t>::max()
                                                                        : at_ms + by_ms;
    }

} // namespace

auto AccountPresenceTracker::refile(Accounts::iterator entry, std::int64_t now_ms) -> void
{
    auto& account = entry->second;
    // The account matters until its latest device is stale and its window has ended; with neither, it is done now.
    auto expires_at_ms = now_ms;
    for (auto const& held : account.devices)
    {
        expires_at_ms = std::max(expires_at_ms, saturating_after(held.seen_at_ms, device_fresh_ms));
    }
    if (account.changed_at_ms.has_value())
    {
        expires_at_ms = std::max(expires_at_ms, saturating_after(*account.changed_at_ms, change_window_ms));
    }
    if (expires_at_ms == account.expires_at_ms)
    {
        return;
    }
    m_by_expiry.erase(ExpiryKey{account.expires_at_ms, entry->first});
    account.expires_at_ms = expires_at_ms;
    m_by_expiry.emplace(expires_at_ms, entry->first);
}

auto AccountPresenceTracker::has_expired_account(std::int64_t now_ms) const noexcept -> bool
{
    return !m_by_expiry.empty() && m_by_expiry.begin()->first <= now_ms;
}

auto AccountPresenceTracker::account_for(std::string_view user, std::int64_t now_ms) -> Accounts::iterator
{
    if (auto const found = m_accounts.find(user); found != m_accounts.end())
    {
        return found;
    }
    if (m_accounts.size() >= max_accounts)
    {
        prune(now_ms);
        if (m_accounts.size() >= max_accounts)
        {
            return m_accounts.end();
        }
    }
    auto const made = m_accounts.try_emplace(std::string{user}).first;
    made->second.expires_at_ms = now_ms;
    m_by_expiry.emplace(now_ms, made->first);
    return made;
}

auto AccountPresenceTracker::note_sync(std::string_view user, std::string_view device, bool online, std::int64_t now_ms)
    -> bool
{
    auto const entry = account_for(user, now_ms);
    if (entry == m_accounts.end())
    {
        return online;
    }
    auto& devices = entry->second.devices;
    // A stale device speaks for nothing; dropping it here keeps an account that keeps syncing from holding them.
    std::erase_if(devices, [now_ms](Device const& held) {
        return !device_is_fresh(held.seen_at_ms, now_ms);
    });
    auto const same_device = [device](Device const& held) {
        return held.id == device;
    };
    if (auto const held = std::ranges::find_if(devices, same_device); held != devices.end())
    {
        held->seen_at_ms = now_ms;
        held->online = online;
    }
    else
    {
        if (devices.size() >= max_devices_per_account)
        {
            auto const oldest = std::ranges::min_element(devices, std::ranges::less{}, &Device::seen_at_ms);
            devices.erase(oldest);
        }
        devices.push_back(Device{std::string{device}, now_ms, online});
    }
    refile(entry, now_ms);
    return std::ranges::any_of(devices, [](Device const& held) {
        return held.online;
    });
}

auto AccountPresenceTracker::forget_device(std::string_view user, std::string_view device) -> void
{
    auto const found = m_accounts.find(user);
    if (found == m_accounts.end())
    {
        return;
    }
    std::erase_if(found->second.devices, [device](Device const& held) {
        return held.id == device;
    });
    // The account may now expire sooner; it is never kept past its old time, and a prune judges it by the new one.
    refile(found, std::numeric_limits<std::int64_t>::min());
}

auto AccountPresenceTracker::change_blocked_for_ms(std::string_view user, std::int64_t now_ms) const
    -> std::optional<std::int64_t>
{
    auto const found = m_accounts.find(user);
    if (found == m_accounts.end())
    {
        // No window to wait for, unless there is no room to start one: then the change is refused (fails closed).
        auto const no_room = m_accounts.size() >= max_accounts && !has_expired_account(now_ms);
        return no_room ? std::optional<std::int64_t>{change_window_ms} : std::nullopt;
    }
    auto const changed_at_ms = found->second.changed_at_ms;
    if (!changed_at_ms.has_value() || window_has_ended(changed_at_ms, now_ms))
    {
        return std::nullopt;
    }
    auto const started_ms = changed_at_ms.value();
    // A start ahead of `now_ms` (which the clock does not produce) is waited for in full, never longer.
    auto const elapsed = now_ms > started_ms ? now_ms - started_ms : std::int64_t{0};
    return change_window_ms - elapsed;
}

auto AccountPresenceTracker::note_change(std::string_view user, std::int64_t now_ms) -> void
{
    if (auto const entry = account_for(user, now_ms); entry != m_accounts.end())
    {
        entry->second.changed_at_ms = now_ms;
        refile(entry, now_ms);
    }
}

auto AccountPresenceTracker::prune(std::int64_t now_ms) -> void
{
    while (has_expired_account(now_ms))
    {
        auto const soonest = m_by_expiry.begin();
        ++m_accounts_examined;
        m_accounts.erase(soonest->second);
        m_by_expiry.erase(soonest);
    }
}

auto AccountPresenceTracker::account_count() const noexcept -> std::size_t
{
    return m_accounts.size();
}

auto AccountPresenceTracker::accounts_examined() const noexcept -> std::uint64_t
{
    return m_accounts_examined;
}

} // namespace merovingian::homeserver
