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

AccountPresenceTracker::AccountPresenceTracker(std::size_t account_cap) noexcept
    : m_account_cap{std::max(account_cap, std::size_t{1U})}
{
}

auto AccountPresenceTracker::refile(Accounts::iterator entry, std::int64_t now_ms) -> void
{
    auto& account = entry->second;
    auto const lowest = std::numeric_limits<std::int64_t>::min();
    auto const window_end_ms =
        account.changed_at_ms.has_value() ? saturating_after(*account.changed_at_ms, change_window_ms) : lowest;
    auto const window_open = window_end_ms > now_ms;
    // A closed account matters until its latest online device is stale and its window has ended. A device whose last
    // ask was unavailable speaks for nothing (`note_sync` answers from online devices only), so it never keeps an
    // account.
    auto filed_at_ms = window_end_ms;
    if (!window_open)
    {
        for (auto const& held : account.devices)
        {
            if (held.online)
            {
                filed_at_ms = std::max(filed_at_ms, saturating_after(held.seen_at_ms, device_fresh_ms));
            }
        }
    }
    (account.window_open ? m_open_windows : m_closed).erase(FiledKey{account.filed_at_ms, entry->first});
    account.window_open = window_open;
    account.filed_at_ms = filed_at_ms;
    (window_open ? m_open_windows : m_closed).emplace(filed_at_ms, entry->first);
}

auto AccountPresenceTracker::close_ended_windows(std::int64_t now_ms) -> void
{
    while (!m_open_windows.empty() && m_open_windows.begin()->first <= now_ms)
    {
        // Refiling erases this front entry, so the loop always moves on. Each visit counts, so a prune that closed
        // windows not yet ended would show in `accounts_examined`.
        ++m_accounts_examined;
        auto const ended = m_accounts.find(m_open_windows.begin()->second);
        if (ended == m_accounts.end())
        {
            m_open_windows.erase(m_open_windows.begin());
            continue;
        }
        refile(ended, now_ms);
    }
}

auto AccountPresenceTracker::has_room(std::int64_t now_ms) const noexcept -> bool
{
    return m_accounts.size() < m_account_cap || !m_closed.empty() ||
           (!m_open_windows.empty() && m_open_windows.begin()->first <= now_ms);
}

auto AccountPresenceTracker::account_for(std::string_view user, std::int64_t now_ms) -> Accounts::iterator
{
    if (auto const found = m_accounts.find(user); found != m_accounts.end())
    {
        return found;
    }
    if (m_accounts.size() >= m_account_cap)
    {
        prune(now_ms);
    }
    if (m_accounts.size() >= m_account_cap)
    {
        if (m_closed.empty())
        {
            // Every account has an open window: evicting one would lift its limit.
            return m_accounts.end();
        }
        // The account whose devices go stale soonest loses their holds; it has no window to lose.
        auto const evicted = m_closed.begin();
        ++m_accounts_examined;
        m_accounts.erase(evicted->second);
        m_closed.erase(evicted);
    }
    auto const made = m_accounts.try_emplace(std::string{user}).first;
    made->second.filed_at_ms = std::numeric_limits<std::int64_t>::min();
    m_closed.emplace(made->second.filed_at_ms, made->first);
    return made;
}

auto AccountPresenceTracker::note_sync(std::string_view user, std::string_view device, bool online, std::int64_t now_ms)
    -> bool
{
    // A device asking for unavailable holds nothing, so an account the table does not hold takes no place for it and
    // never evicts another account's hold to make one.
    auto const tracked = m_accounts.find(user);
    if (tracked == m_accounts.end() && !online)
    {
        return false;
    }
    auto const entry = tracked != m_accounts.end() ? tracked : account_for(user, now_ms);
    if (entry == m_accounts.end())
    {
        // No room (fails closed): nothing is recorded, so no device the table holds asks for anything.
        return false;
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

auto AccountPresenceTracker::forget_device(std::string_view user, std::string_view device, std::int64_t now_ms) -> void
{
    auto const found = m_accounts.find(user);
    if (found == m_accounts.end())
    {
        return;
    }
    std::erase_if(found->second.devices, [device](Device const& held) {
        return held.id == device;
    });
    refile(found, now_ms);
}

auto AccountPresenceTracker::change_blocked_for_ms(std::string_view user, std::int64_t now_ms) const
    -> std::optional<std::int64_t>
{
    auto const found = m_accounts.find(user);
    if (found == m_accounts.end())
    {
        // No window to wait for, unless there is no room to start one: then the change is refused (fails closed) until
        // the soonest window ends, which is later than now since every window is open.
        if (is_full_for(user, now_ms))
        {
            return m_open_windows.begin()->first - now_ms;
        }
        return std::nullopt;
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

auto AccountPresenceTracker::is_full_for(std::string_view user, std::int64_t now_ms) const -> bool
{
    return !has_room(now_ms) && !m_accounts.contains(user);
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
    close_ended_windows(now_ms);
    while (!m_closed.empty() && m_closed.begin()->first <= now_ms)
    {
        auto const soonest = m_closed.begin();
        ++m_accounts_examined;
        m_accounts.erase(soonest->second);
        m_closed.erase(soonest);
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

auto AccountPresenceTracker::account_cap() const noexcept -> std::size_t
{
    return m_account_cap;
}

auto AccountPresenceTracker::note_full_refusal(std::int64_t now_ms) -> std::optional<std::uint64_t>
{
    ++m_full_refusals;
    if (m_full_warned_at_ms.has_value() && now_ms - m_full_warned_at_ms.value() < full_warning_interval_ms)
    {
        return std::nullopt;
    }
    auto const since_last_warning = m_full_refusals - m_full_refusals_warned;
    m_full_refusals_warned = m_full_refusals;
    m_full_warned_at_ms = now_ms;
    return since_last_warning;
}

auto AccountPresenceTracker::full_refusals() const noexcept -> std::uint64_t
{
    return m_full_refusals;
}

} // namespace merovingian::homeserver
