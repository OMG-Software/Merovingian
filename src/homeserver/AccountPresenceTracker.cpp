// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/AccountPresenceTracker.hpp"

#include <algorithm>
#include <iterator>

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

} // namespace

auto AccountPresenceTracker::account_for(std::string_view user, std::int64_t now_ms) -> Account*
{
    if (auto const found = m_accounts.find(user); found != m_accounts.end())
    {
        return &found->second;
    }
    if (m_accounts.size() >= max_accounts)
    {
        prune(now_ms);
        if (m_accounts.size() >= max_accounts)
        {
            return nullptr;
        }
    }
    return &m_accounts.try_emplace(std::string{user}).first->second;
}

auto AccountPresenceTracker::note_sync(std::string_view user, std::string_view device, bool online, std::int64_t now_ms)
    -> bool
{
    auto* const account = account_for(user, now_ms);
    if (account == nullptr)
    {
        return online;
    }
    auto& devices = account->devices;
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
    return std::ranges::any_of(devices, [now_ms](Device const& held) {
        return held.online && device_is_fresh(held.seen_at_ms, now_ms);
    });
}

auto AccountPresenceTracker::forget_device(std::string_view user, std::string_view device) -> void
{
    if (auto const found = m_accounts.find(user); found != m_accounts.end())
    {
        std::erase_if(found->second.devices, [device](Device const& held) {
            return held.id == device;
        });
    }
}

auto AccountPresenceTracker::change_blocked_for_ms(std::string_view user, std::int64_t now_ms) const
    -> std::optional<std::int64_t>
{
    auto const found = m_accounts.find(user);
    if (found == m_accounts.end())
    {
        // No window to wait for, unless there is no room to start one: then the change is refused (fails closed).
        return m_accounts.size() >= max_accounts ? std::optional<std::int64_t>{change_window_ms} : std::nullopt;
    }
    auto const changed_at_ms = found->second.changed_at_ms;
    if (window_has_ended(changed_at_ms, now_ms))
    {
        return std::nullopt;
    }
    // A start ahead of `now_ms` (which the clock does not produce) is waited for in full, never longer.
    auto const elapsed = now_ms > *changed_at_ms ? now_ms - *changed_at_ms : std::int64_t{0};
    return change_window_ms - elapsed;
}

auto AccountPresenceTracker::note_change(std::string_view user, std::int64_t now_ms) -> void
{
    if (auto* const account = account_for(user, now_ms); account != nullptr)
    {
        account->changed_at_ms = now_ms;
    }
}

auto AccountPresenceTracker::prune(std::int64_t now_ms) -> void
{
    for (auto entry = m_accounts.begin(); entry != m_accounts.end();)
    {
        auto& account = entry->second;
        std::erase_if(account.devices, [now_ms](Device const& held) {
            return !device_is_fresh(held.seen_at_ms, now_ms);
        });
        if (account.devices.empty() && window_has_ended(account.changed_at_ms, now_ms))
        {
            entry = m_accounts.erase(entry);
        }
        else
        {
            entry = std::next(entry);
        }
    }
}

auto AccountPresenceTracker::account_count() const noexcept -> std::size_t
{
    return m_accounts.size();
}

} // namespace merovingian::homeserver
