// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/StateGroupKeyHash.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

// What each local account's devices last asked of its presence through a sync's `set_presence`, and when the account's
// presence last changed. In memory only; every operation takes the time in milliseconds of a clock that never goes back
// (`presence_limit_clock_ms`).
//
// Devices (ADR-0871): a device that syncs `online` holds its account online for `device_fresh_ms`, so another device
// syncing `unavailable` in that time does not set the account unavailable. Two clients of one account, one in the
// foreground and one in the background, otherwise set the presence back and forth on every sync.
//
// Changes (ADR-0872): the first change of an account's presence starts a window of `change_window_ms`; every other
// change asked for in the window is dropped (a sync) or refused with 429 (`PUT /presence`). The first one asked for is
// the one kept, never the last.
//
// Bounded: at most `max_accounts` accounts of `max_devices_per_account` devices each. A new device past the device cap
// replaces the account's least recently seen one. Each account is filed under the time it stops mattering (its last
// online device stale and its window ended), so a prune visits only the accounts that have expired, never the table: an
// overflow request does as much work as there are accounts to remove. An account the table has no room for, once the
// expired ones are gone, has its devices ignored (its sync asks for itself alone, as without this table) and every
// change refused until there is room, so a flood of accounts cannot lift the limit for itself. Not thread-safe:
// `runtime.mutex` serialises every use (`HomeserverRuntime::presence_tracker`).
class AccountPresenceTracker final
{
public:
    static constexpr auto change_window_ms = std::int64_t{5'000};
    // The idle timeout (`presence_idle_timeout_ms`): a device holds the account online for as long as the idle sweep
    // would leave it online after that device's last sync. `PresenceService.cpp` asserts the two are equal.
    static constexpr auto device_fresh_ms = std::int64_t{5 * 60 * 1000};
    // Far more devices than one person syncs from at once; each is a device ID and two integers.
    static constexpr auto max_devices_per_account = std::size_t{64U};
    // Accounts that synced or changed presence within the last five minutes.
    static constexpr auto max_accounts = std::size_t{65'536U};

    // Notes that `device` of `user` synced asking for `online` (true) or `unavailable` (false) at `now_ms`. True when a
    // device of the account, this one included, asked for online within `device_fresh_ms`.
    [[nodiscard]] auto note_sync(std::string_view user, std::string_view device, bool online, std::int64_t now_ms)
        -> bool;

    // A sync with `set_presence=offline`: the device no longer holds the account online.
    auto forget_device(std::string_view user, std::string_view device) -> void;

    // How long `user` must wait before a change of presence is kept, or nullopt when one may be kept now.
    [[nodiscard]] auto change_blocked_for_ms(std::string_view user, std::int64_t now_ms) const
        -> std::optional<std::int64_t>;

    // Starts the window of `user` at `now_ms`: a change was just kept.
    auto note_change(std::string_view user, std::int64_t now_ms) -> void;

    // Removes every account whose devices are all stale and whose window ended by `now_ms`.
    auto prune(std::int64_t now_ms) -> void;

    // Accounts held, ones a prune would remove included.
    [[nodiscard]] auto account_count() const noexcept -> std::size_t;

    // Accounts a prune has looked at since the table was made, for tests that prove its cost.
    [[nodiscard]] auto accounts_examined() const noexcept -> std::uint64_t;

private:
    struct Device final
    {
        std::string id{};
        std::int64_t seen_at_ms{0};
        bool online{false};
    };
    struct Account final
    {
        std::vector<Device> devices{};
        std::optional<std::int64_t> changed_at_ms{};
        // When the account stops mattering: its latest device stale and its window ended. Its key in `m_by_expiry`.
        std::int64_t expires_at_ms{0};
    };
    using Accounts = std::unordered_map<std::string, Account, database::detail::StateGroupKeyHash, std::equal_to<>>;
    using ExpiryKey = std::pair<std::int64_t, std::string>;

    // The account of `user`, made when there is room (after removing the expired accounts when the table is full);
    // `m_accounts.end()` when there is none.
    [[nodiscard]] auto account_for(std::string_view user, std::int64_t now_ms) -> Accounts::iterator;

    // Files `entry` under its expiry again, after its devices or window changed.
    auto refile(Accounts::iterator entry, std::int64_t now_ms) -> void;

    // True when an account has expired by `now_ms`, so a prune would make room.
    [[nodiscard]] auto has_expired_account(std::int64_t now_ms) const noexcept -> bool;

    Accounts m_accounts{};
    // (expires_at_ms, user) of every account, soonest first.
    std::set<ExpiryKey> m_by_expiry{};
    std::uint64_t m_accounts_examined{0U};
};

} // namespace merovingian::homeserver
