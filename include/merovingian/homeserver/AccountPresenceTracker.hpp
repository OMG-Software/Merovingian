// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

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
// Bounded: at most `max_accounts` accounts (the account cap, which a test may set lower) of `max_devices_per_account`
// devices each. A new device past the device cap replaces the account's least recently seen one. An account with an
// open window is filed under the window's end; any other under the time its last online device goes stale, and an
// account moves from the first to the second when its window ends. A prune removes only the accounts whose time has
// passed, never visiting the table. When the table is full after a prune, the account with no open window whose devices
// go stale soonest makes room: it loses only its devices' holds, never a window, so the limit holds. Only when every
// account has an open window is there no room: a newcomer's devices are ignored and its change refused until the
// soonest window ends (at most `change_window_ms`), so a flood of accounts cannot lift the limit for itself. Every
// operation does O(log n) work per account it moves or removes. Not thread-safe: `runtime.mutex` serialises every use
// (`HomeserverRuntime::presence_tracker`).
class AccountPresenceTracker final
{
public:
    static constexpr auto change_window_ms = std::int64_t{5'000};
    // The idle timeout (`presence_idle_timeout_ms`): a device holds the account online for as long as the idle sweep
    // would leave it online after that device's last sync. `PresenceService.cpp` asserts the two are equal.
    static constexpr auto device_fresh_ms = std::int64_t{5 * 60 * 1000};
    // Far more devices than one person syncs from at once; each is a device ID and two integers.
    static constexpr auto max_devices_per_account = std::size_t{64U};
    // Accounts with a device that asked for online within the last five minutes, or a window open: the account cap a
    // tracker has unless it is made with another.
    static constexpr auto max_accounts = std::size_t{65'536U};
    // At most one warning that the table is full in this time, so a flood of refused changes costs one warning a
    // minute, which counts what it stands for.
    static constexpr auto full_warning_interval_ms = std::int64_t{60'000};

    AccountPresenceTracker() = default;
    // A tracker holding at most `account_cap` accounts (at least one), so a test can fill the table without
    // `max_accounts` of them. The server's tracker is made with the default.
    explicit AccountPresenceTracker(std::size_t account_cap) noexcept;

    // Notes that `device` of `user` synced asking for `online` (true) or `unavailable` (false) at `now_ms`. True when a
    // device the table holds for the account, this one included, asked for online within `device_fresh_ms`. Records
    // nothing and answers false for an account the table does not hold when the ask is `unavailable` (it needs no
    // place) or when the table has no room for it (fails closed; room is made only by a prune or an eviction, and
    // `is_full_for` tells the caller a change is refused).
    [[nodiscard]] auto note_sync(std::string_view user, std::string_view device, bool online, std::int64_t now_ms)
        -> bool;

    // A sync with `set_presence=offline` at `now_ms`: the device no longer holds the account online.
    auto forget_device(std::string_view user, std::string_view device, std::int64_t now_ms) -> void;

    // How long `user` must wait before a change of presence is kept, or nullopt when one may be kept now: the rest of
    // the account's window, or, when `is_full_for`, the rest of the table's soonest window. Never over the window.
    [[nodiscard]] auto change_blocked_for_ms(std::string_view user, std::int64_t now_ms) const
        -> std::optional<std::int64_t>;

    // True when a change of `user` is refused because the table has no room for the account (every account in it has an
    // open window), not because of the account's own window.
    [[nodiscard]] auto is_full_for(std::string_view user, std::int64_t now_ms) const -> bool;

    // Starts the window of `user` at `now_ms`: a change was just kept. Does nothing for an account the table has no
    // room for, which `change_blocked_for_ms` refused a change of first.
    auto note_change(std::string_view user, std::int64_t now_ms) -> void;

    // Removes every account whose online devices are all stale and whose window ended by `now_ms`.
    auto prune(std::int64_t now_ms) -> void;

    // Accounts held, ones a prune would remove included.
    [[nodiscard]] auto account_count() const noexcept -> std::size_t;

    // Accounts a prune re-filed when their window ended or removed, or a full table evicted, since the table was made,
    // for tests that prove the cost.
    [[nodiscard]] auto accounts_examined() const noexcept -> std::uint64_t;

    // The most accounts the table holds.
    [[nodiscard]] auto account_cap() const noexcept -> std::size_t;

    // Counts a change refused at `now_ms` because the table is full (`is_full_for`). When a warning is due (the first
    // refusal, or the first at least `full_warning_interval_ms` after the last warning), the number refused since the
    // last warning, this one included; otherwise nullopt.
    [[nodiscard]] auto note_full_refusal(std::int64_t now_ms) -> std::optional<std::uint64_t>;

    // Changes refused because the table was full, since the table was made.
    [[nodiscard]] auto full_refusals() const noexcept -> std::uint64_t;

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
        // Its key: the end of its open window (in `m_open_windows`), or else the time its last online device goes stale
        // or its window ended, whichever is later (in `m_closed`).
        std::int64_t filed_at_ms{0};
        bool window_open{false};
    };
    // Looks a user ID up as a string_view without making a string.
    struct UserHash final
    {
        using is_transparent = void;
        [[nodiscard]] auto operator()(std::string_view user) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(user);
        }
    };
    using Accounts = std::unordered_map<std::string, Account, UserHash, std::equal_to<>>;
    using FiledKey = std::pair<std::int64_t, std::string>;

    // The account of `user`, made when there is room (after a prune, and an eviction when the table is still full);
    // `m_accounts.end()` when there is none.
    [[nodiscard]] auto account_for(std::string_view user, std::int64_t now_ms) -> Accounts::iterator;

    // Files `entry` again, after its devices or window changed or its window ended.
    auto refile(Accounts::iterator entry, std::int64_t now_ms) -> void;

    // Moves every account whose window ended by `now_ms` from `m_open_windows` to `m_closed`.
    auto close_ended_windows(std::int64_t now_ms) -> void;

    // True when the table can hold another account at `now_ms`: it is not full, or an account in it has no open window.
    [[nodiscard]] auto has_room(std::int64_t now_ms) const noexcept -> bool;

    Accounts m_accounts{};
    // (window end, user) of every account whose window was open when it was filed, soonest first.
    std::set<FiledKey> m_open_windows{};
    // (stale-or-ended time, user) of every other account, soonest first: the ones a prune removes, and the one a full
    // table evicts.
    std::set<FiledKey> m_closed{};
    std::uint64_t m_accounts_examined{0U};
    std::size_t m_account_cap{max_accounts};
    std::uint64_t m_full_refusals{0U};
    // `m_full_refusals` when the last warning was due, and when that was.
    std::uint64_t m_full_refusals_warned{0U};
    std::optional<std::int64_t> m_full_warned_at_ms{};
};

} // namespace merovingian::homeserver
