// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0875 and ADR-0876: what an account's devices last asked of its presence, and the window after a change in which
// no other change is kept. Every operation takes the time, so no scenario sleeps.

#include "merovingian/homeserver/AccountPresenceTracker.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>

namespace
{

using merovingian::homeserver::AccountPresenceTracker;

constexpr auto start_ms = std::int64_t{1'000'000};
constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};
constexpr auto phone = std::string_view{"PHONE"};
constexpr auto desktop = std::string_view{"DESKTOP"};
// The account cap of the trackers the bound scenarios fill: small, so a full table costs a handful of accounts. The cap
// is the same code at any size.
constexpr auto small_cap = std::size_t{8U};

// Fills a tracker of `small_cap` with accounts each held online by a desktop and none with a window open. @user0 synced
// at start_ms and the rest a millisecond later, so @user0's hold goes stale first and is the one a full table evicts.
auto fill_held_online(AccountPresenceTracker& tracker) -> void
{
    std::ignore = tracker.note_sync("@user0:example.org", desktop, true, start_ms);
    for (auto index = std::size_t{1U}; index < small_cap; ++index)
    {
        std::ignore = tracker.note_sync("@user" + std::to_string(index) + ":example.org", desktop, true, start_ms + 1);
    }
}

} // namespace

SCENARIO("A device syncing online holds its account online against a device syncing unavailable",
         "[unit][presence][account_presence_tracker]")
{
    GIVEN("alice's desktop synced asking for online")
    {
        auto tracker = AccountPresenceTracker{};
        REQUIRE(tracker.note_sync(alice, desktop, true, start_ms));

        WHEN("her phone syncs asking for unavailable a moment later")
        {
            auto const any_online = tracker.note_sync(alice, phone, false, start_ms + 100);

            THEN("a device of the account still asks for online")
            {
                REQUIRE(any_online);
            }
        }

        WHEN("her phone syncs asking for unavailable once the desktop has not synced for the freshness time")
        {
            auto const any_online =
                tracker.note_sync(alice, phone, false, start_ms + AccountPresenceTracker::device_fresh_ms);

            THEN("no device asks for online any more")
            {
                REQUIRE_FALSE(any_online);
            }
        }

        WHEN("the desktop itself syncs asking for unavailable")
        {
            auto const any_online = tracker.note_sync(alice, desktop, false, start_ms + 100);

            THEN("its earlier ask is replaced, so no device asks for online")
            {
                REQUIRE_FALSE(any_online);
            }
        }

        WHEN("the desktop syncs with set_presence=offline and the phone asks for unavailable")
        {
            tracker.forget_device(alice, desktop, start_ms + 100);
            auto const any_online = tracker.note_sync(alice, phone, false, start_ms + 100);

            THEN("the desktop no longer holds the account online")
            {
                REQUIRE_FALSE(any_online);
            }
        }

        WHEN("another account's device asks for unavailable")
        {
            auto const any_online = tracker.note_sync(bob, phone, false, start_ms + 100);

            THEN("alice's desktop does not speak for bob")
            {
                REQUIRE_FALSE(any_online);
            }
        }
    }
}

SCENARIO("The first presence change in a window is kept and the rest wait for it to end",
         "[unit][presence][account_presence_tracker]")
{
    GIVEN("an account whose presence has not changed")
    {
        auto tracker = AccountPresenceTracker{};

        THEN("a change may be kept at once")
        {
            REQUIRE_FALSE(tracker.change_blocked_for_ms(alice, start_ms).has_value());
        }

        WHEN("a change is kept")
        {
            tracker.note_change(alice, start_ms);

            THEN("another change two seconds later waits for the rest of the window")
            {
                auto const blocked = tracker.change_blocked_for_ms(alice, start_ms + 2'000);
                REQUIRE(blocked == std::optional<std::int64_t>{AccountPresenceTracker::change_window_ms - 2'000});
            }
            THEN("a change once the window has ended may be kept")
            {
                REQUIRE_FALSE(tracker.change_blocked_for_ms(alice, start_ms + AccountPresenceTracker::change_window_ms)
                                  .has_value());
            }
            THEN("another account's change is not held back")
            {
                REQUIRE_FALSE(tracker.change_blocked_for_ms(bob, start_ms + 1).has_value());
            }
        }
    }
}

SCENARIO("A prune removes what no longer speaks for an account", "[unit][presence][account_presence_tracker]")
{
    GIVEN("alice changed her presence and synced from one device")
    {
        auto tracker = AccountPresenceTracker{};
        tracker.note_change(alice, start_ms);
        std::ignore = tracker.note_sync(alice, desktop, true, start_ms);
        REQUIRE(tracker.account_count() == 1U);

        WHEN("a prune runs inside the window and the freshness time")
        {
            tracker.prune(start_ms + 1'000);

            THEN("the account is kept")
            {
                REQUIRE(tracker.account_count() == 1U);
                REQUIRE(tracker.change_blocked_for_ms(alice, start_ms + 1'000).has_value());
            }
        }

        WHEN("a prune runs once the device is stale and the window has ended")
        {
            tracker.prune(start_ms + AccountPresenceTracker::device_fresh_ms);

            THEN("the account is removed")
            {
                REQUIRE(tracker.account_count() == 0U);
            }
        }
    }

    GIVEN("bob, whose presence has not changed, synced from a device asking for unavailable")
    {
        auto tracker = AccountPresenceTracker{};
        std::ignore = tracker.note_sync(bob, phone, false, start_ms);

        WHEN("a prune runs at once")
        {
            tracker.prune(start_ms);

            THEN("the account is removed: a device asking for unavailable speaks for nothing and holds no place")
            {
                REQUIRE(tracker.account_count() == 0U);
            }
        }
    }
}

// ADR-0875: an account holds at most max_devices_per_account devices; at the cap a device that holds nothing gives up
// its place first, and only a device asking for online takes an online device's place.
SCENARIO("An account holds a bounded number of devices, and the cap never ends an online hold for nothing",
         "[unit][presence][account_presence_tracker][bounds]")
{
    GIVEN("an account with as many devices as the cap, the oldest of them the only one asking for online")
    {
        auto tracker = AccountPresenceTracker{};
        std::ignore = tracker.note_sync(alice, "OLDEST", true, start_ms);
        for (auto index = std::size_t{1U}; index < AccountPresenceTracker::max_devices_per_account; ++index)
        {
            std::ignore = tracker.note_sync(alice, "D" + std::to_string(index), false,
                                            start_ms + static_cast<std::int64_t>(index));
        }

        WHEN("one more device syncs asking for unavailable")
        {
            auto const any_online = tracker.note_sync(alice, "NEWEST", false, start_ms + 1'000);

            THEN("it takes the place of the least recently seen device that asked for unavailable, and the online hold "
                 "stays")
            {
                REQUIRE(any_online);
                REQUIRE(tracker.note_sync(alice, "NEWEST", false, start_ms + 1'001));
            }
        }
    }

    GIVEN("an account with as many devices as the cap, every one of them asking for online")
    {
        auto tracker = AccountPresenceTracker{};
        for (auto index = std::size_t{0U}; index < AccountPresenceTracker::max_devices_per_account; ++index)
        {
            std::ignore = tracker.note_sync(alice, "D" + std::to_string(index), true,
                                            start_ms + static_cast<std::int64_t>(index));
        }

        WHEN("one more device syncs asking for unavailable")
        {
            auto const any_online = tracker.note_sync(alice, "NEWEST", false, start_ms + 1'000);
            // Forgetting every device but D0 leaves the account held online only if D0, the least recently seen, kept
            // its place; it is never synced again, so the probe cannot put it back.
            for (auto index = std::size_t{1U}; index < AccountPresenceTracker::max_devices_per_account; ++index)
            {
                tracker.forget_device(alice, "D" + std::to_string(index), start_ms + 1'001);
            }

            THEN("it is not recorded, since it holds nothing, and every online hold stays, D0's included")
            {
                REQUIRE(any_online);
                REQUIRE(tracker.note_sync(alice, "PROBE", false, start_ms + 1'002));
            }
        }

        WHEN("one more device syncs asking for online")
        {
            auto const any_online = tracker.note_sync(alice, "NEWEST", true, start_ms + 1'000);
            // Forgetting every device but D0 leaves the account held online only if D0 kept its place.
            tracker.forget_device(alice, "NEWEST", start_ms + 1'001);
            for (auto index = std::size_t{1U}; index < AccountPresenceTracker::max_devices_per_account; ++index)
            {
                tracker.forget_device(alice, "D" + std::to_string(index), start_ms + 1'001);
            }

            THEN("it takes the place of the least recently seen online device, D0")
            {
                REQUIRE(any_online);
                REQUIRE_FALSE(tracker.note_sync(alice, "PROBE", false, start_ms + 1'002));
            }
        }
    }
}

// ADR-0875, ADR-0876: the table holds at most its account cap. A full table evicts the account whose devices go stale
// soonest, and refuses (fails closed) only while every account has an open window.
SCENARIO("The tracker holds a bounded number of accounts", "[unit][presence][account_presence_tracker][bounds]")
{
    GIVEN("a table holding as many accounts as the cap, each inside its window")
    {
        auto tracker = AccountPresenceTracker{small_cap};
        for (auto index = std::size_t{0U}; index < small_cap; ++index)
        {
            tracker.note_change("@user" + std::to_string(index) + ":example.org", start_ms);
        }
        REQUIRE(tracker.account_count() == small_cap);

        WHEN("an account with no entry asks to change its presence")
        {
            auto const blocked = tracker.change_blocked_for_ms(alice, start_ms + 1);
            tracker.note_change(alice, start_ms + 1);

            THEN("it is refused and the table does not grow: a flood of accounts cannot lift the limit")
            {
                REQUIRE(blocked.has_value());
                REQUIRE(tracker.account_count() == small_cap);
            }
        }

        WHEN("it syncs asking for online")
        {
            auto const any_online = tracker.note_sync(alice, desktop, true, start_ms + 1);

            THEN("nothing is recorded, so no device the table holds asks for online, and the table does not grow")
            {
                REQUIRE_FALSE(any_online);
                REQUIRE(tracker.account_count() == small_cap);
            }
        }

        WHEN("the windows have ended and an account with no entry syncs")
        {
            std::ignore = tracker.note_sync(alice, desktop, true, start_ms + AccountPresenceTracker::change_window_ms);

            THEN("the ended accounts are pruned to make room and it is held")
            {
                REQUIRE(tracker.account_count() == 1U);
            }
        }
    }

    GIVEN("a table holding as many accounts as the cap, each held online by a device and none with a window open")
    {
        auto tracker = AccountPresenceTracker{small_cap};
        fill_held_online(tracker);

        WHEN("an account with no entry asks to change its presence, however recently the others synced")
        {
            auto const blocked = tracker.change_blocked_for_ms(alice, start_ms + 2);
            tracker.note_change(alice, start_ms + 2);

            THEN("it is allowed, and the account whose device goes stale soonest gives up its place")
            {
                REQUIRE_FALSE(blocked.has_value());
                REQUIRE(tracker.account_count() == small_cap);
                REQUIRE(tracker.accounts_examined() == 1U);
                REQUIRE(tracker.evictions() == 1U);
                REQUIRE(tracker.take_saturation_report(start_ms + 2) ==
                        std::optional{
                            AccountPresenceTracker::SaturationReport{0U, 1U}
                });
                REQUIRE(tracker.change_blocked_for_ms(alice, start_ms + 3).has_value());
                REQUIRE_FALSE(tracker.note_sync("@user0:example.org", phone, false, start_ms + 3));
            }
        }
    }
}

SCENARIO("A prune of a full table looks only at the accounts that have expired",
         "[unit][presence][account_presence_tracker][bounds]")
{
    GIVEN("a full table in which one account's window ended as the others' began")
    {
        auto tracker = AccountPresenceTracker{small_cap};
        tracker.note_change("@early:example.org", start_ms);
        auto const later_ms = start_ms + AccountPresenceTracker::change_window_ms;
        for (auto index = std::size_t{1U}; index < small_cap; ++index)
        {
            tracker.note_change("@user" + std::to_string(index) + ":example.org", later_ms);
        }
        REQUIRE(tracker.account_count() == small_cap);

        WHEN("an account with no entry asks to change its presence")
        {
            auto const blocked = tracker.change_blocked_for_ms(alice, later_ms + 1);
            tracker.note_change(alice, later_ms + 1);

            THEN("it is allowed and takes the expired account's place: a prune re-filed that one account as its window "
                 "ended, then removed it, and looked at no other")
            {
                REQUIRE_FALSE(blocked.has_value());
                REQUIRE(tracker.account_count() == small_cap);
                REQUIRE(tracker.accounts_examined() == 2U);
                REQUIRE(tracker.change_blocked_for_ms(alice, later_ms + 2).has_value());
            }
        }

        WHEN("the table is full again and a flood of accounts with no entry syncs")
        {
            tracker.note_change(alice, later_ms + 1);
            for (auto index = 0; index < 1'000; ++index)
            {
                std::ignore =
                    tracker.note_sync("@flood" + std::to_string(index) + ":example.org", desktop, true, later_ms + 2);
            }

            THEN("no request looks at the table, since no account has expired")
            {
                REQUIRE(tracker.accounts_examined() == 2U);
                REQUIRE(tracker.account_count() == small_cap);
            }
        }
    }
}

SCENARIO("A device asking for unavailable takes no place in the tracker",
         "[unit][presence][account_presence_tracker][bounds]")
{
    GIVEN("an account the tracker does not hold")
    {
        auto tracker = AccountPresenceTracker{};

        WHEN("its device syncs asking for unavailable")
        {
            auto const any_online = tracker.note_sync(bob, phone, false, start_ms);

            THEN("no device asks for online and the account is not held")
            {
                REQUIRE_FALSE(any_online);
                REQUIRE(tracker.account_count() == 0U);
            }
        }
    }

    GIVEN("a table holding as many accounts as the cap, each held online by a device and none with a window open")
    {
        auto tracker = AccountPresenceTracker{small_cap};
        fill_held_online(tracker);

        WHEN("an account with no entry syncs asking for unavailable")
        {
            auto const any_online = tracker.note_sync(alice, phone, false, start_ms + 2);

            THEN("nothing is evicted: the account whose device goes stale soonest keeps its hold")
            {
                REQUIRE_FALSE(any_online);
                REQUIRE(tracker.accounts_examined() == 0U);
                REQUIRE(tracker.account_count() == small_cap);
                REQUIRE(tracker.note_sync("@user0:example.org", phone, false, start_ms + 3));
            }
        }
    }
}

SCENARIO("A tracker holds max_accounts accounts unless it is made with another cap",
         "[unit][presence][account_presence_tracker][bounds]")
{
    GIVEN("a tracker made as the server makes it, and two made with a cap")
    {
        auto const server = AccountPresenceTracker{};
        auto const small = AccountPresenceTracker{small_cap};
        auto const zero = AccountPresenceTracker{0U};

        THEN("the server's holds max_accounts, the small one its cap, and a cap of zero holds one account")
        {
            REQUIRE(server.account_cap() == AccountPresenceTracker::max_accounts);
            REQUIRE(small.account_cap() == small_cap);
            REQUIRE(zero.account_cap() == 1U);
        }
    }
}

// ADR-0876: a full table's refusals and evictions are counted, and a report of them is due at most once every
// full_warning_interval_ms, carrying what it stands for, so a flood costs one warning a minute. Nothing to report is
// never a report.
SCENARIO("A full tracker's refusals and evictions are reported at most once an interval",
         "[unit][presence][account_presence_tracker][bounds]")
{
    GIVEN("a tracker that has refused and evicted nothing")
    {
        auto tracker = AccountPresenceTracker{small_cap};
        REQUIRE(tracker.full_refusals() == 0U);
        REQUIRE(tracker.evictions() == 0U);
        REQUIRE_FALSE(tracker.take_saturation_report(start_ms).has_value());

        WHEN("it refuses one change, then two more within the interval, and is asked after each")
        {
            using Report = AccountPresenceTracker::SaturationReport;
            tracker.note_full_refusal();
            auto const first = tracker.take_saturation_report(start_ms);
            tracker.note_full_refusal();
            auto const second = tracker.take_saturation_report(start_ms + 1);
            tracker.note_full_refusal();
            auto const third =
                tracker.take_saturation_report(start_ms + AccountPresenceTracker::full_warning_interval_ms - 1);
            auto const after_interval =
                tracker.take_saturation_report(start_ms + AccountPresenceTracker::full_warning_interval_ms);
            auto const nothing_new =
                tracker.take_saturation_report(start_ms + 2 * AccountPresenceTracker::full_warning_interval_ms);

            THEN("the first is reported, the next two wait for the interval, and nothing new is never reported")
            {
                REQUIRE(first == std::optional{
                                     Report{1U, 0U}
                });
                REQUIRE_FALSE(second.has_value());
                REQUIRE_FALSE(third.has_value());
                REQUIRE(after_interval == std::optional{
                                              Report{2U, 0U}
                });
                REQUIRE_FALSE(nothing_new.has_value());
                REQUIRE(tracker.full_refusals() == 3U);
            }
        }
    }
}
