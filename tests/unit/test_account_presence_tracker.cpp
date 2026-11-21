// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0871 and ADR-0872: what an account's devices last asked of its presence, and the window after a change in which
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
            tracker.forget_device(alice, desktop);
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
}

SCENARIO("The tracker is bounded per account and in all", "[unit][presence][account_presence_tracker][bounds]")
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

            THEN("it replaces the least recently seen device, so none asks for online")
            {
                REQUIRE_FALSE(any_online);
            }
        }
    }

    GIVEN("a table holding as many accounts as the cap, each inside its window")
    {
        auto tracker = AccountPresenceTracker{};
        for (auto index = std::size_t{0U}; index < AccountPresenceTracker::max_accounts; ++index)
        {
            tracker.note_change("@user" + std::to_string(index) + ":example.org", start_ms);
        }
        REQUIRE(tracker.account_count() == AccountPresenceTracker::max_accounts);

        WHEN("an account with no entry asks to change its presence")
        {
            auto const blocked = tracker.change_blocked_for_ms(alice, start_ms + 1);
            tracker.note_change(alice, start_ms + 1);

            THEN("it is refused and the table does not grow: a flood of accounts cannot lift the limit")
            {
                REQUIRE(blocked.has_value());
                REQUIRE(tracker.account_count() == AccountPresenceTracker::max_accounts);
            }
        }

        WHEN("it syncs asking for online")
        {
            auto const any_online = tracker.note_sync(alice, desktop, true, start_ms + 1);

            THEN("its own ask is answered, as without the table")
            {
                REQUIRE(any_online);
                REQUIRE(tracker.account_count() == AccountPresenceTracker::max_accounts);
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
}

SCENARIO("A prune of a full table looks only at the accounts that have expired",
         "[unit][presence][account_presence_tracker][bounds]")
{
    GIVEN("a full table in which one account's window ended as the others' began")
    {
        auto tracker = AccountPresenceTracker{};
        tracker.note_change("@early:example.org", start_ms);
        auto const later_ms = start_ms + AccountPresenceTracker::change_window_ms;
        for (auto index = std::size_t{1U}; index < AccountPresenceTracker::max_accounts; ++index)
        {
            tracker.note_change("@user" + std::to_string(index) + ":example.org", later_ms);
        }
        REQUIRE(tracker.account_count() == AccountPresenceTracker::max_accounts);

        WHEN("an account with no entry asks to change its presence")
        {
            auto const blocked = tracker.change_blocked_for_ms(alice, later_ms + 1);
            tracker.note_change(alice, later_ms + 1);

            THEN("it is allowed and takes the expired account's place, the one account a prune looked at")
            {
                REQUIRE_FALSE(blocked.has_value());
                REQUIRE(tracker.account_count() == AccountPresenceTracker::max_accounts);
                REQUIRE(tracker.accounts_examined() == 1U);
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
                REQUIRE(tracker.accounts_examined() == 1U);
                REQUIRE(tracker.account_count() == AccountPresenceTracker::max_accounts);
            }
        }
    }
}
