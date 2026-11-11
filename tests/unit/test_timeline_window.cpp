// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Release-gate audit, classic-sync full-history scan: the timeline window reads the newest end of a room (ADR-0616).
//
// Spec: client-server-api.md, GET /sync: `limited` is "True if the number of events returned was limited by the limit
// on the filter", and `prev_batch` is what a client paginates from.

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/TimelineWindow.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace sync = merovingian::sync;

constexpr auto room = std::string_view{"!room:example.org"};

auto add_rows(db::PersistentStore& store, std::uint64_t first, std::uint64_t last, std::string_view status = "accepted")
    -> void
{
    for (auto ordering = first; ordering <= last; ++ordering)
    {
        auto event = db::PersistentEvent{};
        event.event_id = "$m" + std::to_string(ordering);
        event.room_id = std::string{room};
        event.sender_user_id = "@bob:example.org";
        event.json = "{}";
        event.stream_ordering = ordering;
        event.status = std::string{status};
        store.events.push_back(std::move(event));
    }
}

[[nodiscard]] auto orderings(sync::TimelineWindow const& window) -> std::vector<std::uint64_t>
{
    auto result = std::vector<std::uint64_t>{};
    for (auto const* event : window.matched)
    {
        result.push_back(event->stream_ordering);
    }
    return result;
}

[[nodiscard]] auto take_all(db::PersistentEvent const& /*event*/) -> bool
{
    return true;
}

} // namespace

SCENARIO("a timeline window reads the newest end of a room and stops", "[sync][timeline][security][gate-m-sync]")
{
    GIVEN("a room with three thousand rows")
    {
        auto store = db::PersistentStore{};
        add_rows(store, 1U, 3000U);

        WHEN("a window of two is asked for")
        {
            auto const before = store.sync_timeline_rows_examined.value();
            auto const window = sync::newest_timeline_window(store, room, std::nullopt, 3000U, 2U, take_all);

            THEN("it holds one more than the limit, oldest first, and read only those")
            {
                REQUIRE(orderings(window) == std::vector<std::uint64_t>{2998U, 2999U, 3000U});
                REQUIRE_FALSE(window.budget_ran_out);
                REQUIRE(store.sync_timeline_rows_examined.value() - before == 3U);
            }
        }

        WHEN("the window is bounded above and below")
        {
            auto const window = sync::newest_timeline_window(store, room, 2000U, 2002U, 10U, take_all);

            THEN("it holds exactly the rows above `after` and at or below `up_to`")
            {
                REQUIRE(orderings(window) == std::vector<std::uint64_t>{2001U, 2002U});
                REQUIRE_FALSE(window.budget_ran_out);
            }
        }

        WHEN("the window holds exactly the limit")
        {
            auto const window = sync::newest_timeline_window(store, room, 2998U, 3000U, 2U, take_all);

            THEN("it holds no more than the limit, so it is not cut")
            {
                REQUIRE(orderings(window) == std::vector<std::uint64_t>{2999U, 3000U});
            }
        }

        WHEN("the limit is zero")
        {
            auto const window = sync::newest_timeline_window(store, room, std::nullopt, 3000U, 0U, take_all);

            THEN("one row shows there was something to leave out")
            {
                REQUIRE(window.matched.size() == 1U);
            }
        }

        WHEN("nothing is wanted")
        {
            auto const before = store.sync_timeline_rows_examined.value();
            auto const window =
                sync::newest_timeline_window(store, room, std::nullopt, 3000U, 10U, [](db::PersistentEvent const&) {
                    return false;
                });

            THEN("the walk stops at the budget, and says so")
            {
                REQUIRE(window.matched.empty());
                REQUIRE(window.budget_ran_out);
                REQUIRE(store.sync_timeline_rows_examined.value() - before == sync::max_timeline_rows_skipped);
                REQUIRE(window.oldest_examined ==
                        std::optional<std::uint64_t>{3000U - sync::max_timeline_rows_skipped + 1U});
            }
        }

        WHEN("exactly the budget of rows is passed over, and none is left")
        {
            auto const window = sync::newest_timeline_window(store, room, 3000U - sync::max_timeline_rows_skipped,
                                                             3000U, 10U, [](db::PersistentEvent const&) {
                                                                 return false;
                                                             });

            THEN("the window is complete, so the budget did not run out")
            {
                REQUIRE(window.matched.empty());
                REQUIRE_FALSE(window.budget_ran_out);
            }
        }
    }

    GIVEN("a room whose newest rows were rejected or soft-failed")
    {
        auto store = db::PersistentStore{};
        add_rows(store, 1U, 2U);
        add_rows(store, 3U, 3U, "rejected");
        add_rows(store, 4U, 4U, "soft_failed");

        WHEN("a window is asked for")
        {
            auto offered = std::size_t{0U};
            auto const window = sync::newest_timeline_window(store, room, std::nullopt, 4U, 10U,
                                                             [&offered](db::PersistentEvent const&) {
                                                                 ++offered;
                                                                 return true;
                                                             });

            THEN("they are neither taken nor offered")
            {
                REQUIRE(orderings(window) == std::vector<std::uint64_t>{1U, 2U});
                REQUIRE(offered == 2U);
            }
        }
    }

    GIVEN("a room with no rows")
    {
        auto const store = db::PersistentStore{};

        WHEN("a window is asked for")
        {
            auto const window = sync::newest_timeline_window(store, room, std::nullopt, 10U, 10U, take_all);

            THEN("it is empty")
            {
                REQUIRE(window.matched.empty());
                REQUIRE_FALSE(window.budget_ran_out);
                REQUIRE_FALSE(window.oldest_examined.has_value());
            }
        }
    }

    GIVEN("a position above which the window would be empty")
    {
        auto store = db::PersistentStore{};
        add_rows(store, 1U, 3U);

        WHEN("`after` is above `up_to`")
        {
            auto const window = sync::newest_timeline_window(store, room, 3U, 1U, 10U, take_all);

            THEN("nothing is read")
            {
                REQUIRE(window.matched.empty());
                REQUIRE_FALSE(window.oldest_examined.has_value());
            }
        }
    }
}
