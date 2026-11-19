// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `select_sticky_for_sync` (ADR-0855): which sticky events one room's sync response carries, and
// `sticky_candidates_of_room`: which of a room's sticky rows may be chosen at all.

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/StickyCandidate.hpp"
#include "merovingian/sync/StickyChoice.hpp"
#include "merovingian/sync/StickySelection.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
using merovingian::sync::select_sticky_for_sync;
using merovingian::sync::sticky_candidates_of_room;
using merovingian::sync::StickyCandidate;

constexpr auto no_limit = std::numeric_limits<std::size_t>::max();

[[nodiscard]] auto candidates() -> std::vector<StickyCandidate>
{
    // Listed out of order on purpose: the selection orders them.
    return {
        {"$c", "@alice:example.org",   30U},
        {"$a", "@alice:example.org",   10U},
        {"$d", "@mallory:example.org", 40U},
        {"$b", "@bob:example.org",     20U},
    };
}

constexpr auto sticky_room = std::string_view{"!room:example.org"};
constexpr auto sticky_now_ms = std::int64_t{1'000'000};

// An accepted event of `sticky_room` with an unexpired sticky row.
auto add_sticky_event(db::PersistentStore& store, std::string const& event_id, std::string_view type,
                      std::uint64_t ordering) -> void
{
    auto event = db::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = std::string{sticky_room};
    event.sender_user_id = "@alice:example.org";
    event.stream_ordering = ordering;
    event.json = std::string{R"({"type":")"} + std::string{type} + R"(","content":{}})";
    // Inserted outside REQUIRE, whose expansion repeats its expression.
    auto const inserted = store.events.insert(std::move(event));
    REQUIRE(inserted);
    REQUIRE(store.sticky_events.insert(
        {event_id, std::string{sticky_room}, "@alice:example.org", sticky_now_ms - 1'000, sticky_now_ms + 60'000}));
}

[[nodiscard]] auto candidate_ids(std::vector<StickyCandidate> const& chosen) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const& candidate : chosen)
    {
        ids.push_back(candidate.event_id);
    }
    return ids;
}

} // namespace

SCENARIO("sticky events are chosen oldest first", "[sync][sticky-events]")
{
    GIVEN("four candidates")
    {
        WHEN("nothing is excluded")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::nullopt, {}, {}, no_limit);
            THEN("all are chosen, oldest first")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$a", "$b", "$c", "$d"});
                REQUIRE_FALSE(choice.more);
            }
        }

        WHEN("the upper bound is 30")
        {
            auto const choice = select_sticky_for_sync(candidates(), 30U, std::nullopt, {}, {}, no_limit);
            THEN("a later event is left out and the bound itself is kept")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$a", "$b", "$c"});
            }
        }

        WHEN("the position is 20")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::uint64_t{20U}, {}, {}, no_limit);
            THEN("only events after it are chosen")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$c", "$d"});
            }
        }
    }
}

SCENARIO("a sticky event is left out when it is excluded or its sender is ignored", "[sync][sticky-events]")
{
    GIVEN("four candidates")
    {
        WHEN("one is in the timeline and one sender is ignored")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::nullopt, {"@mallory:example.org"},
                                                       std::unordered_set<std::string>{"$b"}, no_limit);
            THEN("neither is chosen")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$a", "$c"});
            }
        }

        WHEN("there are none")
        {
            auto const choice = select_sticky_for_sync({}, 100U, std::nullopt, {}, {}, no_limit);
            THEN("nothing is chosen")
            {
                REQUIRE(choice.event_ids.empty());
                REQUIRE_FALSE(choice.more);
            }
        }
    }
}

SCENARIO("a limit keeps the oldest and says more remain", "[sync][sticky-events]")
{
    GIVEN("four candidates")
    {
        WHEN("the limit is two")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::nullopt, {}, {}, 2U);
            THEN("the two oldest are chosen and more remain")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$a", "$b"});
                REQUIRE(choice.more);
            }
        }

        WHEN("the limit equals the eligible count")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::nullopt, {}, {}, 4U);
            THEN("nothing remains")
            {
                REQUIRE(choice.event_ids.size() == 4U);
                REQUIRE_FALSE(choice.more);
            }
        }
    }
}

SCENARIO("a sticky redaction that has not been applied is not a candidate", "[sync][sticky-events][security]")
{
    // The sticky exemption skips history visibility, never the rule that a redaction reaches clients only once it
    // applies (rooms/v3.md "Handling redactions"; ADR-0858).
    GIVEN("a room with a sticky message and a sticky redaction whose target has not arrived")
    {
        auto store = db::PersistentStore{};
        add_sticky_event(store, "$message", "m.rtc.member", 10U);
        add_sticky_event(store, "$redaction", "m.room.redaction", 20U);
        store.redactions.withheld.insert("$redaction");

        WHEN("the room's candidates are read")
        {
            auto const chosen = sticky_candidates_of_room(store, sticky_room, sticky_now_ms);
            THEN("only the message is a candidate")
            {
                REQUIRE(candidate_ids(chosen) == std::vector<std::string>{"$message"});
            }
        }

        WHEN("the redaction is applied and no longer withheld")
        {
            store.redactions.withheld.erase("$redaction");
            auto const chosen = sticky_candidates_of_room(store, sticky_room, sticky_now_ms);
            THEN("both are candidates")
            {
                REQUIRE(candidate_ids(chosen) == std::vector<std::string>{"$message", "$redaction"});
            }
        }
    }
}
