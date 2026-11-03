// SPDX-License-Identifier: GPL-3.0-or-later
//
// SearchRoomIndex: the per-room timelines POST /search builds once per request when `event_context` was asked
// for (security audit run 2, F-31; ADR-0333).
// Spec: Matrix CS API v1.19 § Server Side Search: "context: Context for result, if requested." Events before and
// after a result are the room's events in stream order.
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#server-side-search

#include "merovingian/database/persistent_event.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/search_room_index.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{

using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStore;
using merovingian::homeserver::SearchRoomIndex;

auto add_event(PersistentStore& store, std::string const& room_id, std::string const& event_id,
               std::uint64_t stream_ordering, std::string status = "accepted") -> void
{
    auto event = PersistentEvent{};
    event.event_id = event_id;
    event.room_id = room_id;
    event.sender_user_id = "@alice:example.org";
    event.stream_ordering = stream_ordering;
    event.status = std::move(status);
    store.events.push_back(std::move(event));
}

} // namespace

SCENARIO("a room's timeline is its events in stream order, found by binary search", "[search][search-room-index]")
{
    GIVEN("two rooms whose events were stored interleaved and out of order")
    {
        auto store = PersistentStore{};
        add_event(store, "!a:x", "$a3", 30U);
        add_event(store, "!b:x", "$b1", 15U);
        add_event(store, "!a:x", "$a1", 10U);
        add_event(store, "!a:x", "$a2", 20U);
        add_event(store, "!a:x", "$a-rejected", 25U, "rejected");
        add_event(store, "!a:x", "$a-soft", 26U, "soft_failed");
        add_event(store, "!c:x", "$c1", 5U);

        WHEN("an index is built for the first two rooms")
        {
            auto const rooms = std::unordered_set<std::string_view>{"!a:x", "!b:x"};
            auto const index = SearchRoomIndex{store, rooms};

            THEN("each room lists its accepted events by ascending stream ordering")
            {
                auto const a = index.timeline("!a:x");
                REQUIRE(a.size() == 3U);
                REQUIRE(a[0]->event_id == "$a1");
                REQUIRE(a[1]->event_id == "$a2");
                REQUIRE(a[2]->event_id == "$a3");
                REQUIRE(index.timeline("!b:x").size() == 1U);
            }

            THEN("a room that was not asked for lists nothing")
            {
                REQUIRE(index.timeline("!c:x").empty());
            }

            THEN("an event is found at its place in its room's timeline")
            {
                REQUIRE(index.position_of(*store.events.find("$a2")) == std::optional<std::size_t>{1U});
                REQUIRE(index.position_of(*store.events.find("$b1")) == std::optional<std::size_t>{0U});
            }

            THEN("an event left out of the timeline has no place in it")
            {
                REQUIRE_FALSE(index.position_of(*store.events.find("$a-rejected")).has_value());
            }
        }
    }

    GIVEN("two events of one room sharing a stream ordering")
    {
        auto store = PersistentStore{};
        add_event(store, "!a:x", "$first", 7U);
        add_event(store, "!a:x", "$second", 7U);

        WHEN("the index is built")
        {
            auto const rooms = std::unordered_set<std::string_view>{"!a:x"};
            auto const index = SearchRoomIndex{store, rooms};

            THEN("each is found by its own event ID")
            {
                REQUIRE(index.position_of(*store.events.find("$first")).has_value());
                REQUIRE(index.position_of(*store.events.find("$second")).has_value());
                REQUIRE(index.position_of(*store.events.find("$first")) !=
                        index.position_of(*store.events.find("$second")));
            }
        }
    }
}

// F-31: the old builder walked the whole events table and sorted the room once per match, 100 times for a page
// of 100. The index walks it once however many rooms and matches follow.
SCENARIO("the events table is walked once however many rooms are indexed", "[search][search-room-index][security]")
{
    GIVEN("a store with 200 rooms of 5 events each")
    {
        auto store = PersistentStore{};
        auto ordering = std::uint64_t{1U};
        for (auto room = std::size_t{0U}; room < 200U; ++room)
        {
            for (auto event = std::size_t{0U}; event < 5U; ++event)
            {
                add_event(store, "!r" + std::to_string(room) + ":x", "$e" + std::to_string(ordering), ordering);
                ++ordering;
            }
        }

        WHEN("an index is built for one room, then for all of them")
        {
            auto one = std::unordered_set<std::string_view>{"!r0:x"};
            auto all_names = std::vector<std::string>{};
            for (auto room = std::size_t{0U}; room < 200U; ++room)
            {
                all_names.push_back("!r" + std::to_string(room) + ":x");
            }
            auto all = std::unordered_set<std::string_view>{};
            for (auto const& name : all_names)
            {
                all.insert(name);
            }
            auto const narrow = SearchRoomIndex{store, one};
            auto const wide = SearchRoomIndex{store, all};

            THEN("each made one pass, and an index for no rooms made none")
            {
                REQUIRE(narrow.table_walks() == 1U);
                REQUIRE(wide.table_walks() == 1U);
                REQUIRE(SearchRoomIndex{store, {}}.table_walks() == 0U);
                REQUIRE(wide.timeline("!r199:x").size() == 5U);
            }
        }
    }
}
