// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/temp_directory.hpp"
#include "merovingian/database/event_table.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using merovingian::database::EventTable;
using merovingian::database::PersistentEvent;

[[nodiscard]] auto make_event(std::string event_id, std::uint64_t stream_ordering,
                              std::string room_id = "!room:example.org") -> PersistentEvent
{
    return PersistentEvent{std::move(event_id),
                           std::move(room_id),
                           "@alice:example.org",
                           R"({"type":"m.room.message","content":{"body":"hello"}})",
                           stream_ordering,
                           stream_ordering,
                           {},
                           {},
                           {}};
}

// The event IDs of `events`, in the order the range visits them.
template <typename Range>
[[nodiscard]] auto ids_of(Range&& events) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (PersistentEvent const& event : events)
    {
        ids.push_back(event.event_id);
    }
    return ids;
}

// The IDs of the events named in `wanted`, in stream order: a store may hold other events too.
[[nodiscard]] auto stream_order_of(EventTable const& table, std::vector<std::string> const& wanted)
    -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const& event : table.in_stream_order())
    {
        if (std::ranges::find(wanted, event.event_id) != wanted.end())
        {
            ids.push_back(event.event_id);
        }
    }
    return ids;
}

// Every row is found under its own ID, and the stream-order walk visits every row exactly once,
// never going backwards.
[[nodiscard]] auto indexes_agree_with_rows(EventTable const& table) -> bool
{
    for (auto const& event : table)
    {
        auto const found = table.find(event.event_id);
        if (found == table.end() || &*found != &event)
        {
            return false;
        }
    }
    auto visited = std::size_t{0U};
    auto previous = std::uint64_t{0U};
    for (auto const& event : table.in_stream_order())
    {
        if (event.stream_ordering < previous)
        {
            return false;
        }
        previous = event.stream_ordering;
        ++visited;
    }
    return visited == table.size();
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() / ("merovingian-event-table-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("An event table finds rows by ID and walks them in stream order whatever order they arrive in",
         "[database][event-table]")
{
    GIVEN("an empty event table")
    {
        auto table = EventTable{};

        WHEN("events arrive out of stream order, two sharing a stream ordering")
        {
            REQUIRE(table.insert(make_event("$thirty", 30U)));
            REQUIRE(table.insert(make_event("$ten", 10U)));
            REQUIRE(table.insert(make_event("$twenty-a", 20U)));
            REQUIRE(table.insert(make_event("$twenty-b", 20U)));

            THEN("each is found by its ID and an unknown ID is not")
            {
                REQUIRE(table.size() == 4U);
                for (auto const id : {std::string_view{"$thirty"}, std::string_view{"$ten"},
                                      std::string_view{"$twenty-a"}, std::string_view{"$twenty-b"}})
                {
                    auto const found = table.find(id);
                    REQUIRE(found != table.end());
                    REQUIRE(found->event_id == id);
                    REQUIRE(table.contains(id));
                }
                REQUIRE(table.find("$missing") == table.end());
                REQUIRE_FALSE(table.contains("$missing"));
                REQUIRE(ids_of(table.with_id("$ten")) == std::vector<std::string>{"$ten"});
                REQUIRE(std::ranges::empty(table.with_id("$missing")));
            }

            THEN("the stream-order walk is ascending, ties in arrival order, and reverses to newest first")
            {
                REQUIRE(ids_of(table.in_stream_order()) ==
                        std::vector<std::string>{"$ten", "$twenty-a", "$twenty-b", "$thirty"});
                REQUIRE(ids_of(table.in_stream_order() | std::views::reverse) ==
                        std::vector<std::string>{"$thirty", "$twenty-b", "$twenty-a", "$ten"});
            }

            THEN("iterating the table itself still visits rows in arrival order")
            {
                REQUIRE(ids_of(table) == std::vector<std::string>{"$thirty", "$ten", "$twenty-a", "$twenty-b"});
            }
        }
    }
}

SCENARIO("An event table finds an event in a room only when it belongs to that room", "[database][event-table]")
{
    GIVEN("a table holding an event in one room")
    {
        auto table = EventTable{};
        REQUIRE(table.insert(make_event("$event", 1U, "!a:example.org")));

        WHEN("the event is looked up in its own room and in another")
        {
            auto const in_own_room = table.find_in_room("!a:example.org", "$event");
            auto const in_other_room = table.find_in_room("!b:example.org", "$event");
            auto const unknown = table.find_in_room("!a:example.org", "$missing");

            THEN("only the lookup in its own room finds it")
            {
                REQUIRE(in_own_room != table.end());
                REQUIRE(in_own_room->event_id == "$event");
                REQUIRE(in_other_room == table.end());
                REQUIRE(unknown == table.end());
            }
        }
    }
}

SCENARIO("An event table holds an event ID once", "[database][event-table]")
{
    GIVEN("a table holding an event")
    {
        auto table = EventTable{};
        REQUIRE(table.insert(make_event("$event", 5U)));

        WHEN("another row with the same event ID is offered")
        {
            auto duplicate = make_event("$event", 9U);
            duplicate.json = R"({"type":"m.room.message","content":{"body":"impostor"}})";
            auto const added = table.insert(duplicate);

            THEN("it is refused and the first row is kept unchanged")
            {
                REQUIRE_FALSE(added);
                REQUIRE(table.size() == 1U);
                REQUIRE(table.find("$event")->stream_ordering == 5U);
                REQUIRE(table.find("$event")->json.find("impostor") == std::string::npos);
                REQUIRE(indexes_agree_with_rows(table));
            }
        }
    }
}

SCENARIO("Removing rows from an event table keeps both indexes consistent", "[database][event-table]")
{
    GIVEN("a table holding events from two rooms out of stream order")
    {
        auto table = EventTable{};
        REQUIRE(table.insert(make_event("$a4", 40U, "!a:example.org")));
        REQUIRE(table.insert(make_event("$b1", 10U, "!b:example.org")));
        REQUIRE(table.insert(make_event("$a2", 20U, "!a:example.org")));
        REQUIRE(table.insert(make_event("$b3", 30U, "!b:example.org")));

        WHEN("one room's events are removed")
        {
            auto const removed = table.erase_if([](PersistentEvent const& event) {
                return event.room_id == "!a:example.org";
            });

            THEN("they are gone, the rest are still found and still in stream order")
            {
                REQUIRE(removed == 2U);
                REQUIRE(table.size() == 2U);
                REQUIRE(table.find("$a4") == table.end());
                REQUIRE(table.find("$a2") == table.end());
                REQUIRE(table.find("$b1")->stream_ordering == 10U);
                REQUIRE(table.find("$b3")->stream_ordering == 30U);
                REQUIRE(ids_of(table.in_stream_order()) == std::vector<std::string>{"$b1", "$b3"});
                REQUIRE(indexes_agree_with_rows(table));
            }

            AND_WHEN("a removed event is stored again")
            {
                REQUIRE(table.insert(make_event("$a2", 20U, "!a:example.org")));

                THEN("it takes its place in stream order again")
                {
                    REQUIRE(ids_of(table.in_stream_order()) == std::vector<std::string>{"$b1", "$a2", "$b3"});
                    REQUIRE(indexes_agree_with_rows(table));
                }
            }
        }

        WHEN("nothing matches")
        {
            auto const removed = table.erase_if([](PersistentEvent const&) {
                return false;
            });

            THEN("the table is unchanged")
            {
                REQUIRE(removed == 0U);
                REQUIRE(table.size() == 4U);
                REQUIRE(indexes_agree_with_rows(table));
            }
        }
    }
}

SCENARIO("Modifying a row in an event table cannot rename it or move it in stream order", "[database][event-table]")
{
    GIVEN("a table holding three events")
    {
        auto table = EventTable{};
        REQUIRE(table.insert(make_event("$one", 1U)));
        REQUIRE(table.insert(make_event("$two", 2U)));
        REQUIRE(table.insert(make_event("$three", 3U)));

        WHEN("a row's status and JSON are changed")
        {
            table.modify(table.find("$two"), [](PersistentEvent& event) {
                event.status = "soft_failed";
                event.json = R"({"type":"m.room.message","content":{}})";
            });

            THEN("the change is visible through the ID index and the stream order is unchanged")
            {
                REQUIRE(table.find("$two")->status == "soft_failed");
                REQUIRE(table.find("$two")->json == R"({"type":"m.room.message","content":{}})");
                REQUIRE(ids_of(table.in_stream_order()) == std::vector<std::string>{"$one", "$two", "$three"});
            }
        }

        WHEN("a mutation tries to change the row's event ID and stream ordering")
        {
            table.modify(table.find("$two"), [](PersistentEvent& event) {
                event.event_id = "$renamed";
                event.stream_ordering = 99U;
                event.status = "rejected";
            });

            THEN("the indexed fields are put back and the other change is kept")
            {
                REQUIRE(table.find("$renamed") == table.end());
                REQUIRE(table.find("$two")->stream_ordering == 2U);
                REQUIRE(table.find("$two")->status == "rejected");
                REQUIRE(ids_of(table.in_stream_order()) == std::vector<std::string>{"$one", "$two", "$three"});
                REQUIRE(indexes_agree_with_rows(table));
            }
        }
    }
}

SCENARIO("Adding many events to an event table merges them into the stream order", "[database][event-table]")
{
    GIVEN("a table holding events at stream orderings 10 and 40")
    {
        auto table = EventTable{};
        REQUIRE(table.insert(make_event("$ten", 10U)));
        REQUIRE(table.insert(make_event("$forty", 40U)));

        WHEN("a batch arrives out of order, including an ID already held and one repeated in the batch")
        {
            auto const added =
                table.insert_all({make_event("$thirty", 30U), make_event("$fifty", 50U), make_event("$ten", 99U),
                                  make_event("$twenty", 20U), make_event("$fifty", 51U)});

            THEN("only IDs not yet held are added, first copy kept, and every row is in stream order")
            {
                REQUIRE(added == 3U);
                REQUIRE(table.size() == 5U);
                REQUIRE(table.find("$ten")->stream_ordering == 10U);
                REQUIRE(table.find("$fifty")->stream_ordering == 50U);
                REQUIRE(ids_of(table.in_stream_order()) ==
                        std::vector<std::string>{"$ten", "$twenty", "$thirty", "$forty", "$fifty"});
                REQUIRE(indexes_agree_with_rows(table));
            }
        }
    }
}

SCENARIO("A copied event table answers from its own rows", "[database][event-table]")
{
    GIVEN("a table and a copy of it")
    {
        auto original = EventTable{};
        REQUIRE(original.insert(make_event("$b", 2U)));
        REQUIRE(original.insert(make_event("$a", 1U)));
        auto copy = original;

        WHEN("the copy is changed")
        {
            copy.modify(copy.find("$a"), [](PersistentEvent& event) {
                event.status = "rejected";
            });
            REQUIRE(copy.insert(make_event("$c", 3U)));

            THEN("the copy sees its change and the original does not")
            {
                REQUIRE(copy.find("$a")->status == "rejected");
                REQUIRE(&*copy.find("$a") != &*original.find("$a"));
                REQUIRE(original.find("$a")->status == "accepted");
                REQUIRE(original.find("$c") == original.end());
                REQUIRE(ids_of(copy.in_stream_order()) == std::vector<std::string>{"$a", "$b", "$c"});
                REQUIRE(indexes_agree_with_rows(original));
                REQUIRE(indexes_agree_with_rows(copy));
            }
        }

        WHEN("the original's rows are extracted")
        {
            auto const rows = original.extract();

            THEN("they come out in arrival order and the table is empty")
            {
                REQUIRE(ids_of(rows) == std::vector<std::string>{"$b", "$a"});
                REQUIRE(original.empty());
                REQUIRE(original.find("$a") == original.end());
                REQUIRE(std::ranges::empty(original.in_stream_order()));
            }
        }
    }
}

SCENARIO("Events hydrated from SQLite out of stream order are found by ID and walked in stream order",
         "[database][event-table][sqlite]")
{
    GIVEN("a SQLite store whose events were committed out of stream order")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        REQUIRE(merovingian::database::store_room(opened.store, {"!room:example.org", "@alice:example.org"}));
        REQUIRE(merovingian::database::store_event(opened.store, make_event("$late", 3U)));
        REQUIRE(merovingian::database::store_event(opened.store, make_event("$early", 1U)));
        REQUIRE(merovingian::database::store_event(opened.store, make_event("$middle", 2U)));
        auto const ids = std::vector<std::string>{"$early", "$middle", "$late"};

        WHEN("the store is reopened")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);
            auto const& events = reopened.store.events;

            THEN("every event is found by ID and the stream-order walk is ascending")
            {
                for (auto const& id : ids)
                {
                    REQUIRE(events.find(id) != events.end());
                }
                REQUIRE(stream_order_of(events, ids) == ids);
                REQUIRE(indexes_agree_with_rows(events));
            }
        }

        WHEN("an event's status is updated and another is redacted, and the store is reopened")
        {
            REQUIRE(merovingian::database::set_event_status(opened.store, "$early", "soft_failed"));
            REQUIRE(merovingian::database::replace_event_json(opened.store, "$middle",
                                                              R"({"type":"m.room.message","content":{}})"));
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("both stores find the updated rows by ID and keep them in stream order")
            {
                auto const check = [&ids](merovingian::database::PersistentStore const& store) {
                    auto const& events = store.events;
                    REQUIRE(events.find("$early")->status == "soft_failed");
                    REQUIRE(merovingian::database::find_event_status(store, "$early") == "soft_failed");
                    REQUIRE(events.find("$middle")->json == R"({"type":"m.room.message","content":{}})");
                    REQUIRE(events.find("$late")->status == "accepted");
                    REQUIRE(stream_order_of(events, ids) == ids);
                    REQUIRE(indexes_agree_with_rows(events));
                };
                check(opened.store);
                check(reopened.store);
            }
        }
        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Reloading a room from SQLite keeps both event indexes consistent", "[database][event-table][sqlite]")
{
    GIVEN("two handles on one SQLite file, the first holding an event in another room")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto first = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(first.ok);
        REQUIRE(merovingian::database::store_room(first.store, {"!other:example.org", "@alice:example.org"}));
        REQUIRE(merovingian::database::store_event(first.store, make_event("$other", 2U, "!other:example.org")));
        auto second = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(second.ok);

        WHEN("the second handle commits a room out of stream order and the first reloads it")
        {
            REQUIRE(merovingian::database::store_room(second.store, {"!room:example.org", "@alice:example.org"}));
            REQUIRE(merovingian::database::store_event(second.store, make_event("$three", 3U)));
            REQUIRE(merovingian::database::store_event(second.store, make_event("$one", 1U)));
            REQUIRE(merovingian::database::reload_room(first.store, "!room:example.org"));
            auto const& events = first.store.events;

            THEN("the reloaded and the untouched events are found by ID and merged in stream order")
            {
                REQUIRE(events.find("$one") != events.end());
                REQUIRE(events.find("$three") != events.end());
                REQUIRE(events.find("$other")->room_id == "!other:example.org");
                REQUIRE(stream_order_of(events, {"$one", "$other", "$three"}) ==
                        std::vector<std::string>{"$one", "$other", "$three"});
                REQUIRE(indexes_agree_with_rows(events));
            }

            AND_WHEN("the room is reloaded again")
            {
                REQUIRE(merovingian::database::reload_room(first.store, "!room:example.org"));

                THEN("no event is held twice and the indexes still agree")
                {
                    REQUIRE(first.store.events.size() == 3U);
                    REQUIRE(indexes_agree_with_rows(first.store.events));
                }
            }
        }
        std::filesystem::remove(sqlite_path);
    }
}
