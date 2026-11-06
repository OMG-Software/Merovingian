// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The (room_id, event_type, state_key) index over `PersistentStore::state` (security audit run-2,
// F-32, ADR-0344). Every writer keeps it in step with the rows, hydration and reload_room rebuild
// it, and a vector edited behind the store's back is answered by a scan, never wrongly.

#include "../support/temp_directory.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;

constexpr auto room_id = std::string_view{"!room:example.org"};
constexpr auto other_room_id = std::string_view{"!other:example.org"};
constexpr auto alice = std::string_view{"@alice:example.org"};

// A state event of `type` and `state_key` in `room`, stored so that store_state accepts the row.
auto store_state_event(db::PersistentStore& store, std::string_view room, std::string_view type,
                       std::string_view state_key, std::string event_id, std::uint64_t position) -> void
{
    auto event = db::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = std::string{room};
    event.sender_user_id = std::string{alice};
    event.depth = position;
    event.stream_ordering = position;
    event.json = std::string{R"({"type":")"} + std::string{type} + R"(","state_key":")" + std::string{state_key} +
                 R"(","room_id":")" + std::string{room} + R"(","sender":"@alice:example.org","content":{}})";
    REQUIRE(db::store_event(store, std::move(event)));
    REQUIRE(db::store_state(store, {std::string{room}, std::string{type}, std::string{state_key}, event_id}));
}

[[nodiscard]] auto row_ids_of(db::PersistentStore const& store, std::string_view room) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    db::for_each_room_state_row(store, room, [&ids](db::PersistentStateEvent const& row) {
        ids.push_back(row.event_id);
    });
    return ids;
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() / ("merovingian-state-index-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("The state index answers lookups and stays in step with every state write", "[database][state-index][f32]")
{
    GIVEN("a store holding state in two rooms, written through store_state")
    {
        auto store = db::PersistentStore{};
        store_state_event(store, room_id, "m.room.create", "", "$create", 1U);
        store_state_event(store, room_id, "m.space.child", "!child1:example.org", "$child1", 2U);
        store_state_event(store, other_room_id, "m.room.create", "", "$other_create", 3U);

        WHEN("the index is inspected")
        {
            THEN("it covers every row, so a lookup does not scan")
            {
                REQUIRE(store.state_indexed_rows == store.state.size());
                REQUIRE(store.state.size() == 3U);
            }

            THEN("a lookup finds the current event of each key and nothing for an absent one")
            {
                REQUIRE(db::find_current_state_event_id(store, room_id, "m.room.create", "") ==
                        std::optional<std::string>{"$create"});
                REQUIRE(db::find_current_state_event_id(store, room_id, "m.space.child", "!child1:example.org") ==
                        std::optional<std::string>{"$child1"});
                REQUIRE_FALSE(
                    db::find_current_state_event_id(store, room_id, "m.space.child", "!nope:example.org").has_value());
                REQUIRE_FALSE(
                    db::find_current_state_event_id(store, "!unknown:example.org", "m.room.create", "").has_value());
            }

            THEN("a room's walk visits that room's rows only, in the order they were stored")
            {
                REQUIRE(row_ids_of(store, room_id) == std::vector<std::string>{"$create", "$child1"});
                REQUIRE(row_ids_of(store, other_room_id) == std::vector<std::string>{"$other_create"});
                REQUIRE(row_ids_of(store, "!unknown:example.org").empty());
            }
        }

        WHEN("a key's state is replaced and another key is added")
        {
            store_state_event(store, room_id, "m.space.child", "!child1:example.org", "$child1_v2", 4U);
            store_state_event(store, room_id, "m.space.child", "!child2:example.org", "$child2", 5U);

            THEN("the lookup returns the replacing event, the new key is found, and the index is in step")
            {
                REQUIRE(store.state_indexed_rows == store.state.size());
                REQUIRE(db::find_current_state_event_id(store, room_id, "m.space.child", "!child1:example.org") ==
                        std::optional<std::string>{"$child1_v2"});
                REQUIRE(db::find_current_state_event_id(store, room_id, "m.space.child", "!child2:example.org") ==
                        std::optional<std::string>{"$child2"});
                REQUIRE(row_ids_of(store, room_id) == std::vector<std::string>{"$create", "$child1_v2", "$child2"});
            }
        }
    }

    GIVEN("a store whose state vector was edited directly, behind the index")
    {
        auto store = db::PersistentStore{};
        store_state_event(store, room_id, "m.room.create", "", "$create", 1U);
        store.state.push_back({std::string{room_id}, "m.room.topic", "", "$topic"});

        WHEN("it is asked for the row that was pushed directly")
        {
            THEN("the answer is still right, from a scan")
            {
                REQUIRE(store.state_indexed_rows != store.state.size());
                REQUIRE(db::find_current_state_event_id(store, room_id, "m.room.topic", "") ==
                        std::optional<std::string>{"$topic"});
                REQUIRE(row_ids_of(store, room_id) == std::vector<std::string>{"$create", "$topic"});
            }
        }

        WHEN("the index is rebuilt")
        {
            db::rebuild_state_index(store);

            THEN("it is in step again and gives the same answers")
            {
                REQUIRE(store.state_indexed_rows == store.state.size());
                REQUIRE(db::find_current_state_event_id(store, room_id, "m.room.topic", "") ==
                        std::optional<std::string>{"$topic"});
                REQUIRE(row_ids_of(store, room_id) == std::vector<std::string>{"$create", "$topic"});
            }
        }
    }
}

SCENARIO("Hydration and reload_room rebuild the state index", "[database][state-index][sqlite][f32]")
{
    GIVEN("a main store with a room's state and a second store opened on the same file")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto main_open = db::open_sqlite_persistent_store(path.string());
        REQUIRE(main_open.ok);
        auto& main_store = main_open.store;
        REQUIRE(db::store_room(main_store, {std::string{room_id}, std::string{alice}}));
        store_state_event(main_store, room_id, "m.room.create", "", "$create", 1U);
        auto worker_open = db::open_sqlite_persistent_store(path.string());
        REQUIRE(worker_open.ok);
        auto& worker = worker_open.store;

        WHEN("the second store has hydrated")
        {
            THEN("its index covers the hydrated rows and finds them")
            {
                REQUIRE(worker.state.size() == 1U);
                REQUIRE(worker.state_indexed_rows == worker.state.size());
                REQUIRE(db::find_current_state_event_id(worker, room_id, "m.room.create", "") ==
                        std::optional<std::string>{"$create"});
            }
        }

        WHEN("main stores more state and the second store reloads the room")
        {
            store_state_event(main_store, room_id, "m.space.child", "!child1:example.org", "$child1", 2U);
            REQUIRE(db::reload_room(worker, room_id));

            THEN("the second store's index is in step and finds the new row")
            {
                REQUIRE(worker.state.size() == 2U);
                REQUIRE(worker.state_indexed_rows == worker.state.size());
                REQUIRE(db::find_current_state_event_id(worker, room_id, "m.space.child", "!child1:example.org") ==
                        std::optional<std::string>{"$child1"});
                REQUIRE(row_ids_of(worker, room_id) == std::vector<std::string>{"$create", "$child1"});
            }
        }

        std::filesystem::remove(path);
    }
}
