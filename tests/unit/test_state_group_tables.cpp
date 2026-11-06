// SPDX-License-Identifier: GPL-3.0-or-later

// F-07 / F-15, ADR-0325: the state-group tables (`state_groups`, `state_group_state`,
// `event_state_groups`) keep hash indexes, so the lookups the ingest path, local compose and the
// federation read filters make cost the key's rows and not a pass over every room's rows. Tags:
// [state_group_tables][database].
//
// Spec: no spec rule (a server-internal storage structure). What the indexes must preserve is the
// result of the state-before and visibility reads the Server-Server API specifies: "Checks performed
// on receipt of a PDU" and "Room State Resolution".

#include "../support/state_group_scan.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/state_group_tables.hpp"
#include "merovingian/events/limits.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;

constexpr auto rooms_in_store = std::size_t{40U};
constexpr auto groups_per_room = std::size_t{4U};

[[nodiscard]] auto group_id_of(std::size_t room, std::size_t index) -> std::string
{
    return "sg:" + std::to_string(room) + ":" + std::to_string(index);
}

[[nodiscard]] auto event_id_of(std::size_t room, std::size_t index) -> std::string
{
    return "$" + std::to_string(room) + "-" + std::to_string(index);
}

[[nodiscard]] auto room_id_of(std::size_t room) -> std::string
{
    return "!" + std::to_string(room) + ":local.example";
}

// Fills the tables with `rooms_in_store` rooms: each a snapshot group and `groups_per_room - 1` deltas,
// two entries per group, and one event mapped to each group.
auto fill_tables(db::StateGroupTable& groups, db::StateGroupEntryTable& entries, db::EventStateGroupTable& mappings)
    -> void
{
    for (auto room = std::size_t{0U}; room < rooms_in_store; ++room)
    {
        for (auto index = std::size_t{0U}; index < groups_per_room; ++index)
        {
            auto const parent =
                index == 0U ? std::optional<std::string>{} : std::optional<std::string>{group_id_of(room, index - 1U)};
            REQUIRE(
                groups.insert({group_id_of(room, index), room_id_of(room), parent, static_cast<std::uint32_t>(index)}));
            entries.insert(
                {group_id_of(room, index), "m.room.member", "@a" + std::to_string(index), event_id_of(room, index)});
            entries.insert({group_id_of(room, index), "m.room.topic", "", event_id_of(room, index)});
            mappings.assign(event_id_of(room, index), group_id_of(room, index));
        }
    }
}

[[nodiscard]] auto entry_ids(db::StateGroupEntryTable const& entries, std::string const& group_id)
    -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const& entry : entries.entries_of(group_id))
    {
        ids.push_back(entry.event_type + "/" + entry.state_key + "/" + entry.event_id);
    }
    return ids;
}

[[nodiscard]] auto entry_ids_by_scan(db::StateGroupEntryTable const& entries, std::string const& group_id)
    -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const& entry : entries)
    {
        if (entry.state_group_id == group_id)
        {
            ids.push_back(entry.event_type + "/" + entry.state_key + "/" + entry.event_id);
        }
    }
    return ids;
}

[[nodiscard]] auto tables_agree_with_scans(db::StateGroupTable const& groups, db::StateGroupEntryTable const& entries,
                                           db::EventStateGroupTable const& mappings) -> bool
{
    for (auto room = std::size_t{0U}; room < rooms_in_store; ++room)
    {
        for (auto index = std::size_t{0U}; index < groups_per_room; ++index)
        {
            auto const group_id = group_id_of(room, index);
            auto const event_id = event_id_of(room, index);
            auto scanned_group = groups.end();
            for (auto it = groups.begin(); it != groups.end(); ++it)
            {
                if (it->state_group_id == group_id)
                {
                    scanned_group = it;
                    break;
                }
            }
            if (groups.find(group_id) != scanned_group)
            {
                return false;
            }
            if (entry_ids(entries, group_id) != entry_ids_by_scan(entries, group_id) ||
                entries.count_of(group_id) != entry_ids_by_scan(entries, group_id).size())
            {
                return false;
            }
            auto scanned_mapping = std::optional<std::string>{};
            for (auto const& mapping : mappings)
            {
                if (mapping.event_id == event_id)
                {
                    scanned_mapping = mapping.state_group_id;
                }
            }
            auto const indexed = mappings.state_group_of(event_id);
            if (indexed.has_value() != scanned_mapping.has_value() ||
                (indexed.has_value() && std::string{*indexed} != *scanned_mapping))
            {
                return false;
            }
        }
    }
    return true;
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-state-group-tables-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("State-group lookups agree with a scan of the rows across writes and removals",
         "[state_group_tables][database]")
{
    GIVEN("tables holding many rooms' groups, entries and event mappings")
    {
        auto groups = db::StateGroupTable{};
        auto entries = db::StateGroupEntryTable{};
        auto mappings = db::EventStateGroupTable{};
        fill_tables(groups, entries, mappings);

        WHEN("they have only been written to")
        {
            THEN("every indexed lookup equals a scan of the rows")
            {
                REQUIRE(groups.size() == rooms_in_store * groups_per_room);
                REQUIRE(entries.size() == rooms_in_store * groups_per_room * 2U);
                REQUIRE(tables_agree_with_scans(groups, entries, mappings));
            }
            THEN("a key the tables do not hold finds nothing")
            {
                REQUIRE(groups.find("sg:absent") == groups.end());
                REQUIRE(entries.count_of("sg:absent") == 0U);
                REQUIRE(entry_ids(entries, "sg:absent").empty());
                REQUIRE_FALSE(mappings.state_group_of("$absent").has_value());
            }
        }

        WHEN("a second row with a held group ID is inserted")
        {
            auto const added = groups.insert({group_id_of(3U, 1U), "!intruder:local.example", std::nullopt, 0U});

            THEN("the first row is kept and the table does not grow")
            {
                REQUIRE_FALSE(added);
                REQUIRE(groups.size() == rooms_in_store * groups_per_room);
                REQUIRE(groups.find(group_id_of(3U, 1U))->room_id == room_id_of(3U));
            }
        }

        WHEN("an event is assigned a different group")
        {
            mappings.assign(event_id_of(5U, 2U), group_id_of(5U, 0U));

            THEN("its one row names the other group and no row is added")
            {
                REQUIRE(mappings.size() == rooms_in_store * groups_per_room);
                REQUIRE(mappings.state_group_of(event_id_of(5U, 2U)) ==
                        std::optional<std::string_view>{group_id_of(5U, 0U)});
            }
        }

        WHEN("one room's rows are removed from every table")
        {
            auto const room_groups = [](db::PersistentStateGroup const& group) {
                return group.room_id == room_id_of(7U);
            };
            auto removed_ids = std::vector<std::string>{};
            for (auto const& group : groups)
            {
                if (room_groups(group))
                {
                    removed_ids.push_back(group.state_group_id);
                }
            }
            REQUIRE(removed_ids.size() == groups_per_room);
            REQUIRE(groups.erase_if(room_groups) == groups_per_room);
            REQUIRE(entries.erase_if([&](db::PersistentStateGroupStateEntry const& entry) {
                return std::ranges::find(removed_ids, entry.state_group_id) != removed_ids.end();
            }) == groups_per_room * 2U);
            REQUIRE(mappings.erase_if([&](db::PersistentEventStateGroup const& mapping) {
                return std::ranges::find(removed_ids, mapping.state_group_id) != removed_ids.end();
            }) == groups_per_room);

            THEN("that room finds nothing and every other room still equals a scan")
            {
                REQUIRE(groups.find(group_id_of(7U, 0U)) == groups.end());
                REQUIRE(entries.count_of(group_id_of(7U, 2U)) == 0U);
                REQUIRE_FALSE(mappings.state_group_of(event_id_of(7U, 3U)).has_value());
                REQUIRE(groups.size() == (rooms_in_store - 1U) * groups_per_room);
                REQUIRE(entries.size() == (rooms_in_store - 1U) * groups_per_room * 2U);
                for (auto room = std::size_t{0U}; room < rooms_in_store; ++room)
                {
                    if (room == 7U)
                    {
                        continue;
                    }
                    for (auto index = std::size_t{0U}; index < groups_per_room; ++index)
                    {
                        REQUIRE(groups.find(group_id_of(room, index)) != groups.end());
                        REQUIRE(entry_ids(entries, group_id_of(room, index)) ==
                                entry_ids_by_scan(entries, group_id_of(room, index)));
                        REQUIRE(entries.count_of(group_id_of(room, index)) == 2U);
                        REQUIRE(mappings.state_group_of(event_id_of(room, index)) ==
                                std::optional<std::string_view>{group_id_of(room, index)});
                    }
                }
            }

            AND_WHEN("the removed rows are written again")
            {
                for (auto index = std::size_t{0U}; index < groups_per_room; ++index)
                {
                    REQUIRE(groups.insert({group_id_of(7U, index), room_id_of(7U), std::nullopt, 0U}));
                    entries.insert({group_id_of(7U, index), "m.room.topic", "", event_id_of(7U, index)});
                    mappings.assign(event_id_of(7U, index), group_id_of(7U, index));
                }

                THEN("the lookups find them again")
                {
                    REQUIRE(groups.find(group_id_of(7U, 1U)) != groups.end());
                    REQUIRE(entries.count_of(group_id_of(7U, 1U)) == 1U);
                    REQUIRE(mappings.state_group_of(event_id_of(7U, 1U)) ==
                            std::optional<std::string_view>{group_id_of(7U, 1U)});
                }
            }
        }

        WHEN("the tables are copied and the original is cleared")
        {
            auto const groups_copy = groups;
            auto const entries_copy = entries;
            auto const mappings_copy = mappings;
            groups.clear();
            entries.clear();
            mappings.clear();

            THEN("the copies answer from their own index and the originals find nothing")
            {
                REQUIRE(tables_agree_with_scans(groups_copy, entries_copy, mappings_copy));
                REQUIRE(groups.find(group_id_of(0U, 0U)) == groups.end());
                REQUIRE(entries.count_of(group_id_of(0U, 0U)) == 0U);
                REQUIRE_FALSE(mappings.state_group_of(event_id_of(0U, 0U)).has_value());
            }
        }
    }
}

SCENARIO("Reading one group's entries visits only that group's rows, however many other rooms there are",
         "[state_group_tables][database]")
{
    GIVEN("a group with three entries")
    {
        auto entries = db::StateGroupEntryTable{};
        for (auto index = std::size_t{0U}; index < 3U; ++index)
        {
            entries.insert({"sg:target", "m.room.member", "@u" + std::to_string(index), "$t" + std::to_string(index)});
        }

        auto const rows_visited = [&](std::string const& group_id) {
            auto count = std::size_t{0U};
            for (auto const& entry : entries.entries_of(group_id))
            {
                REQUIRE(entry.state_group_id == group_id);
                ++count;
            }
            return count;
        };
        auto const before = rows_visited("sg:target");

        WHEN("thousands of rows belonging to other groups are added")
        {
            for (auto other = std::size_t{0U}; other < 3000U; ++other)
            {
                entries.insert(
                    {"sg:other-" + std::to_string(other % 500U), "m.room.topic", std::to_string(other), "$o"});
            }

            THEN("the walk of the group's entries visits the same three rows")
            {
                REQUIRE(before == 3U);
                REQUIRE(rows_visited("sg:target") == 3U);
                REQUIRE(entries.size() == 3003U);
            }
        }
    }
}

SCENARIO("A full-state read follows the delta chain through the indexes and equals the rows that make it up",
         "[state_group_tables][database]")
{
    GIVEN("a store holding a snapshot, two deltas, and many unrelated rooms' groups")
    {
        auto store = db::PersistentStore{};
        REQUIRE(db::create_or_reuse_state_group(
                    store, "!room:local.example", "sg:0", std::nullopt,
                    {
                        {"sg:0", "m.room.create", "", "$create"},
                        {"sg:0", "m.room.topic",  "", "$topic0"}
        })
                    .has_value());
        REQUIRE(db::create_or_reuse_state_group(
                    store, "!room:local.example", "sg:1", "sg:0",
                    {
                        {"sg:1", "m.room.create", "", "$create"},
                        {"sg:1", "m.room.topic",  "", "$topic1"}
        })
                    .has_value());
        REQUIRE(db::create_or_reuse_state_group(store, "!room:local.example", "sg:2", "sg:1",
                                                {
                                                    {"sg:2", "m.room.create", "", "$create"},
                                                    {"sg:2", "m.room.topic",  "", "$topic1"},
                                                    {"sg:2", "m.room.name",   "", "$name"  }
        })
                    .has_value());
        for (auto room = std::size_t{0U}; room < 30U; ++room)
        {
            REQUIRE(db::create_or_reuse_state_group(store, room_id_of(room), "sg:r" + std::to_string(room),
                                                    std::nullopt,
                                                    {
                                                        {"", "m.room.create", "", "$c" + std::to_string(room)}
            })
                        .has_value());
        }
        REQUIRE(db::set_event_state_group(store, "$e2", "sg:2"));

        WHEN("the newest group's full state is read")
        {
            auto const full = db::read_state_group_full_state(store, "sg:2");

            THEN("it is the newest value of each key and nothing from another room")
            {
                REQUIRE(full.has_value());
                REQUIRE(full->size() == 3U);
                auto topic = std::string{};
                for (auto const& entry : *full)
                {
                    if (entry.event_type == "m.room.topic")
                    {
                        topic = entry.event_id;
                    }
                    REQUIRE(entry.event_id != "$c0");
                }
                REQUIRE(topic == "$topic1");
                REQUIRE(db::find_event_state_group(store, "$e2") == std::optional<std::string>{"sg:2"});
                REQUIRE(merovingian::tests::state_group_index_mismatch(store).empty());
            }
        }

        WHEN("a group names a parent that is not held")
        {
            REQUIRE_FALSE(db::create_or_reuse_state_group(store, "!room:local.example", "sg:orphan", "sg:missing", {})
                              .has_value());

            THEN("no group is created, and an unknown group reads as absent")
            {
                REQUIRE_FALSE(db::find_state_group(store, "sg:orphan").has_value());
                REQUIRE_FALSE(db::read_state_group_full_state(store, "sg:orphan").has_value());
            }
        }
    }
}

SCENARIO("The state-group indexes are rebuilt identically when a store is opened again and when a room is reloaded",
         "[state_group_tables][database][sqlite][reload]")
{
    GIVEN("a database whose store wrote groups for two rooms")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto main_open = db::open_sqlite_persistent_store(path.string());
        REQUIRE(main_open.ok);
        auto& main_store = main_open.store;
        for (auto room = std::size_t{0U}; room < 2U; ++room)
        {
            REQUIRE(db::store_room(main_store, {room_id_of(room), "@a:local.example"}));
            REQUIRE(db::create_or_reuse_state_group(main_store, room_id_of(room), group_id_of(room, 0U), std::nullopt,
                                                    {
                                                        {"", "m.room.create", "", event_id_of(room, 0U)}
            })
                        .has_value());
            REQUIRE(db::create_or_reuse_state_group(main_store, room_id_of(room), group_id_of(room, 1U),
                                                    group_id_of(room, 0U),
                                                    {
                                                        {"", "m.room.create", "", event_id_of(room, 0U)},
                                                        {"", "m.room.topic",  "", event_id_of(room, 1U)}
            })
                        .has_value());
            REQUIRE(db::set_event_state_group(main_store, event_id_of(room, 0U), group_id_of(room, 0U)));
            REQUIRE(db::set_event_state_group(main_store, event_id_of(room, 1U), group_id_of(room, 1U)));
        }
        REQUIRE(merovingian::tests::state_group_index_mismatch(main_store).empty());

        WHEN("the database is opened again")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);

            THEN("the hydrated indexes equal a scan and equal main's lookups")
            {
                REQUIRE(merovingian::tests::state_group_index_mismatch(reopened.store).empty());
                REQUIRE(reopened.store.state_groups.size() == main_store.state_groups.size());
                REQUIRE(db::find_event_state_group(reopened.store, event_id_of(1U, 1U)) ==
                        std::optional<std::string>{group_id_of(1U, 1U)});
                auto const full = db::read_state_group_full_state(reopened.store, group_id_of(0U, 1U));
                REQUIRE(full.has_value());
                REQUIRE(full->size() == 2U);
            }
        }

        WHEN("main writes more to one room and a store opened earlier reloads that room")
        {
            auto worker = db::open_sqlite_persistent_store(path.string());
            REQUIRE(worker.ok);
            REQUIRE(db::create_or_reuse_state_group(main_store, room_id_of(0U), group_id_of(0U, 2U),
                                                    group_id_of(0U, 1U),
                                                    {
                                                        {"", "m.room.create", "", event_id_of(0U, 0U)},
                                                        {"", "m.room.topic",  "", event_id_of(0U, 2U)}
            })
                        .has_value());
            auto message = db::PersistentEvent{};
            message.event_id = event_id_of(0U, 2U);
            message.room_id = room_id_of(0U);
            message.sender_user_id = "@a:local.example";
            message.depth = 3U;
            message.stream_ordering = 3U;
            message.json = R"({"type":"m.room.message","sender":"@a:local.example","origin_server_ts":3,"content":{}})";
            REQUIRE(db::store_event(main_store, std::move(message)));
            REQUIRE(db::set_event_state_group(main_store, event_id_of(0U, 2U), group_id_of(0U, 2U)));
            REQUIRE_FALSE(db::find_event_state_group(worker.store, event_id_of(0U, 2U)).has_value());
            REQUIRE(db::reload_room(worker.store, room_id_of(0U)));
            REQUIRE(db::reload_room(worker.store, room_id_of(0U)));

            THEN("the reloaded indexes equal a scan, find the added rows and still find the other room's")
            {
                REQUIRE(merovingian::tests::state_group_index_mismatch(worker.store).empty());
                REQUIRE(db::find_event_state_group(worker.store, event_id_of(0U, 2U)) ==
                        std::optional<std::string>{group_id_of(0U, 2U)});
                // A delta stores only the entries it changes: the topic.
                REQUIRE(worker.store.state_group_state.count_of(group_id_of(0U, 2U)) == 1U);
                REQUIRE(db::find_event_state_group(worker.store, event_id_of(1U, 1U)) ==
                        std::optional<std::string>{group_id_of(1U, 1U)});
                REQUIRE(worker.store.state_groups.size() == main_store.state_groups.size());
                REQUIRE(worker.store.state_group_state.size() == main_store.state_group_state.size());
                REQUIRE(worker.store.event_state_groups.size() == main_store.event_state_groups.size());
            }
        }

        std::filesystem::remove(path);
    }
}
