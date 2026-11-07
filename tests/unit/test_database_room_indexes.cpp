// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/temp_directory.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <chrono>
#include <filesystem>
#include <string>

namespace
{

// The query plan SQLite chooses for `sql`, one line per step.
[[nodiscard]] auto query_plan(std::string const& path, std::string const& sql) -> std::string
{
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
    sqlite3_stmt* statement = nullptr;
    REQUIRE(sqlite3_prepare_v2(raw, ("EXPLAIN QUERY PLAN " + sql).c_str(), -1, &statement, nullptr) == SQLITE_OK);
    auto plan = std::string{};
    while (sqlite3_step(statement) == SQLITE_ROW)
    {
        plan += reinterpret_cast<char const*>(sqlite3_column_text(statement, 3));
        plan += '\n';
    }
    sqlite3_finalize(statement);
    sqlite3_close(raw);
    return plan;
}

} // namespace

SCENARIO("A room is reloaded from the events and state groups tables by index, not by scanning them",
         "[database][sqlite][index][p12]")
{
    GIVEN("a freshly created SQLite store")
    {
        auto const path = (merovingian::tests::temporary_directory() /
                           ("merovingian-room-index-" +
                            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3"))
                              .string();
        auto const opened = merovingian::database::open_sqlite_persistent_store(path);
        REQUIRE(opened.ok);

        WHEN("the planner is asked how it reads one room's events and state groups")
        {
            auto const events = query_plan(path, "SELECT event_id FROM events WHERE room_id = '!r:example.org'");
            auto const groups =
                query_plan(path, "SELECT state_group_id FROM state_groups WHERE room_id = '!r:example.org'");
            auto const joined =
                query_plan(path, "SELECT e.event_id FROM event_edges e INNER JOIN events ev ON ev.event_id = "
                                 "e.event_id WHERE ev.room_id = '!r:example.org'");

            THEN("each is a search through an index on room_id")
            {
                REQUIRE(events.find("idx_events_room_id") != std::string::npos);
                REQUIRE(groups.find("idx_state_groups_room_id") != std::string::npos);
                REQUIRE(joined.find("idx_events_room_id") != std::string::npos);
            }
        }

        std::filesystem::remove(path);
    }
}
