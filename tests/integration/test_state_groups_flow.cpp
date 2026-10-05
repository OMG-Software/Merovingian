// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Integration tests for ADR-0064 phase A: applying migration 015 against a
// real SQLite database that already holds a pre-015 room, and (gated, like
// every other live-database scenario in this suite) against PostgreSQL.
// See docs/adr/0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md
// and tests/integration/AGENTS.md.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <merovingian/database/migration.hpp>
#include <merovingian/database/persistent_store.hpp>
#include <merovingian/database/postgresql_store.hpp>
#include <merovingian/database/schema.hpp>
#include <sqlite3.h>

namespace
{

using merovingian::database::migration_direction_name;
using merovingian::database::migration_plan_between;
using merovingian::database::MigrationDirection;
using merovingian::database::open_sqlite_persistent_store;
using merovingian::database::PersistentStore;

[[nodiscard]] auto unique_test_suffix() -> std::string
{
    static auto const base = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    static auto counter = std::uint64_t{0U};
    return std::to_string(base) + "-" + std::to_string(counter++);
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    return std::filesystem::temp_directory_path() / ("merovingian-state-groups-" + unique_test_suffix() + ".sqlite3");
}

// Executes `sql` directly against a raw SQLite connection. Every statement
// this file needs to run (the v1..v14 migration catalog, and the hand-seeded
// pre-existing-room rows) is parameter-free, so plain sqlite3_exec is enough
// -- no prepared-statement binding is needed to bring a database to v14
// before exercising migration 015 for real through the public API.
[[nodiscard]] auto exec(sqlite3& connection, std::string const& sql) -> bool
{
    char* error_message = nullptr;
    auto const rc = sqlite3_exec(&connection, sql.c_str(), nullptr, nullptr, &error_message);
    if (error_message != nullptr)
    {
        sqlite3_free(error_message);
    }
    return rc == SQLITE_OK;
}

// Brings a fresh SQLite file to exactly schema version `target_version` by
// executing the real migration catalog's statements (from
// migration_plan_between, the same catalog sqlite_store.cpp's runtime
// startup path applies) and recording each step's schema_migrations ledger
// row, all through raw SQLite calls. This stands in for the private
// migration-execution loop inside sqlite_store.cpp, which is not exported,
// so a test that needs a database frozen at a specific pre-upgrade version
// (rather than one already migrated to current_schema_version()) has to
// replicate it.
[[nodiscard]] auto bootstrap_sqlite_to_version(sqlite3& connection, std::uint32_t target_version) -> bool
{
    auto const plan = migration_plan_between(0U, target_version);
    for (auto const& step : plan.steps)
    {
        for (auto const& statement : step.statements)
        {
            if (!exec(connection, statement.sql))
            {
                return false;
            }
        }
        auto const ledger_row = std::string{"INSERT INTO schema_migrations VALUES ('"} + std::to_string(step.version) +
                                "', '" + step.name + "', '" + std::string{migration_direction_name(step.direction)} +
                                "')";
        if (!exec(connection, ledger_row))
        {
            return false;
        }
    }
    return true;
}

struct SeededRoom final
{
    std::string room_id{};
    std::vector<std::string> current_state_event_ids{};
    std::vector<std::string> forward_extremity_event_ids{};
    std::vector<std::string> all_event_ids{};
};

// Seeds one small room directly at the v14 shape: a linear create/join/
// power_levels prefix, then a fork of two message events with no children --
// the forward extremities migration 015 must discover.
[[nodiscard]] auto seed_pre_v15_room(sqlite3& connection, std::string_view suffix) -> SeededRoom
{
    auto room = SeededRoom{};
    room.room_id = "!seed-" + std::string{suffix} + ":example.org";
    auto const create_id = "$create-" + std::string{suffix};
    auto const join_id = "$join-" + std::string{suffix};
    auto const power_id = "$power-" + std::string{suffix};
    auto const msg_a_id = "$msg-a-" + std::string{suffix};
    auto const msg_b_id = "$msg-b-" + std::string{suffix};

    REQUIRE(exec(connection,
                 "INSERT INTO rooms (room_id, creator_user_id) VALUES ('" + room.room_id + "', '@alice:example.org')"));

    auto const insert_event = [&](std::string const& event_id, std::uint64_t depth, std::uint64_t stream_ordering) {
        return exec(connection, "INSERT INTO events (event_id, room_id, sender_user_id, json, depth, "
                                "stream_ordering) VALUES ('" +
                                    event_id + "', '" + room.room_id + "', '@alice:example.org', '{}', '" +
                                    std::to_string(depth) + "', '" + std::to_string(stream_ordering) + "')");
    };
    REQUIRE(insert_event(create_id, 1U, 1U));
    REQUIRE(insert_event(join_id, 2U, 2U));
    REQUIRE(insert_event(power_id, 3U, 3U));
    REQUIRE(insert_event(msg_a_id, 4U, 4U));
    REQUIRE(insert_event(msg_b_id, 4U, 5U));
    room.all_event_ids = {create_id, join_id, power_id, msg_a_id, msg_b_id};

    auto const insert_edge = [&](std::string const& event_id, std::string const& prev_event_id) {
        return exec(connection, "INSERT INTO event_edges VALUES ('" + event_id + "', '" + prev_event_id + "')");
    };
    REQUIRE(insert_edge(join_id, create_id));
    REQUIRE(insert_edge(power_id, join_id));
    REQUIRE(insert_edge(msg_a_id, power_id));
    REQUIRE(insert_edge(msg_b_id, power_id));
    room.forward_extremity_event_ids = {msg_a_id, msg_b_id};

    auto const insert_state = [&](std::string const& event_type, std::string const& state_key,
                                  std::string const& event_id) {
        return exec(connection, "INSERT INTO current_state VALUES ('" + room.room_id + "', '" + event_type + "', '" +
                                    state_key + "', '" + event_id + "')");
    };
    REQUIRE(insert_state("m.room.create", "", create_id));
    REQUIRE(insert_state("m.room.member", "@alice:example.org", join_id));
    REQUIRE(insert_state("m.room.power_levels", "", power_id));
    room.current_state_event_ids = {create_id, join_id, power_id};

    return room;
}

// RAII wrappers for the raw SQLite handles this file drives directly (no
// owning raw pointers, per coding-rules.md), mirroring the
// SqliteConnection/SqliteStatement pattern in src/database/sqlite_store.cpp.
struct SqliteConnectionDeleter final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        sqlite3_close(connection);
    }
};

using SqliteConnectionHandle = std::unique_ptr<sqlite3, SqliteConnectionDeleter>;

struct SqliteStatementDeleter final
{
    auto operator()(sqlite3_stmt* statement) const noexcept -> void
    {
        sqlite3_finalize(statement);
    }
};

using SqliteStatementHandle = std::unique_ptr<sqlite3_stmt, SqliteStatementDeleter>;

// SQLITE_TRANSIENT expands to an old-style C cast ((sqlite3_destructor_type)-1),
// which trips -Wold-style-cast -Werror if used directly; sqlite_store.cpp's own
// sqlite_transient_destructor() works around the same thing the same way.
[[nodiscard]] auto sqlite_transient_destructor() noexcept -> sqlite3_destructor_type
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<sqlite3_destructor_type>(-1);
}

[[nodiscard]] auto open_sqlite_connection_raii(std::string const& path) -> SqliteConnectionHandle
{
    auto* raw_connection = static_cast<sqlite3*>(nullptr);
    auto const rc = sqlite3_open(path.c_str(), &raw_connection);
    auto connection = SqliteConnectionHandle{raw_connection};
    if (rc != SQLITE_OK)
    {
        return nullptr;
    }
    return connection;
}

// Runs `EXPLAIN QUERY PLAN SELECT 1 FROM event_edges WHERE prev_event_id =
// ?1` and concatenates every returned row's "detail" column (the plan text
// SQLite reports for each step, e.g. "SEARCH event_edges USING INDEX ..." or
// "SCAN event_edges") -- the migration-015 index scenario asserts on this
// text to prove the seeding query (and, later, phase B's children-of-event
// lookup) can use an index rather than a full table scan.
[[nodiscard]] auto event_edges_prev_event_id_query_plan(sqlite3& connection) -> std::string
{
    auto const sql = std::string{"EXPLAIN QUERY PLAN SELECT 1 FROM event_edges WHERE prev_event_id = ?1"};
    auto* raw_statement = static_cast<sqlite3_stmt*>(nullptr);
    REQUIRE(sqlite3_prepare_v2(&connection, sql.c_str(), static_cast<int>(sql.size()), &raw_statement, nullptr) ==
            SQLITE_OK);
    auto statement = SqliteStatementHandle{raw_statement};
    REQUIRE(statement != nullptr);
    REQUIRE(sqlite3_bind_text(statement.get(), 1, "$example-event", -1, sqlite_transient_destructor()) == SQLITE_OK);

    auto detail = std::string{};
    while (sqlite3_step(statement.get()) == SQLITE_ROW)
    {
        auto const* text = reinterpret_cast<char const*>(sqlite3_column_text(statement.get(), 3));
        if (text != nullptr)
        {
            if (!detail.empty())
            {
                detail += " | ";
            }
            detail += text;
        }
    }
    return detail;
}

} // namespace

SCENARIO("Migration 015 seeds a snapshot state group for a room that already existed at v14",
         "[state_groups][database][integration][migration]")
{
    GIVEN("a SQLite database bootstrapped to schema v14 with one pre-existing room")
    {
        auto const path = unique_sqlite_path();
        auto connection = open_sqlite_connection_raii(path.string());
        REQUIRE(connection != nullptr);
        REQUIRE(bootstrap_sqlite_to_version(*connection, 14U));
        auto const room = seed_pre_v15_room(*connection, "a");
        connection.reset();

        WHEN("the persistent store is opened, applying migration 015 for real")
        {
            auto opened = open_sqlite_persistent_store(path.string());

            THEN("the store reaches the current schema version")
            {
                REQUIRE(opened.ok);
                REQUIRE(opened.store.schema.version == merovingian::database::current_schema_version());
            }

            AND_THEN("a seed snapshot state group exists for the room, equal to its current_state")
            {
                auto const seed_group_id = "seed:" + room.room_id;
                auto const group = merovingian::database::find_state_group(opened.store, seed_group_id);
                REQUIRE(group.has_value());
                REQUIRE_FALSE(group->parent_state_group_id.has_value());
                REQUIRE(group->delta_depth == 0U);

                auto const full_state = merovingian::database::read_state_group_full_state(opened.store, seed_group_id);
                REQUIRE(full_state.has_value());
                REQUIRE(full_state->size() == room.current_state_event_ids.size());
                for (auto const& row : *full_state)
                {
                    auto const found = std::find(room.current_state_event_ids.begin(),
                                                 room.current_state_event_ids.end(), row.event_id);
                    REQUIRE(found != room.current_state_event_ids.end());
                }
            }

            AND_THEN("the room's forward extremities are exactly its childless events")
            {
                auto extremities = merovingian::database::find_forward_extremities(opened.store, room.room_id);
                std::ranges::sort(extremities);
                auto expected = room.forward_extremity_event_ids;
                std::ranges::sort(expected);
                REQUIRE(extremities == expected);
            }

            AND_THEN("each forward extremity maps to the seed state group")
            {
                auto const seed_group_id = "seed:" + room.room_id;
                for (auto const& event_id : room.forward_extremity_event_ids)
                {
                    auto const mapped = merovingian::database::find_event_state_group(opened.store, event_id);
                    REQUIRE(mapped.has_value());
                    REQUIRE(*mapped == seed_group_id);
                }
            }

            AND_THEN("every event's status is accepted")
            {
                for (auto const& event_id : room.all_event_ids)
                {
                    auto const status = merovingian::database::find_event_status(opened.store, event_id);
                    REQUIRE(status.has_value());
                    REQUIRE(*status == "accepted");
                }
            }
        }

        WHEN("the store is opened a second time")
        {
            auto const first_open = open_sqlite_persistent_store(path.string());
            REQUIRE(first_open.ok);
            auto const state_group_count_after_first_open = first_open.store.state_groups.size();
            auto const state_group_state_count_after_first_open = first_open.store.state_group_state.size();
            auto const forward_extremity_count_after_first_open = first_open.store.forward_extremities.size();

            auto const second_open = open_sqlite_persistent_store(path.string());

            THEN("re-running the migration chain is a no-op")
            {
                REQUIRE(second_open.ok);
                REQUIRE(second_open.store.schema.version == merovingian::database::current_schema_version());
                REQUIRE(second_open.store.state_groups.size() == state_group_count_after_first_open);
                REQUIRE(second_open.store.state_group_state.size() == state_group_state_count_after_first_open);
                REQUIRE(second_open.store.forward_extremities.size() == forward_extremity_count_after_first_open);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("event_edges has a usable index for prev_event_id lookups after migration 015",
         "[state_groups][database][integration][migration]")
{
    GIVEN("a SQLite database migrated to the current schema version")
    {
        auto const path = unique_sqlite_path();
        auto opened = open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);

        WHEN("the query planner is asked how it would look up an event's children (migration 015's own seeding "
             "query, and phase B's future ingest-time lookup, both need this)")
        {
            auto connection = open_sqlite_connection_raii(path.string());
            REQUIRE(connection != nullptr);
            auto const plan = event_edges_prev_event_id_query_plan(*connection);

            THEN("it uses an index rather than a full table scan")
            {
                INFO("query plan: " << plan);
                REQUIRE((plan.find("USING INDEX") != std::string::npos ||
                         plan.find("USING COVERING INDEX") != std::string::npos));
                REQUIRE(plan.find("SCAN event_edges") == std::string::npos);
                REQUIRE(plan.find("SCAN g") == std::string::npos);
            }
        }

        std::filesystem::remove(path);
    }
}

namespace
{

[[nodiscard]] auto env_string(char const* name) -> std::string_view
{
    auto const* value = std::getenv(name);
    return value == nullptr ? std::string_view{} : std::string_view{value};
}

[[nodiscard]] auto postgresql_uri_from_environment() -> std::string_view
{
    return env_string("MEROVINGIAN_TEST_POSTGRESQL_URI");
}

} // namespace

SCENARIO("PostgreSQL bootstrap creates the ADR-0064 phase A tables",
         "[state_groups][database][postgresql][integration]")
{
    GIVEN("a live PostgreSQL URI")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            // This suite cannot exercise a live PostgreSQL server from this
            // sandbox (no server is reachable and no
            // MEROVINGIAN_TEST_POSTGRESQL_URI is configured here); the CI
            // workflow that does set it runs this scenario for real. The
            // deeper pre-existing-room seeding scenario above is SQLite-only
            // for the same reason test_postgresql_persistence_flow.cpp's own
            // scenarios are all gated the same way -- see this file's header
            // comment and the project report for why the PostgreSQL seeding
            // path was not additionally replicated here.
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }

        WHEN("the persistent store is opened, applying migration 015 for real")
        {
            auto opened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("the schema reaches the current version and the new tables are present")
            {
                REQUIRE(opened.ok);
                REQUIRE(opened.store.schema.version == merovingian::database::current_schema_version());
                auto const has_table = [&opened](std::string_view name) {
                    return std::ranges::find(opened.store.schema.tables, name) != opened.store.schema.tables.end();
                };
                REQUIRE(has_table("state_groups"));
                REQUIRE(has_table("state_group_state"));
                REQUIRE(has_table("event_state_groups"));
                REQUIRE(has_table("forward_extremities"));
            }
        }
    }
}
