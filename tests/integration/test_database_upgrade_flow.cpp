// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The schema's upgrade path (ADR-0216, ADR-0224). Every pre-1.0 migration is
// collapsed into the one v1 step, so these scenarios show what the path does
// today: a fresh database is built at v1 in its final shape, the forward-only
// seam (migrate_*_schema_to) never moves past this build or backwards, and a
// database a pre-1.0 build created is refused rather than misread. Upgrade
// compatibility is promised from 1.0.0; when a v2 migration exists, the
// "any older schema version" scenario starts to cover it, and when 1.1 starts
// a fixture written by the last 1.0.x release joins them.
#include "../support/temp_directory.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/database/schema.hpp"
#include "scratch_postgresql_database.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <libpq-fe.h>
#include <sqlite3.h>

namespace
{

[[nodiscard]] auto unique_sqlite_path(std::string_view label) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-upgrade-" + std::string{label} + "-" + std::to_string(now) + ".sqlite3");
}

struct SqliteClose final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        sqlite3_close(connection);
    }
};

struct SqliteFinalize final
{
    auto operator()(sqlite3_stmt* statement) const noexcept -> void
    {
        sqlite3_finalize(statement);
    }
};

// Prepares one statement on a connection that creates the file if it is
// missing, with every value bound as text.
class SqliteQuery final
{
public:
    SqliteQuery(std::filesystem::path const& path, std::string const& sql, std::vector<std::string> values)
        : values_{std::move(values)}
    {
        auto* raw = static_cast<sqlite3*>(nullptr);
        auto const opened =
            sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        connection_ = std::unique_ptr<sqlite3, SqliteClose>{raw};
        if (opened != SQLITE_OK)
        {
            return;
        }
        auto* raw_statement = static_cast<sqlite3_stmt*>(nullptr);
        if (sqlite3_prepare_v2(connection_.get(), sql.c_str(), -1, &raw_statement, nullptr) != SQLITE_OK)
        {
            return;
        }
        statement_ = std::unique_ptr<sqlite3_stmt, SqliteFinalize>{raw_statement};
        // A null destructor is SQLITE_STATIC (whose macro is an old-style cast):
        // `values_` outlives every step, so SQLite need not copy them.
        for (auto index = std::size_t{0U}; index < values_.size(); ++index)
        {
            if (sqlite3_bind_text(statement_.get(), static_cast<int>(index + 1U), values_[index].c_str(),
                                  static_cast<int>(values_[index].size()), nullptr) != SQLITE_OK)
            {
                statement_.reset();
                return;
            }
        }
    }

    // One step: true when it ran to completion.
    [[nodiscard]] auto execute() -> bool
    {
        return statement_ != nullptr && sqlite3_step(statement_.get()) == SQLITE_DONE;
    }

    // The first column of the first row as an integer, or -1 when there is none.
    [[nodiscard]] auto first_integer() -> std::int64_t
    {
        if (statement_ == nullptr || sqlite3_step(statement_.get()) != SQLITE_ROW)
        {
            return -1;
        }
        return sqlite3_column_int64(statement_.get(), 0);
    }

private:
    std::vector<std::string> values_{};
    std::unique_ptr<sqlite3, SqliteClose> connection_{};
    std::unique_ptr<sqlite3_stmt, SqliteFinalize> statement_{};
};

[[nodiscard]] auto sqlite_execute(std::filesystem::path const& path, std::string const& sql,
                                  std::vector<std::string> values = {}) -> bool
{
    return SqliteQuery{path, sql, std::move(values)}.execute();
}

[[nodiscard]] auto sqlite_count(std::filesystem::path const& path, std::string const& sql,
                                std::vector<std::string> values = {}) -> std::int64_t
{
    return SqliteQuery{path, sql, std::move(values)}.first_integer();
}

struct PgFinish final
{
    auto operator()(PGconn* connection) const noexcept -> void
    {
        PQfinish(connection);
    }
};

struct PgClear final
{
    auto operator()(PGresult* result) const noexcept -> void
    {
        PQclear(result);
    }
};

[[nodiscard]] auto pg_query(std::string const& conninfo, std::string const& sql, std::vector<std::string> const& values)
    -> std::unique_ptr<PGresult, PgClear>
{
    auto const connection = std::unique_ptr<PGconn, PgFinish>{PQconnectdb(conninfo.c_str())};
    if (PQstatus(connection.get()) != CONNECTION_OK)
    {
        return {};
    }
    auto pointers = std::vector<char const*>{};
    std::ranges::transform(values, std::back_inserter(pointers), [](std::string const& value) {
        return value.c_str();
    });
    return std::unique_ptr<PGresult, PgClear>{
        PQexecParams(connection.get(), sql.c_str(), static_cast<int>(pointers.size()), nullptr,
                     pointers.empty() ? nullptr : pointers.data(), nullptr, nullptr, 0)};
}

[[nodiscard]] auto pg_execute(std::string const& conninfo, std::string const& sql,
                              std::vector<std::string> const& values = {}) -> bool
{
    auto const result = pg_query(conninfo, sql, values);
    auto const status = PQresultStatus(result.get());
    return status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK;
}

// The first column of the first row as an integer, or -1 when there is none.
[[nodiscard]] auto pg_count(std::string const& conninfo, std::string const& sql,
                            std::vector<std::string> const& values = {}) -> std::int64_t
{
    auto const result = pg_query(conninfo, sql, values);
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK || PQntuples(result.get()) < 1)
    {
        return -1;
    }
    return std::stoll(PQgetvalue(result.get(), 0, 0));
}

[[nodiscard]] auto postgresql_uri_from_environment() -> std::string
{
    auto const* value = std::getenv("MEROVINGIAN_TEST_POSTGRESQL_URI");
    return value == nullptr ? std::string{} : std::string{value};
}

[[nodiscard]] auto has_table(merovingian::database::SchemaState const& state, std::string_view table) -> bool
{
    return std::ranges::find(state.tables, table) != state.tables.end();
}

// Columns the pre-1.0 chain ALTERed onto an existing table, which the v1 step
// now creates with the table.
struct FoldedColumn final
{
    std::string table{};
    std::string column{};
};

[[nodiscard]] auto folded_columns() -> std::vector<FoldedColumn>
{
    return {
        {"account_threepids",  "client_secret"           },
        {"account_threepids",  "sid"                     },
        {"pushers",            "data_extra_json"         },
        {"users",              "deactivated"             },
        {"events",             "status"                  },
        {"state_groups",       "parent_state_group_id"   },
        {"state_groups",       "delta_depth"             },
        {"media",              "legacy_endpoint_visible" },
        {"media",              "upload_name"             },
        {"refresh_tokens",     "predecessor_hash"        },
        {"access_tokens",      "predecessor_refresh_hash"},
        {"rooms",              "directory_public"        },
        {"to_device_messages", "created_at_ms"           },
        {"remote_media",       "local_media_id"          },
        {"remote_media",       "fetched_at_ms"           },
        {"room_aliases",       "creator_user_id"         },
    };
}

constexpr auto v1_index_names = std::array{
    std::string_view{"event_edges_prev_event_id"},
    std::string_view{"idx_to_device_messages_recipient_age"},
    std::string_view{"idx_deferred_pdus_room_id"},
    std::string_view{"idx_media_pending_uploads_owner"},
};

// Versions 2 to 26 of the ledger every pre-1.0 build up to 0.12.46 wrote, after
// its v1 row (also named initial_schema).
constexpr auto pre_collapse_step_names = std::array{
    std::string_view{"sync_stream_watermark"},
    std::string_view{"event_stream_watermark"},
    std::string_view{"state_transitions"},
    std::string_view{"backfill_state_transitions"},
    std::string_view{"account_threepids"},
    std::string_view{"account_threepids_columns"},
    std::string_view{"pushers"},
    std::string_view{"notifications"},
    std::string_view{"openid_tokens"},
    std::string_view{"pushers_data_extra"},
    std::string_view{"login_tokens"},
    std::string_view{"appservice_txn_cursor"},
    std::string_view{"user_deactivation"},
    std::string_view{"event_graph_state"},
    std::string_view{"media_legacy_endpoint_visibility"},
    std::string_view{"token_rotation_lineage"},
    std::string_view{"room_directory_visibility"},
    std::string_view{"to_device_queue_age_bound"},
    std::string_view{"remote_media_cache_mapping"},
    std::string_view{"room_alias_creator"},
    std::string_view{"appservice_outbox"},
    std::string_view{"deferred_pdus"},
    std::string_view{"receipts"},
    std::string_view{"appservice_directory"},
    std::string_view{"media_upload_names_and_pending_uploads"},
};

constexpr auto pre_collapse_ledger_rows = static_cast<std::int64_t>(pre_collapse_step_names.size() + 1U);

} // namespace

SCENARIO("A SQLite schema is built at v1 and stops there", "[database][upgrade][sqlite]")
{
    GIVEN("no database file")
    {
        auto const path = unique_sqlite_path("stop");
        std::filesystem::remove(path);

        WHEN("the schema is migrated to v1")
        {
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(path.string(), 1U);

            THEN("the schema is at v1, recorded by one ledger row, with every current table")
            {
                REQUIRE(migrated.ok);
                REQUIRE(migrated.state.version == 1U);
                REQUIRE(migrated.state.applied_migrations.size() == 1U);
                REQUIRE(migrated.state.applied_migrations.front().name == "initial_schema");
                for (auto const table : merovingian::database::current_schema_tables())
                {
                    INFO("table " << table);
                    REQUIRE(has_table(migrated.state, table));
                }
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A SQLite schema is never migrated past this build", "[database][upgrade][sqlite]")
{
    GIVEN("a database at the current version")
    {
        auto const path = unique_sqlite_path("bounds");
        std::filesystem::remove(path);
        REQUIRE(merovingian::database::migrate_sqlite_schema_to(path.string(),
                                                                merovingian::database::current_schema_version())
                    .ok);

        WHEN("it is asked for a version newer than this build knows")
        {
            auto const ahead = merovingian::database::migrate_sqlite_schema_to(
                path.string(), merovingian::database::current_schema_version() + 1U);

            THEN("it refuses and the schema stays where it was")
            {
                REQUIRE_FALSE(ahead.ok);
                auto const again = merovingian::database::migrate_sqlite_schema_to(
                    path.string(), merovingian::database::current_schema_version());
                REQUIRE(again.ok);
                REQUIRE(again.state.version == merovingian::database::current_schema_version());
            }
        }

        WHEN("it is asked for version 0, which no schema has")
        {
            auto const zero = merovingian::database::migrate_sqlite_schema_to(path.string(), 0U);

            THEN("it refuses")
            {
                REQUIRE_FALSE(zero.ok);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A SQLite database that cannot be opened is refused", "[database][upgrade][sqlite]")
{
    GIVEN("a database path whose parent is a regular file, not a directory")
    {
        auto const parent = unique_sqlite_path("not-a-directory");
        {
            auto output = std::ofstream{parent};
            output << "not a directory" << '\n';
        }
        auto const path = parent / "merovingian.sqlite3";

        WHEN("the schema is migrated to the current version")
        {
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(
                path.string(), merovingian::database::current_schema_version());

            THEN("it refuses and leaves the file as it was")
            {
                REQUIRE_FALSE(migrated.ok);
                REQUIRE(std::filesystem::is_regular_file(parent));
            }
        }
        std::filesystem::remove(parent);
    }
}

// Tables the v1 step did not create, with no ledger to say what they are, must
// not be adopted: the step fails on them, records nothing, and nothing is served.
SCENARIO("A SQLite database holding tables but no schema ledger is refused, not adopted", "[database][upgrade][sqlite]")
{
    GIVEN("a SQLite database with a users table of another shape and no schema_migrations")
    {
        auto const path = unique_sqlite_path("unexpected");
        std::filesystem::remove(path);
        REQUIRE(sqlite_execute(path, "CREATE TABLE users (name TEXT)"));

        WHEN("it is migrated to v1")
        {
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(path.string(), 1U);

            THEN("the migration fails and records no ledger")
            {
                REQUIRE_FALSE(migrated.ok);
                REQUIRE(sqlite_count(path, "SELECT count(*) FROM sqlite_master WHERE name = 'schema_migrations'") == 0);
            }
        }

        WHEN("it is opened as a persistent store")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());

            THEN("the store refuses to open rather than serve a schema it did not build")
            {
                REQUIRE_FALSE(opened.ok);
            }
        }
        std::filesystem::remove(path);
    }
}

// Covers nothing while v1 is the only version; it starts to test every forward
// migration as soon as a v2 exists.
SCENARIO("A SQLite database at any older schema version opens at the current version", "[database][upgrade][sqlite]")
{
    GIVEN("one database for every schema version older than this build's")
    {
        auto paths = std::vector<std::filesystem::path>{};
        for (auto version = std::uint32_t{1U}; version < merovingian::database::current_schema_version(); ++version)
        {
            auto path = unique_sqlite_path("v" + std::to_string(version));
            std::filesystem::remove(path);
            REQUIRE(merovingian::database::migrate_sqlite_schema_to(path.string(), version).ok);
            paths.push_back(std::move(path));
        }

        WHEN("each is opened as a persistent store")
        {
            auto versions = std::vector<std::uint32_t>{};
            for (auto const& path : paths)
            {
                auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());
                versions.push_back(opened.ok ? opened.store.schema.version : 0U);
            }

            THEN("every one is migrated to the current version")
            {
                REQUIRE(versions.size() == paths.size());
                REQUIRE(std::ranges::all_of(versions, [](std::uint32_t version) {
                    return version == merovingian::database::current_schema_version();
                }));
            }
        }
        for (auto const& path : paths)
        {
            std::filesystem::remove(path);
        }
    }
}

SCENARIO("A fresh SQLite database has every column and index of the v1 schema", "[database][upgrade][sqlite][collapse]")
{
    GIVEN("no database file")
    {
        auto const path = unique_sqlite_path("shape");
        std::filesystem::remove(path);

        WHEN("it is opened as a persistent store")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);

            THEN("each column the pre-1.0 chain added later is already on its table")
            {
                for (auto const& [table, column] : folded_columns())
                {
                    INFO("table " << table << " column " << column);
                    REQUIRE(sqlite_count(path, "SELECT count(*) FROM pragma_table_info(?1) WHERE name = ?2",
                                         {table, column}) == 1);
                }
            }

            AND_THEN("each index the store's lookups rely on exists")
            {
                for (auto const index : v1_index_names)
                {
                    INFO("index " << index);
                    REQUIRE(sqlite_count(path, "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                                         {std::string{index}}) == 1);
                }
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A SQLite database a pre-1.0 build created is refused, not upgraded",
         "[database][upgrade][sqlite][collapse][security]")
{
    GIVEN("a SQLite database whose ledger records the 26 migrations a pre-1.0 build applied")
    {
        auto const path = unique_sqlite_path("pre-collapse");
        std::filesystem::remove(path);
        REQUIRE(merovingian::database::migrate_sqlite_schema_to(path.string(), 1U).ok);
        for (auto index = std::size_t{0U}; index < pre_collapse_step_names.size(); ++index)
        {
            REQUIRE(sqlite_execute(path, "INSERT INTO schema_migrations VALUES (?1, ?2, 'upgrade')",
                                   {std::to_string(index + 2U), std::string{pre_collapse_step_names[index]}}));
        }

        WHEN("it is opened as a persistent store, or migrated")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(
                path.string(), merovingian::database::current_schema_version());

            THEN("both refuse, the open says why, and the ledger is left as it was")
            {
                REQUIRE_FALSE(opened.ok);
                INFO("reason: " << opened.reason);
                REQUIRE(opened.reason.find("migration this build does not have") != std::string::npos);
                REQUIRE_FALSE(migrated.ok);
                REQUIRE(sqlite_count(path, "SELECT count(*) FROM schema_migrations") == pre_collapse_ledger_rows);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A PostgreSQL schema is built at v1 and stops there", "[database][upgrade][postgresql][integration]")
{
    GIVEN("an empty PostgreSQL database")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());

        WHEN("the schema is migrated to v1")
        {
            auto const migrated = merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 1U);

            THEN("the schema is at v1, recorded by one ledger row, with every current table")
            {
                REQUIRE(migrated.ok);
                REQUIRE(migrated.state.version == 1U);
                REQUIRE(migrated.state.applied_migrations.size() == 1U);
                for (auto const table : merovingian::database::current_schema_tables())
                {
                    INFO("table " << table);
                    REQUIRE(has_table(migrated.state, table));
                }
            }
        }
    }
}

SCENARIO("A PostgreSQL schema is never migrated past this build", "[database][upgrade][postgresql][integration]")
{
    GIVEN("a PostgreSQL database at the current version")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        REQUIRE(merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(),
                                                                    merovingian::database::current_schema_version())
                    .ok);

        WHEN("it is asked for a version newer than this build knows, or for version 0")
        {
            auto const ahead = merovingian::database::migrate_postgresql_schema_to(
                scratch.conninfo(), merovingian::database::current_schema_version() + 1U);
            auto const zero = merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 0U);

            THEN("both are refused and the schema stays where it was")
            {
                REQUIRE_FALSE(ahead.ok);
                REQUIRE_FALSE(zero.ok);
                auto const again = merovingian::database::migrate_postgresql_schema_to(
                    scratch.conninfo(), merovingian::database::current_schema_version());
                REQUIRE(again.ok);
                REQUIRE(again.state.version == merovingian::database::current_schema_version());
            }
        }
    }
}

// libpq reads a URI's query after its path, so a dbname there would send the
// "scratch" connection back to the shared database (PR #536 review).
SCENARIO("A scratch database's connection string names only the scratch database", "[database][postgresql][scratch]")
{
    GIVEN("connection strings for the shared database, some naming it again in the query")
    {
        auto const cases = std::vector<std::pair<std::string, std::string>>{
            {"postgresql://u:p@db.test:5432/shared?dbname=shared&sslmode=disable",
             "postgresql://u:p@db.test:5432/scratch?sslmode=disable"                                                                  },
            {"postgresql://db.test/shared?sslmode=require&%64bname=shared&connect_timeout=5",
             "postgresql://db.test/scratch?sslmode=require&connect_timeout=5"                                                         },
            {"postgresql://db.test/shared?dbname=shared",                                     "postgresql://db.test/scratch"          },
            {"postgres://db.test?dbname=shared",                                              "postgres://db.test/scratch"            },
            {"postgresql://db.test/shared",                                                   "postgresql://db.test/scratch"          },
            {"postgresql://db.test/shared?dbnamex=1",                                         "postgresql://db.test/scratch?dbnamex=1"},
        };

        WHEN("each is pointed at the scratch database")
        {
            THEN("the path names it and no query parameter names another")
            {
                for (auto const& [shared, expected] : cases)
                {
                    INFO("conninfo " << shared);
                    REQUIRE(merovingian::tests::conninfo_for_database(shared, "scratch") == expected);
                }
            }

            AND_THEN("a keyword/value string gets the scratch dbname last, which libpq uses")
            {
                REQUIRE(merovingian::tests::conninfo_for_database("host=db.test dbname=shared", "scratch") ==
                        "host=db.test dbname=shared dbname=scratch");
            }
        }
    }
}

SCENARIO("A PostgreSQL server that cannot be reached is refused", "[database][upgrade][postgresql]")
{
    GIVEN("a connection string for a loopback port with nothing listening")
    {
        auto const conninfo = std::string{"postgresql://merovingian_test@127.0.0.1:1/merovingian_test?sslmode=disable"};

        WHEN("the schema is migrated to the current version")
        {
            auto const migrated = merovingian::database::migrate_postgresql_schema_to(
                conninfo, merovingian::database::current_schema_version());

            THEN("it refuses")
            {
                REQUIRE_FALSE(migrated.ok);
            }
        }
    }
}

SCENARIO("A fresh PostgreSQL database has every column and index of the v1 schema",
         "[database][upgrade][postgresql][integration][collapse]")
{
    GIVEN("an empty PostgreSQL database")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());

        WHEN("it is opened as a persistent store")
        {
            auto const opened = merovingian::database::open_postgresql_persistent_store(scratch.conninfo());
            INFO("open refused: " << opened.reason);
            REQUIRE(opened.ok);

            THEN("each column the pre-1.0 chain added later is already on its table")
            {
                for (auto const& [table, column] : folded_columns())
                {
                    INFO("table " << table << " column " << column);
                    REQUIRE(pg_count(scratch.conninfo(),
                                     "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' "
                                     "AND table_name = $1 AND column_name = $2",
                                     {table, column}) == 1);
                }
            }

            AND_THEN("each index the store's lookups rely on exists")
            {
                for (auto const index : v1_index_names)
                {
                    INFO("index " << index);
                    REQUIRE(pg_count(scratch.conninfo(),
                                     "SELECT count(*) FROM pg_indexes WHERE schemaname = 'public' AND indexname = $1",
                                     {std::string{index}}) == 1);
                }
            }
        }
    }
}

SCENARIO("A PostgreSQL database a pre-1.0 build created is refused, not upgraded",
         "[database][upgrade][postgresql][integration][collapse][security]")
{
    GIVEN("a PostgreSQL database whose ledger records the 26 migrations a pre-1.0 build applied")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        REQUIRE(merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 1U).ok);
        for (auto index = std::size_t{0U}; index < pre_collapse_step_names.size(); ++index)
        {
            REQUIRE(pg_execute(scratch.conninfo(), "INSERT INTO schema_migrations VALUES ($1, $2, 'upgrade')",
                               {std::to_string(index + 2U), std::string{pre_collapse_step_names[index]}}));
        }

        WHEN("it is opened as a persistent store, or migrated")
        {
            auto const opened = merovingian::database::open_postgresql_persistent_store(scratch.conninfo());
            auto const migrated = merovingian::database::migrate_postgresql_schema_to(
                scratch.conninfo(), merovingian::database::current_schema_version());

            THEN("both refuse, the open says why, and the ledger is left as it was")
            {
                REQUIRE_FALSE(opened.ok);
                INFO("reason: " << opened.reason);
                REQUIRE(opened.reason.find("migration this build does not have") != std::string::npos);
                REQUIRE_FALSE(migrated.ok);
                REQUIRE(pg_count(scratch.conninfo(), "SELECT count(*) FROM schema_migrations") ==
                        pre_collapse_ledger_rows);
            }
        }
    }
}
