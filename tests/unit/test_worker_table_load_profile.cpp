// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// The federation_worker table load profile (ADR-0062 part 2): which tables a store opened with it hydrates, and a
// classification of every table the migrations create against that allowlist. The worker itself opens no database
// since ADR-0733; the allowlist still bounds what a federation_worker-profile store holds, and the key-pipe scenarios
// below cover the one secret main still hands the worker at spawn.

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/WorkerSupervisor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

// ---- source-tree consistency helpers ----------------------------------
//
// These read the checked-in migrations -- not runtime data -- to prove that
// every table migrations/*.sql creates is classified somewhere.
// MEROVINGIAN_TEST_SOURCE_ROOT is a test-only compile definition (see
// tests/meson.build) naming the project source root, the same
// -DMEROVINGIAN_TEST_* pattern used elsewhere in this suite to locate
// sibling build artifacts.

[[nodiscard]] auto source_root() -> std::filesystem::path
{
#ifdef MEROVINGIAN_TEST_SOURCE_ROOT
    return std::filesystem::path{MEROVINGIAN_TEST_SOURCE_ROOT};
#else
    return std::filesystem::current_path();
#endif
}

[[nodiscard]] auto read_whole_file(std::filesystem::path const& path) -> std::string
{
    auto input = std::ifstream{path, std::ios::binary};
    REQUIRE(input.is_open());
    auto buffer = std::ostringstream{};
    buffer << input.rdbuf();
    return buffer.str();
}

// Extracts the identifier starting at `pos` (letters, digits, underscore),
// skipping any leading whitespace.
[[nodiscard]] auto next_identifier(std::string_view text, std::size_t pos) -> std::string
{
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])) != 0)
    {
        ++pos;
    }
    auto const start = pos;
    while (pos < text.size() && (std::isalnum(static_cast<unsigned char>(text[pos])) != 0 || text[pos] == '_'))
    {
        ++pos;
    }
    return std::string{text.substr(start, pos - start)};
}

// Parses every `CREATE TABLE [IF NOT EXISTS] <name>` out of a migration
// file's SQL statements.
[[nodiscard]] auto parse_created_tables(std::string const& sql) -> std::set<std::string>
{
    auto created = std::set<std::string>{};
    auto pos = std::size_t{0U};
    auto const needle = std::string_view{"CREATE TABLE"};
    while ((pos = sql.find(needle, pos)) != std::string::npos)
    {
        auto cursor = pos + needle.size();
        auto const if_not_exists = std::string_view{" IF NOT EXISTS "};
        if (sql.compare(cursor, if_not_exists.size(), if_not_exists) == 0)
        {
            cursor += if_not_exists.size();
        }
        // The v1 migration quotes every table name ("users"), as the build's
        // generated DDL does.
        while (cursor < sql.size() && std::isspace(static_cast<unsigned char>(sql[cursor])) != 0)
        {
            ++cursor;
        }
        if (cursor < sql.size() && sql[cursor] == '"')
        {
            ++cursor;
        }
        auto name = next_identifier(sql, cursor);
        std::ranges::transform(name, name.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (!name.empty())
        {
            created.insert(name);
        }
        pos = cursor;
    }
    return created;
}

[[nodiscard]] auto all_migration_created_tables() -> std::set<std::string>
{
    auto created = std::set<std::string>{};
    auto const migrations_dir = source_root() / "migrations";
    REQUIRE(std::filesystem::exists(migrations_dir));
    for (auto const& entry : std::filesystem::directory_iterator{migrations_dir})
    {
        if (entry.path().extension() != ".sql")
        {
            continue;
        }
        auto const tables = parse_created_tables(read_whole_file(entry.path()));
        created.insert(tables.begin(), tables.end());
    }
    return created;
}

[[nodiscard]] auto cpp_allowlist_as_set() -> std::set<std::string>
{
    auto allowlist = std::set<std::string>{};
    for (auto const& table : merovingian::database::federation_worker_table_allowlist)
    {
        allowlist.emplace(table);
    }
    return allowlist;
}

// Every table PersistentStore can hold that is NOT in the worker allowlist,
// confirmed by tracing every worker-reachable code path during the N1 part 2
// review (see docs/database-persistence.md, "Every table classified",
// and PersistentStore.hpp's
// federation_worker_table_allowlist doc comment for the file:line citations
// behind each classification) rather than merely "probably relayed". A table
// created by a migration but absent from BOTH this list and the C++
// allowlist fails the classification scenario below, so a new table cannot
// go unclassified.
[[nodiscard]] auto worker_never_reads_tables() -> std::set<std::string>
{
    return {
        "users",
        "devices",
        "access_tokens",
        "refresh_tokens",
        "federation_destinations",
        "federation_transactions",
        "invites",
        "state_transitions",
        "sync_stream_watermark",
        "event_stream_watermark",
        "stream_token_epoch",
        "device_keys",
        "one_time_keys",
        "fallback_keys",
        "cross_signing_keys",
        "key_signatures",
        "key_backup_versions",
        "key_backup_version_counters",
        "key_backup_sessions",
        "media",
        "media_blobs",
        "remote_media",
        "audit_log",
        "admin_actions",
        "policy_rules",
        "account_data",
        "room_account_data",
        "to_device_messages",
        "device_list_changes",
        "presence_state",
        "filters",
        "profiles",
        "account_threepids",
        "client_txn_ids",
        "pushers",
        "notifications",
        "openid_tokens",
        "login_tokens",
        "appservice_txn_cursor",
        "appservice_outbox",
        // R03: PDUs main retains for a retry. Written and read by main only;
        // the worker relays every PDU to main and never sees this table.
        "deferred_pdus",
        // ADR-0169: read receipts. Written and read by main only; the worker
        // relays receipt EDUs to main and never computes unread counts.
        "receipts",
        // ADR-0192: rooms an appservice published to one of its networks. Main only; the worker serves no
        // client directory.
        "appservice_directory",
        // ADR-0212: mxc:// URIs reserved by POST /_matrix/media/v1/create.
        // The client API and the federation media download run in main.
        "media_pending_uploads",
        // Vestigial: declared in src/database/Schema.cpp's DDL but never
        // populated or queried by any runtime code path, main's or the
        // worker's (confirmed by grep finding no reference outside
        // Schema.cpp). state_groups was vestigial too until 0.12.13's
        // ADR-0064 phase A (migration 015) gave it real readers and
        // extended it with parent_state_group_id/delta_depth -- it now
        // belongs to the worker allowlist above, not here.
        // state_group_edges remains vestigial; ADR-0064 phase A deliberately
        // left it alone (see docs/database-persistence.md).
        "event_json",
        "key_backups",
        "push_rules",
        "rate_limits",
        "room_versions",
        "state_group_edges",
    };
}

// Tables read by every process (main and worker alike), not gated by
// TableLoadProfile at all: schema_migrations is read via
// database::load_schema_state before any profile-specific row hydration
// begins, for any store to open.
[[nodiscard]] auto ungated_infrastructure_tables() -> std::set<std::string>
{
    return {"schema_migrations"};
}

} // namespace

// ---- F. load profile: which tables the worker pulls into memory --------

SCENARIO("The full load profile includes every table, including secret-bearing ones",
         "[database][worker_table_profile]")
{
    GIVEN("the full load profile")
    {
        constexpr auto profile = merovingian::database::TableLoadProfile::full;

        THEN("secret-bearing tables are included")
        {
            REQUIRE(merovingian::database::table_load_profile_includes("server_signing_keys", profile));
            REQUIRE(merovingian::database::table_load_profile_includes("users", profile));
            REQUIRE(merovingian::database::table_load_profile_includes("access_tokens", profile));
            REQUIRE(merovingian::database::table_load_profile_includes("refresh_tokens", profile));
            REQUIRE(merovingian::database::table_load_profile_includes("login_tokens", profile));
            REQUIRE(merovingian::database::table_load_profile_includes("openid_tokens", profile));
            REQUIRE(merovingian::database::table_load_profile_includes("account_threepids", profile));
        }
        AND_THEN("an ordinary room-scoped table is included")
        {
            REQUIRE(merovingian::database::table_load_profile_includes("rooms", profile));
        }
    }
}

SCENARIO("The federation_worker load profile excludes every table outside the allowlist",
         "[database][worker_table_profile]")
{
    GIVEN("the federation_worker load profile")
    {
        constexpr auto profile = merovingian::database::TableLoadProfile::federation_worker;

        THEN("credential-bearing tables the worker never needs are excluded")
        {
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("users", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("access_tokens", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("refresh_tokens", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("login_tokens", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("openid_tokens", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("account_threepids", profile));
        }
        AND_THEN("an arbitrary non-allowlisted table is excluded, proving this is a fail-closed allowlist "
                 "rather than a denylist")
        {
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("some_future_migration_table", profile));
        }
    }
}

SCENARIO("server_signing_keys is allowlisted at the table level for the federation worker load profile "
         "(the secret_key column restriction is enforced separately, in the SQL query)",
         "[database][worker_table_profile]")
{
    GIVEN("the federation_worker load profile")
    {
        constexpr auto profile = merovingian::database::TableLoadProfile::federation_worker;

        THEN("server_signing_keys itself is included, for the worker's remote-key cache reads")
        {
            REQUIRE(merovingian::database::table_load_profile_includes("server_signing_keys", profile));
        }
    }
}

SCENARIO("The federation_worker load profile still includes the room-scoped tables federation needs",
         "[database][worker_table_profile]")
{
    GIVEN("the federation_worker load profile")
    {
        constexpr auto profile = merovingian::database::TableLoadProfile::federation_worker;

        THEN("rooms, events, and state remain available for make_join/backfill/state routes")
        {
            REQUIRE(merovingian::database::table_load_profile_includes("rooms", profile));
            REQUIRE(merovingian::database::table_load_profile_includes("events", profile));
            REQUIRE(merovingian::database::table_load_profile_includes("current_state", profile));
            REQUIRE(merovingian::database::table_load_profile_includes("membership", profile));
        }
    }
}

// ---- the IPC key pipe: the one secret main hands the worker at spawn ----

SCENARIO("The worker key pipe refuses empty material", "[federation][worker-supervisor][worker_table_profile]")
{
    GIVEN("no key material")
    {
        auto const bytes = std::vector<std::uint8_t>{};

        WHEN("the supervisor prepares the key pipe")
        {
            THEN("it fails closed instead of handing the worker an empty pipe")
            {
                REQUIRE_THROWS(merovingian::homeserver::make_worker_key_pipe(bytes));
            }
        }
    }
}

SCENARIO("The fixed worker fd numbers are two, distinct, and past the standard streams",
         "[federation][worker-supervisor][worker_table_profile]")
{
    GIVEN("the fixed child fd numbers")
    {
        WHEN("they are compared")
        {
            THEN("the key fd collides with neither the IPC socket nor stdio")
            {
                REQUIRE(merovingian::homeserver::kWorkerIpcFd > 2);
                REQUIRE(merovingian::homeserver::kWorkerIpcKeyFd > 2);
                REQUIRE(merovingian::homeserver::kWorkerIpcKeyFd != merovingian::homeserver::kWorkerIpcFd);
            }
        }
    }
}

// ---- source-tree consistency: every migration table is classified ------

SCENARIO("Every table migrations/*.sql creates is classified as worker-allowlisted, "
         "never-read-by-the-worker, or ungated infrastructure",
         "[database][worker_table_profile]")
{
    GIVEN("every CREATE TABLE statement in migrations/*.sql, and the three classification sets")
    {
        auto const created = all_migration_created_tables();
        auto const allowlisted = cpp_allowlist_as_set();
        auto const never_read = worker_never_reads_tables();
        auto const ungated = ungated_infrastructure_tables();

        WHEN("every created table is looked up across the three sets")
        {
            THEN("each table belongs to exactly one of the three classifications")
            {
                REQUIRE_FALSE(created.empty());
                for (auto const& table : created)
                {
                    auto const in_allowlist = allowlisted.contains(table);
                    auto const in_never_read = never_read.contains(table);
                    auto const in_ungated = ungated.contains(table);
                    auto const classifications =
                        static_cast<int>(in_allowlist) + static_cast<int>(in_never_read) + static_cast<int>(in_ungated);
                    INFO("table: " << table << " allowlist=" << in_allowlist << " never_read=" << in_never_read
                                   << " ungated=" << in_ungated);
                    REQUIRE(classifications == 1);
                }
            }
            AND_THEN("no classified table name is stale (renamed or dropped) relative to the schema")
            {
                for (auto const& table : allowlisted)
                {
                    INFO("allowlisted table no longer created by any migration: " << table);
                    REQUIRE(created.contains(table));
                }
                for (auto const& table : never_read)
                {
                    INFO("never-read table no longer created by any migration: " << table);
                    REQUIRE(created.contains(table));
                }
                for (auto const& table : ungated)
                {
                    INFO("ungated table no longer created by any migration: " << table);
                    REQUIRE(created.contains(table));
                }
            }
        }
    }
}
