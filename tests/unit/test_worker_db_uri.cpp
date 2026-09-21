// SPDX-License-Identifier: GPL-3.0-or-later

// Finding N1 part 2 (ADR-0062): a separate, least-privilege PostgreSQL login
// for the federation worker, handed over a second inherited pipe fd instead
// of a file the worker opens itself, plus a load profile so the worker never
// pulls secret-bearing tables into its own memory. See
// docs/adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md.

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation_worker/args.hpp"
#include "merovingian/federation_worker/db_uri_fd.hpp"
#include "merovingian/homeserver/worker_supervisor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace
{

using merovingian::core::FileDescriptor;
using merovingian::federation_worker::parse_worker_args;

// ---- shared helpers --------------------------------------------------

[[nodiscard]] auto make_pipe() -> std::pair<FileDescriptor, FileDescriptor>
{
    auto fds = std::array<int, 2>{-1, -1};
    REQUIRE(::pipe(fds.data()) == 0);
    return {FileDescriptor{fds[0]}, FileDescriptor{fds[1]}};
}

auto write_all(int fd, std::vector<std::uint8_t> const& bytes) -> void
{
    auto written = std::size_t{0U};
    while (written < bytes.size())
    {
        auto const rc = ::write(fd, bytes.data() + written, bytes.size() - written);
        REQUIRE(rc > 0);
        written += static_cast<std::size_t>(rc);
    }
}

auto write_all(int fd, std::string const& text) -> void
{
    auto const bytes = std::vector<std::uint8_t>(text.begin(), text.end());
    write_all(fd, bytes);
}

auto parse(std::vector<char const*> const& args) -> merovingian::federation_worker::ParsedWorkerArgs
{
    return parse_worker_args(static_cast<int>(args.size()), args.data());
}

// ---- source-tree consistency helpers ----------------------------------
//
// These read two static, checked-in text files -- not runtime data -- to
// prove two invariants that no purely in-process test can see: that
// packaging/postgresql/provision-federation-worker-role.sql's GRANT SELECT
// list names exactly database::federation_worker_table_allowlist's tables,
// and that every table migrations/*.sql creates is classified somewhere.
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

[[nodiscard]] auto trimmed(std::string_view text) -> std::string_view
{
    auto const first = text.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos)
    {
        return {};
    }
    auto const last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1U);
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

// Parses every table name granted `GRANT SELECT ... ON <table> TO ...`
// (with or without a column list) out of a provision-*.sql file.
[[nodiscard]] auto parse_granted_tables(std::string const& sql) -> std::set<std::string>
{
    auto granted = std::set<std::string>{};
    auto stream = std::istringstream{sql};
    auto line = std::string{};
    while (std::getline(stream, line))
    {
        auto const trimmed_line = trimmed(line);
        if (!trimmed_line.starts_with("GRANT SELECT"))
        {
            continue;
        }
        auto const on_pos = trimmed_line.find(" ON ");
        if (on_pos == std::string_view::npos)
        {
            continue;
        }
        granted.insert(next_identifier(trimmed_line, on_pos + 4U));
    }
    return granted;
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
// review (see docs/database-persistence.md, "Federation worker
// least-privilege role", and persistent_store.hpp's
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
        "device_keys",
        "one_time_keys",
        "fallback_keys",
        "cross_signing_keys",
        "key_signatures",
        "key_backup_versions",
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
        // Vestigial: declared in src/database/schema.cpp's DDL but never
        // populated or queried by any runtime code path, main's or the
        // worker's (confirmed by grep finding no reference outside
        // schema.cpp).
        "event_json",
        "key_backups",
        "push_rules",
        "rate_limits",
        "room_versions",
        "state_group_edges",
        "state_groups",
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

// A postgresql config that otherwise validates cleanly: everything is left
// at its default except the one field each scenario deliberately changes.
// database.backend defaults to postgresql and security.federation.enabled
// defaults to true, which together are exactly the "federation worker
// enabled, PostgreSQL backend" condition this rule gates.
[[nodiscard]] auto default_postgresql_config() -> merovingian::config::Config
{
    return merovingian::config::Config{};
}

} // namespace

// ---- A. config validation matrix --------------------------------------

SCENARIO("A PostgreSQL worker requires a database_uri_file unless credential sharing is opted into",
         "[config][worker_db_uri]")
{
    GIVEN("a PostgreSQL config with the federation worker enabled and no database_uri_file")
    {
        auto config = default_postgresql_config();
        config.federation_worker().database_uri_file.clear();

        WHEN("the config is validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("validation fails, naming federation.worker.database_uri_file")
            {
                REQUIRE_FALSE(findings.empty());
                auto found = false;
                for (auto const& finding : findings)
                {
                    found = found || finding.field == "federation.worker.database_uri_file";
                }
                REQUIRE(found);
            }
        }
    }
}

SCENARIO("allow_shared_database_credentials opts out of the database_uri_file requirement", "[config][worker_db_uri]")
{
    GIVEN("the same config, with allow_shared_database_credentials set")
    {
        auto config = default_postgresql_config();
        config.federation_worker().database_uri_file.clear();
        config.federation_worker().allow_shared_database_credentials = true;

        WHEN("the config is validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("no finding is reported for federation.worker.database_uri_file")
            {
                for (auto const& finding : findings)
                {
                    REQUIRE(finding.field != "federation.worker.database_uri_file");
                }
            }
        }
    }
}

SCENARIO("SQLite backends do not require a federation worker database_uri_file", "[config][worker_db_uri]")
{
    GIVEN("an otherwise-default config switched to the SQLite backend, with no database_uri_file")
    {
        auto config = default_postgresql_config();
        config.database().backend = merovingian::config::DatabaseBackend::sqlite;
        config.federation_worker().database_uri_file.clear();

        WHEN("the config is validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("no finding is reported for federation.worker.database_uri_file")
            {
                for (auto const& finding : findings)
                {
                    REQUIRE(finding.field != "federation.worker.database_uri_file");
                }
            }
        }
    }
}

SCENARIO("A configured database_uri_file satisfies the requirement", "[config][worker_db_uri]")
{
    GIVEN("a PostgreSQL config with an explicit database_uri_file")
    {
        auto config = default_postgresql_config();
        config.federation_worker().database_uri_file = "/etc/merovingian/fed-worker-db-uri";

        WHEN("the config is validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("no finding is reported for federation.worker.database_uri_file")
            {
                for (auto const& finding : findings)
                {
                    REQUIRE(finding.field != "federation.worker.database_uri_file");
                }
            }
        }
    }
}

SCENARIO("A bare default config's placeholder federation worker database_uri_file satisfies validation",
         "[config][worker_db_uri]")
{
    GIVEN("a bare default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the config is validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("the compiled-in placeholder database_uri_file satisfies the requirement")
            {
                REQUIRE_FALSE(config.federation_worker().database_uri_file.empty());
                for (auto const& finding : findings)
                {
                    REQUIRE(finding.field != "federation.worker.database_uri_file");
                }
            }
        }
    }
}

SCENARIO("federation.worker.allow_shared_database_credentials is parsed from key-value config",
         "[config][worker_db_uri][parser]")
{
    GIVEN("key-value configuration enabling the opt-out")
    {
        auto const input = std::string{"federation.worker.allow_shared_database_credentials=true\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the flag is applied")
            {
                REQUIRE(result.config.federation_worker().allow_shared_database_credentials);
            }
        }
    }
}

SCENARIO("federation.worker.database_uri_file is parsed from key-value config", "[config][worker_db_uri][parser]")
{
    GIVEN("key-value configuration setting the worker database URI file")
    {
        auto const input = std::string{"federation.worker.database_uri_file=/run/secrets/fed-worker-db-uri\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the path is applied")
            {
                REQUIRE(result.config.federation_worker().database_uri_file == "/run/secrets/fed-worker-db-uri");
            }
        }
    }
}

SCENARIO("federation.worker.allow_shared_database_credentials rejects a non-boolean value",
         "[config][worker_db_uri][parser]")
{
    GIVEN("key-value configuration with a malformed boolean")
    {
        auto const input = std::string{"federation.worker.allow_shared_database_credentials=maybe\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("a finding is reported")
            {
                auto found = false;
                for (auto const& finding : result.findings)
                {
                    found = found || finding.field == "federation.worker.allow_shared_database_credentials";
                }
                REQUIRE(found);
            }
        }
    }
}

// ---- B. args parsing ---------------------------------------------------

SCENARIO("parse_worker_args treats --db-uri-fd as optional", "[federation-worker][args][worker_db_uri]")
{
    GIVEN("valid required arguments with no --db-uri-fd")
    {
        WHEN("they are parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.conf",
                "--ipc-fd",
                "3",
                "--ipc-key-fd",
                "4",
            });

            THEN("no error is reported and no db-uri fd is captured")
            {
                REQUIRE_FALSE(result.error.has_value());
                REQUIRE_FALSE(result.db_uri_fd.has_value());
            }
        }
    }
}

SCENARIO("parse_worker_args captures a valid --db-uri-fd", "[federation-worker][args][worker_db_uri]")
{
    GIVEN("a --db-uri-fd distinct from the other fixed fds")
    {
        WHEN("it is parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.conf",
                "--ipc-fd",
                "3",
                "--ipc-key-fd",
                "4",
                "--db-uri-fd",
                "5",
            });

            THEN("the value is captured")
            {
                REQUIRE_FALSE(result.error.has_value());
                REQUIRE(result.db_uri_fd == 5);
            }
        }
    }
}

SCENARIO("parse_worker_args rejects a non-numeric --db-uri-fd", "[federation-worker][args][worker_db_uri]")
{
    GIVEN("a --db-uri-fd that is not a number")
    {
        WHEN("it is parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.conf",
                "--ipc-fd",
                "3",
                "--ipc-key-fd",
                "4",
                "--db-uri-fd",
                "not-a-fd",
            });

            THEN("an error is reported")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }
}

SCENARIO("parse_worker_args rejects a --db-uri-fd colliding with --ipc-fd", "[federation-worker][args][worker_db_uri]")
{
    GIVEN("a --db-uri-fd equal to --ipc-fd")
    {
        WHEN("it is parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.conf",
                "--ipc-fd",
                "3",
                "--ipc-key-fd",
                "4",
                "--db-uri-fd",
                "3",
            });

            THEN("an error is reported")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }
}

SCENARIO("parse_worker_args rejects a --db-uri-fd colliding with --ipc-key-fd",
         "[federation-worker][args][worker_db_uri]")
{
    GIVEN("a --db-uri-fd equal to --ipc-key-fd")
    {
        WHEN("it is parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.conf",
                "--ipc-fd",
                "3",
                "--ipc-key-fd",
                "4",
                "--db-uri-fd",
                "4",
            });

            THEN("an error is reported")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }
}

SCENARIO("parse_worker_args rejects a --db-uri-fd naming a standard stream", "[federation-worker][args][worker_db_uri]")
{
    GIVEN("a --db-uri-fd of 0, 1, or 2")
    {
        WHEN("stdin (0) is given")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.conf",
                "--ipc-fd",
                "3",
                "--ipc-key-fd",
                "4",
                "--db-uri-fd",
                "0",
            });

            THEN("an error is reported")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }
}

// ---- C. reading the URI from an inherited fd ---------------------------

SCENARIO("read_worker_database_uri accepts exact content followed by EOF", "[federation-worker][worker_db_uri]")
{
    GIVEN("a pipe carrying a PostgreSQL connection URI, then closed")
    {
        auto [read_fd, write_fd] = make_pipe();
        auto const uri = std::string{"postgresql://fedworker@127.0.0.1/merovingian"};
        write_all(write_fd.get(), uri);
        write_fd.reset();

        WHEN("read_worker_database_uri reads it")
        {
            auto const result = merovingian::federation_worker::read_worker_database_uri(std::move(read_fd));

            THEN("the exact bytes are returned")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->bytes().size() == uri.size());
                for (auto i = std::size_t{0U}; i < uri.size(); ++i)
                {
                    REQUIRE(static_cast<char>(result->bytes()[i]) == uri[i]);
                }
            }
        }
    }
}

SCENARIO("read_worker_database_uri rejects an empty pipe", "[federation-worker][worker_db_uri]")
{
    GIVEN("a pipe closed with nothing written")
    {
        auto [read_fd, write_fd] = make_pipe();
        write_fd.reset();

        WHEN("read_worker_database_uri reads it")
        {
            auto const result = merovingian::federation_worker::read_worker_database_uri(std::move(read_fd));

            THEN("no URI is returned")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("read_worker_database_uri rejects a URI larger than the bounded cap", "[federation-worker][worker_db_uri]")
{
    GIVEN("a pipe carrying more than the maximum accepted bytes")
    {
        auto [read_fd, write_fd] = make_pipe();
        auto const oversized = std::string(merovingian::federation_worker::kMaxWorkerDatabaseUriBytes + 1U, 'x');
        write_all(write_fd.get(), oversized);
        write_fd.reset();

        WHEN("read_worker_database_uri reads it")
        {
            auto const result = merovingian::federation_worker::read_worker_database_uri(std::move(read_fd));

            THEN("it fails closed instead of silently truncating")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("read_worker_database_uri closes the fd it consumes", "[federation-worker][worker_db_uri]")
{
    GIVEN("a pipe carrying a valid URI")
    {
        auto [read_fd, write_fd] = make_pipe();
        write_all(write_fd.get(), std::string{"postgresql://fedworker@127.0.0.1/merovingian"});
        write_fd.reset();
        auto const raw_fd = read_fd.get();

        WHEN("read_worker_database_uri consumes it")
        {
            auto const result = merovingian::federation_worker::read_worker_database_uri(std::move(read_fd));

            THEN("the URI is accepted and the fd number is no longer open")
            {
                REQUIRE(result.has_value());
                REQUIRE(::fcntl(raw_fd, F_GETFD) < 0);
            }
        }
    }
}

// ---- E. applying the URI onto the worker's own config copy -------------

SCENARIO("apply_worker_database_uri overrides the worker's connection and clears file-based credentials",
         "[federation-worker][worker_db_uri]")
{
    GIVEN("a config carrying main's database.uri_file and role settings")
    {
        auto config = merovingian::config::Config{};
        config.database().uri_file = "/etc/merovingian/db-uri";
        config.database().runtime_role = "merovingian_runtime";
        config.database().migration_role = "merovingian_migration";

        WHEN("apply_worker_database_uri is applied with a fd-delivered URI")
        {
            auto const uri = std::string_view{"postgresql://fedworker@127.0.0.1/merovingian"};
            merovingian::federation_worker::apply_worker_database_uri(config, uri);

            THEN("the worker connects with the delivered URI directly, never the file or the SET ROLE dance")
            {
                REQUIRE(config.database().worker_conninfo_override == uri);
                REQUIRE(config.database().uri_file.empty());
                REQUIRE(config.database().runtime_role.empty());
                REQUIRE(config.database().migration_role.empty());
            }
        }
    }
}

// ---- F. load profile: which tables the worker pulls into memory --------

SCENARIO("The full load profile includes every table, including secret-bearing ones", "[database][worker_db_uri]")
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

SCENARIO("The federation_worker load profile excludes every table outside the allowlist", "[database][worker_db_uri]")
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
         "(the secret_key column restriction is enforced separately, at the SQL query and GRANT level)",
         "[database][worker_db_uri]")
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
         "[database][worker_db_uri]")
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

// ---- D & G. the generalized worker secret pipe --------------------------

SCENARIO("The worker database URI pipe stays close-on-exec in the parent",
         "[federation][worker-supervisor][worker_db_uri]")
{
    GIVEN("a PostgreSQL connection URI")
    {
        auto const uri = std::string{"postgresql://fedworker@127.0.0.1/merovingian"};
        auto const bytes = std::vector<std::uint8_t>(uri.begin(), uri.end());

        WHEN("the supervisor prepares the db-uri pipe for a worker spawn")
        {
            auto const read_end = merovingian::homeserver::make_worker_db_uri_pipe(bytes);

            THEN("the read end is still close-on-exec in the parent")
            {
                auto const flags = ::fcntl(read_end.get(), F_GETFD);
                REQUIRE(flags >= 0);
                REQUIRE((flags & FD_CLOEXEC) != 0);
            }

            THEN("the read end never occupies any of the three fixed child fd numbers")
            {
                REQUIRE(read_end.get() != merovingian::homeserver::kWorkerIpcFd);
                REQUIRE(read_end.get() != merovingian::homeserver::kWorkerIpcKeyFd);
                REQUIRE(read_end.get() != merovingian::homeserver::kWorkerDbUriFd);
            }

            THEN("the pipe yields exactly the URI bytes followed by end-of-file")
            {
                auto buffer = std::array<std::uint8_t, 128U>{};
                auto const count = ::read(read_end.get(), buffer.data(), buffer.size());
                REQUIRE(count == static_cast<ssize_t>(bytes.size()));
                REQUIRE(std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + count) == bytes);
                REQUIRE(::read(read_end.get(), buffer.data(), buffer.size()) == 0);
            }
        }
    }
}

SCENARIO("The worker database URI pipe refuses empty material", "[federation][worker-supervisor][worker_db_uri]")
{
    GIVEN("no URI material")
    {
        auto const bytes = std::vector<std::uint8_t>{};

        WHEN("the supervisor prepares the db-uri pipe")
        {
            THEN("it fails closed instead of handing the worker an empty pipe")
            {
                REQUIRE_THROWS(merovingian::homeserver::make_worker_db_uri_pipe(bytes));
            }
        }
    }
}

SCENARIO("The fixed worker fd numbers are three, mutually distinct, and past the standard streams",
         "[federation][worker-supervisor][worker_db_uri]")
{
    GIVEN("the fixed child fd numbers")
    {
        THEN("db-uri collides with neither the IPC socket, the key fd, nor stdio")
        {
            REQUIRE(merovingian::homeserver::kWorkerDbUriFd > 2);
            REQUIRE(merovingian::homeserver::kWorkerDbUriFd != merovingian::homeserver::kWorkerIpcFd);
            REQUIRE(merovingian::homeserver::kWorkerDbUriFd != merovingian::homeserver::kWorkerIpcKeyFd);
        }
    }
}

// ---- source-tree consistency: SQL grants vs. the C++ allowlist ---------

SCENARIO("provision-federation-worker-role.sql grants SELECT on exactly the C++ worker table allowlist, "
         "plus the ungated schema_migrations bookkeeping table",
         "[database][worker_db_uri]")
{
    GIVEN("the checked-in GRANT script and the C++ allowlist array")
    {
        auto const sql_path = source_root() / "packaging" / "postgresql" / "provision-federation-worker-role.sql";
        auto const granted = parse_granted_tables(read_whole_file(sql_path));
        auto const allowlisted = cpp_allowlist_as_set();
        // schema_migrations is granted in SQL (any role needs it to open the
        // store at all) but is deliberately NOT part of
        // federation_worker_table_allowlist -- that array is specifically
        // TableLoadProfile's per-request table set, and schema_migrations is
        // read via load_schema_state before any profile applies. It is the
        // one legitimate name allowed in `granted` without also being in
        // `allowlisted`.
        auto expected = allowlisted;
        for (auto const& table : ungated_infrastructure_tables())
        {
            expected.insert(table);
        }

        WHEN("the two sets are compared")
        {
            THEN("every table the C++ allowlist (plus ungated infrastructure) names is granted in the SQL script")
            {
                for (auto const& table : expected)
                {
                    INFO("missing GRANT SELECT for table: " << table);
                    REQUIRE(granted.contains(table));
                }
            }
            AND_THEN("the SQL script grants nothing beyond the C++ allowlist and ungated infrastructure")
            {
                for (auto const& table : granted)
                {
                    INFO("SQL grants a table absent from the C++ allowlist and ungated set: " << table);
                    REQUIRE(expected.contains(table));
                }
            }
            AND_THEN("neither set is empty, so this comparison cannot pass by both being vacuous")
            {
                REQUIRE_FALSE(granted.empty());
                REQUIRE_FALSE(allowlisted.empty());
            }
        }
    }
}

SCENARIO("provision-federation-worker-role.sql never grants the server_signing_keys secret_key column",
         "[database][worker_db_uri]")
{
    GIVEN("the checked-in GRANT script")
    {
        auto const sql_path = source_root() / "packaging" / "postgresql" / "provision-federation-worker-role.sql";
        auto const sql = read_whole_file(sql_path);

        THEN("the script contains no GRANT naming secret_key")
        {
            auto const lowered = [&sql] {
                auto copy = sql;
                std::ranges::transform(copy, copy.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                return copy;
            }();
            auto pos = std::size_t{0U};
            while ((pos = lowered.find("grant select", pos)) != std::string::npos)
            {
                auto const line_end = lowered.find('\n', pos);
                auto const line =
                    lowered.substr(pos, line_end == std::string::npos ? std::string::npos : line_end - pos);
                REQUIRE(line.find("secret_key") == std::string::npos);
                pos = (line_end == std::string::npos) ? lowered.size() : line_end + 1U;
            }
        }
    }
}

// ---- source-tree consistency: every migration table is classified ------

SCENARIO("Every table migrations/*.sql creates is classified as worker-allowlisted, "
         "never-read-by-the-worker, or ungated infrastructure",
         "[database][worker_db_uri]")
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
