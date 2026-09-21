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

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
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

SCENARIO("The federation_worker load profile excludes every secret-bearing table", "[database][worker_db_uri]")
{
    GIVEN("the federation_worker load profile")
    {
        constexpr auto profile = merovingian::database::TableLoadProfile::federation_worker;

        THEN("server_signing_keys.secret_key is never pulled into worker memory")
        {
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("server_signing_keys", profile));
        }
        AND_THEN("neither are the other credential-bearing tables the worker never needs")
        {
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("users", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("access_tokens", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("refresh_tokens", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("login_tokens", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("openid_tokens", profile));
            REQUIRE_FALSE(merovingian::database::table_load_profile_includes("account_threepids", profile));
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
