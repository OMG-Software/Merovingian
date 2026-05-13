// SPDX-License-Identifier: GPL-3.0-or-later

#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>
#include <merovingian/config/config.hpp>
#include <merovingian/config/config_parser.hpp>
#include <merovingian/database/runtime_database.hpp>

SCENARIO("Database config defaults to PostgreSQL", "[config][database]")
{
    GIVEN("a default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("database settings are inspected")
        {
            auto const& database = config.database();

            THEN("PostgreSQL remains the default backend")
            {
                REQUIRE(database.backend == merovingian::config::DatabaseBackend::postgresql);
                REQUIRE(database.uri_file == "/etc/merovingian/db-uri");
                REQUIRE(database.sqlite_path == "/var/lib/merovingian/merovingian.sqlite3");
                REQUIRE(database.pool_size == 16U);
                REQUIRE(database.role == merovingian::config::DatabaseRole::runtime);
            }
        }
    }
}

SCENARIO("Database backend helpers parse SQLite and expose performance warnings", "[config][database]")
{
    GIVEN("supported backend names")
    {
        WHEN("backend names and warnings are queried")
        {
            auto const postgresql = merovingian::config::parse_database_backend("postgresql");
            auto const sqlite = merovingian::config::parse_database_backend("sqlite");
            auto const unknown = merovingian::config::parse_database_backend("mysql");
            auto const sqlite_warning =
                merovingian::config::database_backend_performance_warning(merovingian::config::DatabaseBackend::sqlite);
            auto const postgresql_warning = merovingian::config::database_backend_performance_warning(
                merovingian::config::DatabaseBackend::postgresql);

            THEN("SQLite is opt-in and carries a small-installation warning")
            {
                REQUIRE(postgresql == merovingian::config::DatabaseBackend::postgresql);
                REQUIRE(sqlite == merovingian::config::DatabaseBackend::sqlite);
                REQUIRE_FALSE(unknown.has_value());
                REQUIRE(merovingian::config::database_backend_name(merovingian::config::DatabaseBackend::postgresql) ==
                        "postgresql");
                REQUIRE(merovingian::config::database_backend_name(merovingian::config::DatabaseBackend::sqlite) ==
                        "sqlite");
                REQUIRE(sqlite_warning.find("small installations") != std::string_view::npos);
                REQUIRE(postgresql_warning.empty());
            }
        }
    }
}

SCENARIO("Database role helpers separate runtime and migration privileges", "[config][database][role]")
{
    GIVEN("supported database role names")
    {
        WHEN("role names are parsed")
        {
            auto const runtime = merovingian::config::parse_database_role("runtime");
            auto const migration = merovingian::config::parse_database_role("migration");
            auto const unknown = merovingian::config::parse_database_role("admin");

            THEN("runtime and migration roles are explicit")
            {
                REQUIRE(runtime == merovingian::config::DatabaseRole::runtime);
                REQUIRE(migration == merovingian::config::DatabaseRole::migration);
                REQUIRE_FALSE(unknown.has_value());
                REQUIRE(merovingian::config::database_role_name(merovingian::config::DatabaseRole::runtime) ==
                        "runtime");
                REQUIRE(merovingian::config::database_role_name(merovingian::config::DatabaseRole::migration) ==
                        "migration");
            }
        }
    }
}

SCENARIO("Key-value config parser applies migration database role", "[config][parser][database][role]")
{
    GIVEN("config input selecting the migration role")
    {
        auto const input = std::string{"database.backend=postgresql\n"
                                       "database.role=migration\n"
                                       "database.uri_file=/run/secrets/merovingian-migrator-uri\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the role is retained for offline migration tooling")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.database().backend == merovingian::config::DatabaseBackend::postgresql);
                REQUIRE(result.config.database().role == merovingian::config::DatabaseRole::migration);
            }
        }
    }
}

SCENARIO("Key-value config parser applies SQLite database settings", "[config][parser][database]")
{
    GIVEN("config input selecting SQLite")
    {
        auto const input = std::string{"database.backend=sqlite\n"
                                       "database.sqlite_path=/var/lib/merovingian/small.sqlite3\n"
                                       "database.pool_size=1\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("SQLite settings are retained without exposing path in summaries")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.database().backend == merovingian::config::DatabaseBackend::sqlite);
                REQUIRE(result.config.database().sqlite_path == "/var/lib/merovingian/small.sqlite3");
                REQUIRE(result.config.database().pool_size == 1U);
            }
        }
    }
}

SCENARIO("SQLite runtime database summary includes performance warning", "[database][runtime]")
{
    GIVEN("runtime config selecting SQLite")
    {
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = "/var/lib/merovingian/small.sqlite3";
        database.pool_size = 1U;
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            database,
            merovingian::config::SecurityConfig{},
        };

        WHEN("runtime database config is summarized")
        {
            auto const runtime_database = merovingian::database::make_runtime_database_config(config);
            auto const summary = merovingian::database::database_summary(runtime_database);

            THEN("the backend and warning are visible but the file path is not")
            {
                REQUIRE(runtime_database.backend == merovingian::config::DatabaseBackend::sqlite);
                REQUIRE(runtime_database.warning.find("small installations") != std::string::npos);
                REQUIRE(summary.find("backend=sqlite") != std::string::npos);
                REQUIRE(summary.find("warning=") != std::string::npos);
                REQUIRE(summary.find(runtime_database.sqlite_path) == std::string::npos);
            }
        }
    }
}

SCENARIO("SQLite config requires a database path", "[config][database][validation]")
{
    GIVEN("SQLite config with an empty path")
    {
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path.clear();
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            database,
            merovingian::config::SecurityConfig{},
        };

        WHEN("the config is validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("a SQLite path finding is reported")
            {
                REQUIRE_FALSE(findings.empty());
                REQUIRE(findings.front().field == "database.sqlite_path");
            }
        }
    }
}
