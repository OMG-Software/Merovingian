// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/database/runtime_database.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Runtime database config preserves PostgreSQL URI file path and pool size", "[database][runtime]")
{
    GIVEN("configuration with a database URI file and pool size")
    {
        auto database = merovingian::config::DatabaseConfig{};
        database.uri_file = "/run/secrets/merovingian-db-uri";
        database.pool_size = 32U;
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            database,
            merovingian::config::SecurityConfig{},
        };

        WHEN("the runtime database config is created")
        {
            auto const runtime_database = merovingian::database::make_runtime_database_config(config);

            THEN("the backend URI file path and pool size are preserved")
            {
                REQUIRE(runtime_database.backend == merovingian::config::DatabaseBackend::postgresql);
                REQUIRE(runtime_database.uri_file == "/run/secrets/merovingian-db-uri");
                REQUIRE(runtime_database.pool_size == 32U);
                REQUIRE(runtime_database.warning.empty());
            }
        }
    }
}

SCENARIO("Runtime database config supports SQLite for small installations", "[database][runtime]")
{
    GIVEN("configuration selecting SQLite")
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

        WHEN("the runtime database config and summary are created")
        {
            auto const runtime_database = merovingian::database::make_runtime_database_config(config);
            auto const summary = merovingian::database::database_summary(runtime_database);

            THEN("SQLite is selected with an explicit performance warning")
            {
                REQUIRE(runtime_database.backend == merovingian::config::DatabaseBackend::sqlite);
                REQUIRE(runtime_database.sqlite_path == "/var/lib/merovingian/small.sqlite3");
                REQUIRE(runtime_database.warning.find("small installations") != std::string::npos);
                REQUIRE(summary.find("backend=sqlite") != std::string::npos);
                REQUIRE(summary.find("warning=") != std::string::npos);
                REQUIRE(summary.find(runtime_database.sqlite_path) == std::string::npos);
            }
        }
    }
}

SCENARIO("Runtime database summary excludes URI file paths and credentials", "[database][runtime][security]")
{
    GIVEN("a runtime database config containing a sensitive URI file path")
    {
        auto runtime_database = merovingian::database::RuntimeDatabaseConfig{};
        runtime_database.backend = merovingian::config::DatabaseBackend::postgresql;
        runtime_database.uri_file = "/run/secrets/postgresql://user:password@example.invalid/merovingian";
        runtime_database.pool_size = 16U;

        WHEN("the database summary is generated")
        {
            auto const summary = merovingian::database::database_summary(runtime_database);

            THEN("sensitive URI information is not included")
            {
                REQUIRE(summary.find("pool_size=16") != std::string::npos);
                REQUIRE(summary.find(runtime_database.uri_file) == std::string::npos);
                REQUIRE(summary.find("password") == std::string::npos);
                REQUIRE(summary.find("postgresql://") == std::string::npos);
            }
        }
    }
}
