// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/database/runtime_database.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Runtime database config preserves URI file path and pool size", "[database][runtime]")
{
    // Given
    auto database = merovingian::config::DatabaseConfig{};
    database.uri_file = "/run/secrets/merovingian-db-uri";
    database.pool_size = 32U;
    auto const config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        database,
        merovingian::config::SecurityConfig{},
    };

    // When
    auto const runtime_database = merovingian::database::make_runtime_database_config(config);

    // Then
    REQUIRE(runtime_database.uri_file == "/run/secrets/merovingian-db-uri");
    REQUIRE(runtime_database.pool_size == 32U);
}

TEST_CASE("Runtime database summary excludes URI file paths and credentials", "[database][runtime][security]")
{
    // Given
    auto runtime_database = merovingian::database::RuntimeDatabaseConfig{};
    runtime_database.uri_file = "/run/secrets/postgresql://user:password@example.invalid/merovingian";
    runtime_database.pool_size = 16U;

    // When
    auto const summary = merovingian::database::database_summary(runtime_database);

    // Then
    REQUIRE(summary.find("pool_size=16") != std::string::npos);
    REQUIRE(summary.find(runtime_database.uri_file) == std::string::npos);
    REQUIRE(summary.find("password") == std::string::npos);
    REQUIRE(summary.find("postgresql://") == std::string::npos);
}
