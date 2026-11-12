// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// C44 (ADR-0733): the federation worker opens no database. Its configuration copy is switched to the memory backend
// with every database location emptied before Landlock rules are built and before its runtime starts.

#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/federation_worker/WorkerDatabaseConfig.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>

namespace config = merovingian::config;
namespace fw = merovingian::federation_worker;

SCENARIO("The worker's configuration copy names no database once its location is cleared",
         "[federation-worker][c44][worker-database-config]")
{
    GIVEN("a configuration naming a database on each backend's keys")
    {
        auto const backend = GENERATE(config::DatabaseBackend::sqlite, config::DatabaseBackend::postgresql);
        auto configured = config::Config{};
        auto& database = configured.database();
        database.backend = backend;
        database.sqlite_path = "/var/lib/merovingian/merovingian.sqlite3";
        database.uri_file = "/etc/merovingian/db-uri";
        database.migration_role = "merovingian_migrate";
        database.runtime_role = "merovingian_runtime";
        database.worker_conninfo_override = "postgresql://worker@localhost/merovingian";
        database.pool_size = 7U;

        WHEN("the worker clears its database location")
        {
            fw::clear_database_location(configured);

            THEN("the backend is memory and no path, URI, role or override is left")
            {
                auto const& cleared = configured.database();
                REQUIRE(cleared.backend == config::DatabaseBackend::memory);
                REQUIRE(cleared.sqlite_path.empty());
                REQUIRE(cleared.uri_file.empty());
                REQUIRE(cleared.migration_role.empty());
                REQUIRE(cleared.runtime_role.empty());
                REQUIRE(cleared.worker_conninfo_override.empty());
            }

            THEN("nothing else in the configuration changes")
            {
                REQUIRE(configured.database().pool_size == 7U);
            }
        }
    }
}
