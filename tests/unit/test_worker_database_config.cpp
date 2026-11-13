// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// C44 (ADR-0733): the federation worker opens no database. Its configuration copy is switched to the memory backend
// with every database location emptied before Landlock rules are built and before its runtime starts.

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParser.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/federation_worker/WorkerDatabaseConfig.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstddef>
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
        database.pool_size = 7U;

        WHEN("the worker clears its database location")
        {
            fw::clear_database_location(configured);

            THEN("the backend is memory and no path, URI or role is left")
            {
                auto const& cleared = configured.database();
                REQUIRE(cleared.backend == config::DatabaseBackend::memory);
                REQUIRE(cleared.sqlite_path.empty());
                REQUIRE(cleared.uri_file.empty());
                REQUIRE(cleared.migration_role.empty());
                REQUIRE(cleared.runtime_role.empty());
            }

            THEN("nothing else in the configuration changes")
            {
                REQUIRE(configured.database().pool_size == 7U);
            }
        }
    }
}

// ADR-0736: the two keys that once gave the worker a database are refused, each by name, whatever its value.
SCENARIO("A configuration that still sets a retired worker database key is refused, naming the key",
         "[config][c44][retired-worker-database-keys]")
{
    GIVEN("a configuration line setting one of the retired keys")
    {
        auto const line =
            GENERATE(std::string{"federation.worker.database_uri_file=/etc/merovingian/fed-worker-db-uri"},
                     std::string{"federation.worker.database_uri_file="},
                     std::string{"federation.worker.allow_shared_database_credentials=true"},
                     std::string{"federation.worker.allow_shared_database_credentials=false"});
        auto const key = line.substr(0U, line.find('='));

        WHEN("the configuration is parsed")
        {
            auto const result = config::parse_key_value_config(line + "\n");

            THEN("exactly one finding names the key and says the worker no longer opens a database")
            {
                auto named = std::size_t{0U};
                for (auto const& finding : result.findings)
                {
                    if (finding.field == key)
                    {
                        ++named;
                        REQUIRE(finding.message.find("no longer opens a database") != std::string::npos);
                    }
                }
                REQUIRE(named == 1U);
                REQUIRE(result.findings.size() == 1U);
            }
        }
    }
}
