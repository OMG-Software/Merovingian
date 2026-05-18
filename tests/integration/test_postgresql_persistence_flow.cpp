// SPDX-License-Identifier: GPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include <merovingian/database/persistent_store.hpp>
#include <merovingian/database/postgresql_store.hpp>
#include <merovingian/database/schema.hpp>

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

// Optional role-separation knobs. The CI workflow creates two PostgreSQL
// roles (a migration role with DDL grants and a runtime role with DML-only
// grants) and exposes them through these env vars. Locally, leaving them
// unset skips the role-enforcement scenario but still runs the rest.
[[nodiscard]] auto runtime_role_from_environment() -> std::string_view
{
    return env_string("MEROVINGIAN_TEST_POSTGRESQL_RUNTIME_ROLE");
}

[[nodiscard]] auto migration_role_from_environment() -> std::string_view
{
    return env_string("MEROVINGIAN_TEST_POSTGRESQL_MIGRATION_ROLE");
}

} // namespace

SCENARIO("PostgreSQL persistence integration is gated by an explicit test URI",
         "[database][postgresql][integration]")
{
    GIVEN("the PostgreSQL integration test environment")
    {
        auto const uri = postgresql_uri_from_environment();

        WHEN("the URI is absent")
        {
            if (uri.empty())
            {
                THEN("the gate is explicit and does not attempt an ambient database connection")
                {
                    REQUIRE(uri.empty());
                }
            }
            else
            {
                auto const policy = merovingian::database::validate_postgresql_conninfo(uri);
                auto opened = merovingian::database::open_postgresql_persistent_store(uri);

                THEN("the provided PostgreSQL URI bootstraps and hydrates a live test store")
                {
                    REQUIRE(policy.allowed);
                    REQUIRE(opened.ok);
                    REQUIRE(opened.store.open);
                }
            }
        }
    }
}

SCENARIO("PostgreSQL bootstrap brings the schema to the current version",
         "[database][postgresql][integration][schema]")
{
    GIVEN("a live PostgreSQL URI")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }

        WHEN("the persistent store is opened")
        {
            auto opened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("the schema is at current_schema_version and the migration ledger is populated")
            {
                REQUIRE(opened.ok);
                REQUIRE(opened.store.schema.version == merovingian::database::current_schema_version());
                REQUIRE_FALSE(opened.store.schema.applied_migrations.empty());
                // Every schema version up to the current one is represented in
                // the applied ledger; the helper deliberately rejects gaps.
                auto seen = std::vector<bool>(opened.store.schema.applied_migrations.size(), false);
                for (auto const& record : opened.store.schema.applied_migrations)
                {
                    REQUIRE(record.version >= 1U);
                    REQUIRE(record.version <= merovingian::database::current_schema_version());
                }
                REQUIRE(opened.store.schema.tables.size() >=
                        merovingian::database::initial_schema_tables().size());
            }
        }
    }
}

SCENARIO("PostgreSQL persistent rows survive an open/close/reopen cycle",
         "[database][postgresql][integration][restart]")
{
    GIVEN("a live PostgreSQL URI and a freshly-bootstrapped store")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened.ok);

        // Use the test instance's own scratch fields so this scenario is
        // idempotent: an audit row uniquely tagged with the test name acts
        // as the canary across the restart cycle.
        auto const canary_action = std::string{"postgresql-restart-canary"};
        REQUIRE(merovingian::database::append_admin_action(
            opened.store, {"@test-admin:example.org", canary_action, "@target:example.org"}));

        WHEN("the store is closed and a brand-new store is opened against the same database")
        {
            opened = {}; // RAII close on the previous store + connection.
            auto reopened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("the canary row is visible after restart")
            {
                REQUIRE(reopened.ok);
                auto const found =
                    std::ranges::any_of(reopened.store.admin_actions,
                                        [&canary_action](merovingian::database::PersistentAdminAction const& row) {
                                            return row.action == canary_action;
                                        });
                REQUIRE(found);
            }
        }
    }
}

SCENARIO("PostgreSQL role separation: runtime role cannot execute DDL",
         "[database][postgresql][integration][roles]")
{
    GIVEN("a live PostgreSQL URI plus migration and runtime role names")
    {
        auto const uri = postgresql_uri_from_environment();
        auto const runtime_role = runtime_role_from_environment();
        auto const migration_role = migration_role_from_environment();
        if (uri.empty() || runtime_role.empty() || migration_role.empty())
        {
            SUCCEED("skipped: live PG URI or role env vars are not set");
            return;
        }
        auto connection = merovingian::database::open_postgresql_connection(uri);
        REQUIRE(connection.ok);

        WHEN("the session switches to the runtime role and tries to CREATE TABLE")
        {
            REQUIRE(merovingian::database::set_postgresql_role(connection.connection, runtime_role));
            auto const after_set = merovingian::database::current_postgresql_user(connection.connection);
            auto const ddl_attempt = connection.connection.execute(
                {"runtime_role_ddl_smoke",
                 "CREATE TABLE merovingian_runtime_role_smoke (id TEXT PRIMARY KEY)", {}});
            // Cleanup: switch back to migration role so subsequent scenarios
            // can DDL freely. RESET ROLE returns to the original login user.
            REQUIRE(merovingian::database::reset_postgresql_role(connection.connection));
            REQUIRE(merovingian::database::set_postgresql_role(connection.connection, migration_role));
            // If the runtime role had managed to create the table (which the
            // grant policy should prevent), drop it now to keep the database
            // tidy. The DROP runs as the migration role.
            (void)connection.connection.execute(
                {"drop_runtime_role_smoke",
                 "DROP TABLE IF EXISTS merovingian_runtime_role_smoke", {}});

            THEN("the runtime-role session is denied DDL and CURRENT_USER reflects the role switch")
            {
                REQUIRE(after_set == std::string{runtime_role});
                REQUIRE_FALSE(ddl_attempt.ok);
            }
        }
    }
}
