// SPDX-License-Identifier: GPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <optional>
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

// Returns a process-unique, monotonically distinct suffix. The live
// PostgreSQL database persists across both the meson-test run and the
// dedicated integration-test run within one CI job, so restart scenarios
// must not reuse fixed primary keys or the second run hits duplicate-key
// failures. The timestamp differs between process invocations; the counter
// keeps separate scenarios in one invocation distinct.
[[nodiscard]] auto unique_test_suffix() -> std::string
{
    static auto const base = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    static auto counter = std::uint64_t{0U};
    return std::to_string(base) + "-" + std::to_string(counter++);
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

SCENARIO("PostgreSQL persistence integration is gated by an explicit test URI", "[database][postgresql][integration]")
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

SCENARIO("PostgreSQL bootstrap brings the schema to the current version", "[database][postgresql][integration][schema]")
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
                REQUIRE(opened.store.schema.tables.size() >= merovingian::database::initial_schema_tables().size());
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

SCENARIO("PostgreSQL users tokens rooms and events survive an open/close/reopen cycle",
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

        auto const suffix = unique_test_suffix();
        auto const user_id = "@pg-restart-user-" + suffix + ":example.org";
        auto const room_id = "!pg-restart-room-" + suffix + ":example.org";
        auto const event_id = "$pg-restart-event-" + suffix + ":example.org";
        REQUIRE(merovingian::database::store_user(opened.store, {user_id, "hash:restart-test", false, false, false}));
        // store_access_token requires the versioned hash prefix; a bare string
        // is rejected before the row is ever written.
        REQUIRE(merovingian::database::store_access_token(
            opened.store, {user_id, "device1", "token-hash:v2:restart-" + suffix, false, std::nullopt}));
        REQUIRE(merovingian::database::store_room(opened.store, {room_id, user_id}));
        REQUIRE(merovingian::database::store_membership(opened.store, {room_id, user_id, "join", 1U}) ==
                merovingian::database::MembershipStoreResult::stored);
        REQUIRE(merovingian::database::store_event(
            opened.store, {event_id, room_id, user_id, "{\"type\":\"m.room.message\"}", 1U, 1U, {}, {}, {}}));

        WHEN("the store is closed and reopened")
        {
            opened = {};
            auto reopened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("user token room membership and event all survive the restart")
            {
                REQUIRE(reopened.ok);
                auto const user_found = std::ranges::any_of(reopened.store.users,
                                                            [&user_id](merovingian::database::PersistentUser const& u) {
                                                                return u.user_id == user_id;
                                                            });
                REQUIRE(user_found);

                auto const token_found = std::ranges::any_of(
                    reopened.store.access_tokens, [&user_id](merovingian::database::PersistentAccessToken const& t) {
                        return t.user_id == user_id;
                    });
                REQUIRE(token_found);

                auto const room_found = std::ranges::any_of(reopened.store.rooms,
                                                            [&room_id](merovingian::database::PersistentRoom const& r) {
                                                                return r.room_id == room_id;
                                                            });
                REQUIRE(room_found);

                auto const member_found = std::ranges::any_of(
                    reopened.store.memberships,
                    [&room_id, &user_id](merovingian::database::PersistentMembership const& m) {
                        return m.room_id == room_id && m.user_id == user_id && m.membership == "join";
                    });
                REQUIRE(member_found);

                auto const event_found = std::ranges::any_of(
                    reopened.store.events, [&event_id](merovingian::database::PersistentEvent const& e) {
                        return e.event_id == event_id;
                    });
                REQUIRE(event_found);
            }
        }
    }
}

SCENARIO("PostgreSQL account data policy rules and federation queues survive restart",
         "[database][postgresql][integration][restart]")
{
    GIVEN("a live PostgreSQL URI with account data policy rules and federation queue rows")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened.ok);

        auto const suffix = unique_test_suffix();
        auto const user_id = "@acct-data-user-" + suffix + ":example.org";
        auto const rule_id = "pg-restart-rule-" + suffix;
        auto const dest_name = "federation.restart-" + suffix + ".example.org";
        auto const txn_id = "pg-restart-txn-" + suffix;

        REQUIRE(merovingian::database::store_account_data(opened.store,
                                                          {user_id, "", "m.push_rules", "{\"global\":{}}", 1U}));
        REQUIRE(merovingian::database::store_policy_rule(
            opened.store, {rule_id, "server", "bad.example.org", "block", "test restart"}));
        REQUIRE(merovingian::database::store_federation_destination(opened.store, {dest_name, "idle", 0U, 0U, 0U}));
        REQUIRE(merovingian::database::store_federation_transaction(
            opened.store, {txn_id, dest_name, "PUT", "/_matrix/federation/v1/send/" + txn_id, "local.example.org",
                           "1000", "{\"pdus\":[]}", 0U, 0U}));

        WHEN("the store is closed and reopened")
        {
            opened = {};
            auto reopened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("account data policy rules and federation queue entries all survive")
            {
                REQUIRE(reopened.ok);

                auto const acct_found = std::ranges::any_of(
                    reopened.store.account_data, [&user_id](merovingian::database::PersistentAccountData const& d) {
                        return d.user_id == user_id && d.event_type == "m.push_rules";
                    });
                REQUIRE(acct_found);

                auto const rule_found = std::ranges::any_of(
                    reopened.store.policy_rules, [&rule_id](merovingian::database::PersistentPolicyRule const& r) {
                        return r.rule_id == rule_id;
                    });
                REQUIRE(rule_found);

                auto const dest_found =
                    std::ranges::any_of(reopened.store.federation_destinations,
                                        [&dest_name](merovingian::database::PersistentFederationDestination const& d) {
                                            return d.server_name == dest_name;
                                        });
                REQUIRE(dest_found);

                auto const txn_found =
                    std::ranges::any_of(reopened.store.federation_transactions,
                                        [&txn_id](merovingian::database::PersistentFederationTransaction const& t) {
                                            return t.transaction_id == txn_id;
                                        });
                REQUIRE(txn_found);
            }
        }
    }
}

SCENARIO("PostgreSQL media metadata survives an open/close/reopen cycle",
         "[database][postgresql][integration][restart][media]")
{
    GIVEN("a live PostgreSQL URI with local and remote media rows")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened.ok);

        auto const suffix = unique_test_suffix();
        auto const media_id = "pg-restart-media-" + suffix;
        auto const remote_media_id = "pg-restart-remote-" + suffix;
        auto const remote_server = "media.restart-" + suffix + ".example.org";

        REQUIRE(
            merovingian::database::store_local_media(opened.store, {media_id, "@owner:example.org", "image/png", 1024U,
                                                                    "sha256", "abc123digest", false, false}));
        REQUIRE(merovingian::database::store_remote_media(
            opened.store, {remote_server, remote_media_id, "image/jpeg", 2048U, false}));

        WHEN("the store is closed and reopened")
        {
            opened = {};
            auto reopened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("both local and remote media metadata survive the restart")
            {
                REQUIRE(reopened.ok);

                auto const local_found = std::ranges::any_of(
                    reopened.store.local_media, [&media_id](merovingian::database::PersistentLocalMedia const& m) {
                        return m.media_id == media_id && m.content_type == "image/png";
                    });
                REQUIRE(local_found);

                auto const remote_found = std::ranges::any_of(
                    reopened.store.remote_media,
                    [&remote_server, &remote_media_id](merovingian::database::PersistentRemoteMedia const& m) {
                        return m.server_name == remote_server && m.media_id == remote_media_id;
                    });
                REQUIRE(remote_found);
            }
        }
    }
}

SCENARIO("PostgreSQL role separation: runtime role cannot execute DDL", "[database][postgresql][integration][roles]")
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
                {"runtime_role_ddl_smoke", "CREATE TABLE merovingian_runtime_role_smoke (id TEXT PRIMARY KEY)", {}});
            // Cleanup: switch back to migration role so subsequent scenarios
            // can DDL freely. RESET ROLE returns to the original login user.
            REQUIRE(merovingian::database::reset_postgresql_role(connection.connection));
            REQUIRE(merovingian::database::set_postgresql_role(connection.connection, migration_role));
            // If the runtime role had managed to create the table (which the
            // grant policy should prevent), drop it now to keep the database
            // tidy. The DROP runs as the migration role.
            std::ignore = connection.connection.execute(
                {"drop_runtime_role_smoke", "DROP TABLE IF EXISTS merovingian_runtime_role_smoke", {}});

            THEN("the runtime-role session is denied DDL and CURRENT_USER reflects the role switch")
            {
                REQUIRE(after_set == std::string{runtime_role});
                REQUIRE_FALSE(ddl_attempt.ok);
            }
        }
    }
}

SCENARIO("PostgreSQL transaction rollback leaves no partial rows", "[database][postgresql][integration][transaction]")
{
    GIVEN("a live PostgreSQL connection")
    {
        auto const uri = postgresql_uri_from_environment();
        auto const migration_role = migration_role_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto connection = merovingian::database::open_postgresql_connection(uri);
        REQUIRE(connection.ok);
        auto& executor = connection.connection;
        if (!migration_role.empty())
        {
            REQUIRE(merovingian::database::set_postgresql_role(executor, migration_role));
        }

        // Scratch table name derived from a process-unique suffix; '-' is replaced
        // so the result is a valid unquoted SQL identifier. The value is fully
        // controlled (timestamp + counter), so the inline interpolation is safe.
        auto probe = std::string{"merovingian_rollback_probe_"} + unique_test_suffix();
        std::ranges::replace(probe, '-', '_');
        std::ignore = executor.execute({"rb_predrop", "DROP TABLE IF EXISTS " + probe, {}});

        WHEN("a helper-managed transaction hits a duplicate-key failure")
        {
            auto const rolled_back = executor.execute_transaction({
                {"rb_create",           "CREATE TABLE " + probe + " (id TEXT PRIMARY KEY)", {}},
                {"rb_insert",           "INSERT INTO " + probe + " (id) VALUES ('x')",      {}},
                {"rb_insert_duplicate", "INSERT INTO " + probe + " (id) VALUES ('x')",      {}},
            });

            THEN("no trace of the table or row survives, and a committed transaction does persist")
            {
                REQUIRE_FALSE(rolled_back);
                // The rolled-back CREATE/INSERT must have left nothing behind.
                auto const exists = executor.execute(
                    {"rb_exists",
                     "SELECT count(*) FROM information_schema.tables WHERE table_name = '" + probe + "'",
                     {}});
                REQUIRE(exists.ok);
                REQUIRE(exists.rows.size() == 1U);
                REQUIRE(exists.rows.front().size() == 1U);
                REQUIRE(exists.rows.front().front() == "0");

                // Positive control: the same statements under COMMIT do persist,
                // proving the rollback (not a broken connection) caused the absence.
                REQUIRE(executor.execute_transaction({
                    {"rb_create2", "CREATE TABLE " + probe + " (id TEXT PRIMARY KEY)", {}},
                    {"rb_insert2", "INSERT INTO " + probe + " (id) VALUES ('x')",      {}},
                }));
                auto const count = executor.execute({"rb_count", "SELECT count(*) FROM " + probe, {}});
                REQUIRE(count.ok);
                REQUIRE(count.rows.size() == 1U);
                REQUIRE(count.rows.front().front() == "1");

                std::ignore = executor.execute({"rb_cleanup", "DROP TABLE IF EXISTS " + probe, {}});
            }
        }
    }
}

SCENARIO("PostgreSQL migrations apply in contiguous order and bootstrap is idempotent",
         "[database][postgresql][integration][schema][migrations]")
{
    GIVEN("a live PostgreSQL URI")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }

        WHEN("the persistent store is opened and then opened a second time")
        {
            auto opened = merovingian::database::open_postgresql_persistent_store(uri);
            REQUIRE(opened.ok);

            auto versions = std::vector<std::uint32_t>{};
            versions.reserve(opened.store.schema.applied_migrations.size());
            for (auto const& record : opened.store.schema.applied_migrations)
            {
                versions.push_back(static_cast<std::uint32_t>(record.version));
            }
            std::ranges::sort(versions);

            auto reopened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("every version from 1..current is present exactly once and re-bootstrap is a no-op")
            {
                // Strictly increasing by one ⇒ ordered, contiguous, and free of gaps
                // or duplicates across the applied-migration ledger.
                REQUIRE_FALSE(versions.empty());
                REQUIRE(versions.front() == 1U);
                REQUIRE(versions.back() == merovingian::database::current_schema_version());
                for (auto index = std::size_t{1U}; index < versions.size(); ++index)
                {
                    REQUIRE(versions[index] == versions[index - 1U] + 1U);
                }
                REQUIRE(versions.size() == static_cast<std::size_t>(merovingian::database::current_schema_version()));

                // Re-opening must not re-apply migrations: same version, same ledger size.
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.schema.version == merovingian::database::current_schema_version());
                REQUIRE(reopened.store.schema.applied_migrations.size() ==
                        opened.store.schema.applied_migrations.size());
            }
        }
    }
}

SCENARIO("PostgreSQL role separation: the migration role can execute DDL the runtime role cannot",
         "[database][postgresql][integration][roles]")
{
    GIVEN("a live PostgreSQL URI plus a migration role name")
    {
        auto const uri = postgresql_uri_from_environment();
        auto const migration_role = migration_role_from_environment();
        if (uri.empty() || migration_role.empty())
        {
            SUCCEED("skipped: live PG URI or migration role env var is not set");
            return;
        }
        auto connection = merovingian::database::open_postgresql_connection(uri);
        REQUIRE(connection.ok);
        auto& executor = connection.connection;

        WHEN("the session switches to the migration role and performs DDL + DML")
        {
            REQUIRE(merovingian::database::set_postgresql_role(executor, migration_role));
            auto const after_set = merovingian::database::current_postgresql_user(executor);

            auto probe = std::string{"merovingian_migration_role_smoke_"} + unique_test_suffix();
            std::ranges::replace(probe, '-', '_');
            std::ignore = executor.execute({"mr_predrop", "DROP TABLE IF EXISTS " + probe, {}});
            auto const create = executor.execute({"mr_create", "CREATE TABLE " + probe + " (id TEXT PRIMARY KEY)", {}});
            auto const insert = executor.execute({"mr_insert", "INSERT INTO " + probe + " (id) VALUES ('x')", {}});

            // Cleanup regardless of assertion outcomes, then return to the login role.
            std::ignore = executor.execute({"mr_drop", "DROP TABLE IF EXISTS " + probe, {}});
            REQUIRE(merovingian::database::reset_postgresql_role(executor));

            THEN("the migration role is granted DDL and DML (the inverse of the runtime-role denial)")
            {
                REQUIRE(after_set == std::string{migration_role});
                REQUIRE(create.ok);
                REQUIRE(insert.ok);
            }
        }
    }
}

SCENARIO("PostgreSQL savepoints isolate a failing statement without losing prior work",
         "[database][postgresql][integration][transaction][savepoint]")
{
    GIVEN("a live PostgreSQL connection with a scratch table inside an open transaction")
    {
        auto const uri = postgresql_uri_from_environment();
        auto const migration_role = migration_role_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto connection = merovingian::database::open_postgresql_connection(uri);
        REQUIRE(connection.ok);
        auto& executor = connection.connection;
        if (!migration_role.empty())
        {
            REQUIRE(merovingian::database::set_postgresql_role(executor, migration_role));
        }

        // Fully-controlled scratch identifier (timestamp + counter); '-' is
        // replaced so the result is a valid unquoted SQL identifier.
        auto probe = std::string{"merovingian_savepoint_probe_"} + unique_test_suffix();
        std::ranges::replace(probe, '-', '_');
        std::ignore = executor.execute({"sp_predrop", "DROP TABLE IF EXISTS " + probe, {}});
        REQUIRE(executor.execute({"sp_create", "CREATE TABLE " + probe + " (id TEXT PRIMARY KEY)", {}}).ok);

        WHEN("a statement after a savepoint fails and the transaction rolls back to that savepoint")
        {
            // Begin a transaction, insert a durable row, then take a savepoint.
            REQUIRE(executor.execute({"sp_begin", "BEGIN", {}}).ok);
            REQUIRE(executor.execute({"sp_keep", "INSERT INTO " + probe + " (id) VALUES ('keep')", {}}).ok);
            REQUIRE(executor.execute({"sp_mark", "SAVEPOINT sp1", {}}).ok);
            // A duplicate-key insert fails and aborts the transaction to the
            // savepoint boundary; without recovery the connection cannot proceed.
            auto const failed = executor.execute({"sp_dup", "INSERT INTO " + probe + " (id) VALUES ('keep')", {}});
            // Rolling back to the savepoint recovers the transaction so the
            // earlier 'keep' row survives and further work can continue.
            REQUIRE(executor.execute({"sp_rollback", "ROLLBACK TO SAVEPOINT sp1", {}}).ok);
            REQUIRE(executor.execute({"sp_other", "INSERT INTO " + probe + " (id) VALUES ('other')", {}}).ok);
            REQUIRE(executor.execute({"sp_commit", "COMMIT", {}}).ok);

            THEN("the failed statement is discarded but the pre- and post-savepoint rows commit")
            {
                // The duplicate insert must have been rejected.
                REQUIRE_FALSE(failed.ok);
                auto const rows = executor.execute(
                    {"sp_select", "SELECT id FROM " + probe + " ORDER BY id", {}});
                REQUIRE(rows.ok);
                // Exactly 'keep' and 'other' survive; the duplicate left no trace.
                REQUIRE(rows.rows.size() == 2U);
                REQUIRE(rows.rows.at(0U).front() == "keep");
                REQUIRE(rows.rows.at(1U).front() == "other");

                std::ignore = executor.execute({"sp_cleanup", "DROP TABLE IF EXISTS " + probe, {}});
            }
        }
    }
}

SCENARIO("PostgreSQL concurrent connections enforce isolation and commit visibility",
         "[database][postgresql][integration][transaction][concurrency]")
{
    GIVEN("two independent live PostgreSQL connections sharing one committed scratch table")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto writer = merovingian::database::open_postgresql_connection(uri);
        auto reader = merovingian::database::open_postgresql_connection(uri);
        REQUIRE(writer.ok);
        REQUIRE(reader.ok);
        auto& writer_exec = writer.connection;
        auto& reader_exec = reader.connection;

        auto probe = std::string{"merovingian_concurrency_probe_"} + unique_test_suffix();
        std::ranges::replace(probe, '-', '_');
        std::ignore = writer_exec.execute({"cc_predrop", "DROP TABLE IF EXISTS " + probe, {}});
        // The table is created and committed (autocommit) so the reader
        // connection can see the table before any rows are written.
        REQUIRE(writer_exec.execute({"cc_create", "CREATE TABLE " + probe + " (id TEXT PRIMARY KEY)", {}}).ok);

        WHEN("the writer inserts a row inside an uncommitted transaction")
        {
            REQUIRE(writer_exec.execute({"cc_begin", "BEGIN", {}}).ok);
            REQUIRE(writer_exec.execute({"cc_insert", "INSERT INTO " + probe + " (id) VALUES ('shared')", {}}).ok);

            // Before the writer commits, the reader's snapshot must not see the row.
            auto const before = reader_exec.execute(
                {"cc_before", "SELECT count(*) FROM " + probe + " WHERE id = 'shared'", {}});

            REQUIRE(writer_exec.execute({"cc_commit", "COMMIT", {}}).ok);

            // After commit, a fresh read on the other connection must see the row.
            auto const after = reader_exec.execute(
                {"cc_after", "SELECT count(*) FROM " + probe + " WHERE id = 'shared'", {}});

            // A second connection inserting the same primary key must be rejected,
            // proving the unique constraint is enforced across connections.
            auto const conflict = reader_exec.execute(
                {"cc_conflict", "INSERT INTO " + probe + " (id) VALUES ('shared')", {}});

            THEN("uncommitted writes stay invisible, committed writes appear, and the PK is enforced")
            {
                REQUIRE(before.ok);
                // Read isolation: the writer's open transaction is invisible to the reader.
                REQUIRE(before.rows.front().front() == "0");
                REQUIRE(after.ok);
                // Commit visibility: once committed, the row is visible to the other connection.
                REQUIRE(after.rows.front().front() == "1");
                // Cross-connection uniqueness: the duplicate insert is rejected.
                REQUIRE_FALSE(conflict.ok);

                std::ignore = writer_exec.execute({"cc_cleanup", "DROP TABLE IF EXISTS " + probe, {}});
            }
        }
    }
}
