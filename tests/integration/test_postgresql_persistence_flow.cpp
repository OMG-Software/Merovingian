// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/master_key.hpp"
#include "../support/temp_directory.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <merovingian/config/config.hpp>
#include <merovingian/database/migration.hpp>
#include <merovingian/database/persistent_store.hpp>
#include <merovingian/database/postgresql_store.hpp>
#include <merovingian/database/schema.hpp>
#include <merovingian/homeserver/room_service.hpp>
#include <merovingian/homeserver/runtime.hpp>

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

// ADR-0062 part 2 (0.12.13 audit, finding N1): the federation worker's
// least-privilege PostgreSQL role. The CI workflow, when it provisions this
// scenario, creates a role via packaging/postgresql/provision-federation-worker-role.sql
// (SELECT only, no SELECT on server_signing_keys or the other tables
// database::table_load_profile_includes excludes) and exposes its name here.
// Locally, leaving it unset skips this scenario but still runs the rest.
[[nodiscard]] auto worker_role_from_environment() -> std::string_view
{
    return env_string("MEROVINGIAN_TEST_POSTGRESQL_WORKER_ROLE");
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

// M-09: execute_prepared_statement used to send every PostgreSQL parameter
// as a null-terminated C string, so media_blobs.bytes (a BYTEA column)
// truncated at any embedded NUL byte and could not carry arbitrary binary
// content such as real image bytes. The fix hex-encodes parameters marked
// `binary` before binding them and decodes the bytea column on read; this
// exercises that round trip against a live server, matching the SQLite
// coverage in tests/unit/test_database_persistence.cpp's #448 regression.
SCENARIO("PostgreSQL media blob bytes round-trip exactly through a real BYTEA column, including embedded NULs",
         "[database][postgresql][integration][media][binary]")
{
    GIVEN("a live PostgreSQL URI and a blob payload covering every byte value")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened.ok);

        auto payload = std::string{"\x89PNG"};
        payload.push_back('\0');
        payload.push_back('\0');
        for (auto value = 0; value <= 255; ++value)
        {
            payload.push_back(static_cast<char>(value));
        }
        payload += "tail";

        auto const suffix = unique_test_suffix();
        auto const storage_id = "pg-binary-blob-" + suffix;
        auto const digest = std::string(64U, 'd');

        WHEN("the blob is stored and read back on the same store handle")
        {
            REQUIRE(merovingian::database::store_media_blob(
                opened.store,
                {storage_id, "blake2b", digest, static_cast<std::uint64_t>(payload.size()), payload, 1U}));
            auto const find_blob = [](merovingian::database::PersistentStore const& store,
                                      std::string const& id) -> merovingian::database::PersistentMediaBlob const* {
                auto const it = std::ranges::find_if(store.media_blobs,
                                                     [&id](merovingian::database::PersistentMediaBlob const& blob) {
                                                         return blob.storage_id == id;
                                                     });
                return it == store.media_blobs.end() ? nullptr : &(*it);
            };
            auto const* found_immediately = find_blob(opened.store, storage_id);

            // MED-6 (ADR-0113): a write records the blob's metadata in the
            // in-memory mirror but not its bytes, so the bytes are held once.
            THEN("the in-memory mirror records the blob's size but holds none of its bytes")
            {
                REQUIRE(found_immediately != nullptr);
                REQUIRE(found_immediately->size_bytes == payload.size());
                REQUIRE(found_immediately->bytes.empty());
            }

            AND_WHEN("the store is closed and reopened, forcing a real round trip through PostgreSQL")
            {
                opened = {};
                auto reopened = merovingian::database::open_postgresql_persistent_store(uri);

                THEN("the blob survives with every byte intact, including the NULs and high bytes")
                {
                    REQUIRE(reopened.ok);
                    auto const* reloaded = find_blob(reopened.store, storage_id);
                    REQUIRE(reloaded != nullptr);
                    REQUIRE(reloaded->bytes.size() == payload.size());
                    REQUIRE(reloaded->bytes == payload);
                }
            }
        }
    }
}

namespace
{

[[nodiscard]] auto find_signing_key(merovingian::database::PersistentStore const& store, std::string const& server_name,
                                    std::string const& key_id)
    -> merovingian::database::PersistentServerSigningKey const*
{
    auto const found = std::ranges::find_if(store.server_signing_keys,
                                            [&](merovingian::database::PersistentServerSigningKey const& key) {
                                                return key.server_name == server_name && key.key_id == key_id;
                                            });
    return found == store.server_signing_keys.end() ? nullptr : &(*found);
}

} // namespace

// 0.12.14 audit, DB-1: server_signing_keys.secret_key is a BYTEA column on
// PostgreSQL. The write stored the secretbox string intact, but the read
// returned PostgreSQL's `\x<hex>` text form undecoded, so after the first
// restart the server could not decrypt its own signing key and every
// federation signature failed. Every BLOB column must round-trip byte-exactly.
SCENARIO("PostgreSQL server signing key secret survives an open/close/reopen cycle unchanged",
         "[database][postgresql][integration][restart][signing_key][binary]")
{
    GIVEN("a live PostgreSQL URI and a stored secretbox:v1: signing key")
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
        auto const server_name = "pg-signing-store-" + suffix + ".example.org";
        auto const key_id = std::string{"ed25519:pgrestart"};
        auto const secret = std::string{"secretbox:v1:QUJDREVGR0hJSktM+/0123456789abcdefghijklmnopqrstuvwxyz=="};
        REQUIRE(merovingian::database::store_server_signing_key(
            opened.store, {server_name, key_id, "cHVibGljLWtleQ", 4102444800000U, secret}));

        WHEN("the store is closed and a brand-new store is opened against the same database")
        {
            opened = {};
            auto reopened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("secret_key equals the stored string, not its bytea hex representation")
            {
                REQUIRE(reopened.ok);
                auto const* key = find_signing_key(reopened.store, server_name, key_id);
                REQUIRE(key != nullptr);
                REQUIRE(key->secret_key == secret);
                REQUIRE(key->public_key == "cHVibGljLWtleQ");
            }

            AND_WHEN("only the validity window is refreshed with an empty secret, then the store is reopened")
            {
                REQUIRE(reopened.ok);
                REQUIRE(merovingian::database::store_server_signing_key(
                    reopened.store, {server_name, key_id, "cHVibGljLWtleQ", 4102444800001U, std::string{}}));
                reopened = {};
                auto third = merovingian::database::open_postgresql_persistent_store(uri);

                THEN("the stored secret is preserved and still reads back exactly")
                {
                    REQUIRE(third.ok);
                    auto const* key = find_signing_key(third.store, server_name, key_id);
                    REQUIRE(key != nullptr);
                    REQUIRE(key->secret_key == secret);
                    REQUIRE(key->valid_until_ts == 4102444800001U);
                }
            }
        }
    }
}

SCENARIO("PostgreSQL BLOB columns round-trip arbitrary non-UTF-8 bytes including 0x00 and 0xFF",
         "[database][postgresql][integration][restart][signing_key][binary]")
{
    GIVEN("a live PostgreSQL URI and a secret_key holding every byte value in a non-UTF-8 order")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened.ok);

        // Starts with a lone continuation byte and 0xFF, has embedded NULs, a
        // backslash run followed by "x41" (bytea's escape and hex spellings),
        // then every byte value descending, and ends on a NUL.
        auto payload = std::string{};
        for (auto const byte : {0x80, 0xFF, 0x00, 0x00, 0x5C, 0x5C, 0x78, 0x34, 0x31})
        {
            payload.push_back(static_cast<char>(byte));
        }
        for (auto value = 255; value >= 0; --value)
        {
            payload.push_back(static_cast<char>(value));
        }
        payload.push_back('\0');
        REQUIRE(payload.find('\0') != std::string::npos);

        auto const suffix = unique_test_suffix();
        auto const server_name = "pg-binary-key-" + suffix + ".example.org";
        auto const key_id = std::string{"ed25519:pgbinary"};
        REQUIRE(merovingian::database::store_server_signing_key(
            opened.store, {server_name, key_id, "cHVibGljLWtleQ", 4102444800000U, payload}));

        WHEN("the store is closed and reopened, forcing a real round trip through PostgreSQL")
        {
            opened = {};
            auto reopened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("every byte comes back exactly, with the same length")
            {
                REQUIRE(reopened.ok);
                auto const* key = find_signing_key(reopened.store, server_name, key_id);
                REQUIRE(key != nullptr);
                REQUIRE(key->secret_key.size() == payload.size());
                REQUIRE(key->secret_key == payload);
            }
        }
    }
}

// The whole path the audit traced: persisted secretbox key -> restart ->
// ensure_runtime_server_signing_key decrypts it -> the same identity.
SCENARIO("A PostgreSQL-backed runtime reloads its own signing key after a restart",
         "[database][postgresql][integration][restart][signing_key][homeserver]")
{
    GIVEN("a live PostgreSQL URI and a runtime that has minted and encrypted its signing key")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }

        auto const uri_file =
            merovingian::tests::temporary_directory() / ("merovingian-pg-uri-" + unique_test_suffix() + ".txt");
        {
            auto output = std::ofstream{uri_file};
            output << uri << '\n';
        }

        // A fresh server name keeps this scenario independent of signing keys
        // other runs left in the shared test database, which were encrypted
        // under master keys this process does not have.
        auto server = merovingian::config::ServerConfig{};
        server.server_name = "pg-signing-runtime-" + unique_test_suffix() + ".example.org";
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::postgresql;
        database.uri_file = uri_file.string();
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        auto const config = merovingian::config::Config{
            server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };

        auto first = merovingian::homeserver::start_runtime(config);
        REQUIRE(first.started);
        auto const original = merovingian::homeserver::ensure_runtime_server_signing_key(first.runtime);
        REQUIRE(original.has_value());
        REQUIRE(original->secret_key.starts_with("secretbox:v1:"));

        WHEN("the runtime is stopped and a new runtime starts against the same database")
        {
            first = {};
            auto second = merovingian::homeserver::start_runtime(config);
            REQUIRE(second.started);
            auto const reloaded = merovingian::homeserver::ensure_runtime_server_signing_key(second.runtime);

            THEN("the same signing key is returned, decrypted into the runtime's signing provider")
            {
                REQUIRE(reloaded.has_value());
                REQUIRE(reloaded->key_id == original->key_id);
                REQUIRE(reloaded->public_key == original->public_key);
                REQUIRE(reloaded->secret_key == original->secret_key);
                REQUIRE(second.runtime.database.signing_secret_key.bytes().size() > 0U);
            }
        }

        std::filesystem::remove(uri_file);
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

SCENARIO("PostgreSQL federation worker role: the worker profile never selects secret_key even though "
         "the role has column-restricted read access to server_signing_keys",
         "[database][postgresql][integration][roles][worker_db_uri]")
{
    GIVEN("a live PostgreSQL URI, migration role, and a federation-worker role granted SELECT on "
          "server_signing_keys' server_name/key_id/public_key/valid_until_ts columns but not secret_key "
          "(packaging/postgresql/provision-federation-worker-role.sql)")
    {
        auto const uri = postgresql_uri_from_environment();
        auto const migration_role = migration_role_from_environment();
        auto const worker_role = worker_role_from_environment();
        if (uri.empty() || migration_role.empty() || worker_role.empty())
        {
            SUCCEED("skipped: live PG URI, migration role, or "
                    "MEROVINGIAN_TEST_POSTGRESQL_WORKER_ROLE env vars are not set");
            return;
        }

        // Bring the schema to the current version first (as the migration
        // role), the same precondition every other role-enforcement scenario
        // in this file relies on, so the two opens below exercise only the
        // row-hydration path, not a migration under an unexpected role.
        {
            auto migrator = merovingian::database::open_postgresql_persistent_store(uri, {}, migration_role);
            REQUIRE(migrator.ok);
        }

        WHEN("the store opens under that role with TableLoadProfile::federation_worker")
        {
            auto const opened = merovingian::database::open_postgresql_persistent_store(
                uri, worker_role, {}, merovingian::database::TableLoadProfile::federation_worker);

            THEN("it succeeds, and no row's secret_key was ever hydrated into memory")
            {
                REQUIRE(opened.ok);
                // server_signing_keys itself is allowlisted (the worker's
                // remote-key cache legitimately reads other servers' rows),
                // but the worker-profile query never selects the secret_key
                // column at all -- every row loaded under this role and
                // profile must therefore carry an empty secret_key,
                // regardless of what the row actually holds in the database.
                for (auto const& key : opened.store.server_signing_keys)
                {
                    REQUIRE(key.secret_key.empty());
                }
            }
        }

        WHEN("the same role is asked to open with TableLoadProfile::full instead")
        {
            auto const opened = merovingian::database::open_postgresql_persistent_store(
                uri, worker_role, {}, merovingian::database::TableLoadProfile::full);

            THEN("the open fails, because the unrestricted profile SELECTs columns and tables this "
                 "least-privilege role was never granted (secret_key among them)")
            {
                REQUIRE_FALSE(opened.ok);
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
                auto const rows = executor.execute({"sp_select", "SELECT id FROM " + probe + " ORDER BY id", {}});
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
            auto const before =
                reader_exec.execute({"cc_before", "SELECT count(*) FROM " + probe + " WHERE id = 'shared'", {}});

            REQUIRE(writer_exec.execute({"cc_commit", "COMMIT", {}}).ok);

            // After commit, a fresh read on the other connection must see the row.
            auto const after =
                reader_exec.execute({"cc_after", "SELECT count(*) FROM " + probe + " WHERE id = 'shared'", {}});

            // A second connection inserting the same primary key must be rejected,
            // proving the unique constraint is enforced across connections.
            auto const conflict =
                reader_exec.execute({"cc_conflict", "INSERT INTO " + probe + " (id) VALUES ('shared')", {}});

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

SCENARIO("PostgreSQL reload_room picks up a room committed by a different store handle",
         "[database][postgresql][integration][reload][regression]")
{
    GIVEN("two independent store handles open on the same PostgreSQL database — modelling the federation worker's "
          "PersistentStore (handle A, hydrated once at worker startup) and the main process's PersistentStore "
          "(handle B, which keeps writing after that point)")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened_a = merovingian::database::open_postgresql_persistent_store(uri);
        auto opened_b = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened_a.ok);
        REQUIRE(opened_b.ok);

        auto const suffix = unique_test_suffix();
        auto const user_id = "@pg-reload-user-" + suffix + ":example.org";
        auto const room_id = "!pg-reload-room-" + suffix + ":example.org";
        auto const create_event_id = "$pg-reload-create-" + suffix + ":example.org";
        auto const member_event_id = "$pg-reload-member-" + suffix + ":example.org";

        WHEN("a room, membership, and events with DAG relations are committed through handle B only")
        {
            REQUIRE(merovingian::database::store_room(opened_b.store, {room_id, user_id}));
            REQUIRE(merovingian::database::store_membership(opened_b.store, {room_id, user_id, "join", 1U}) ==
                    merovingian::database::MembershipStoreResult::stored);
            REQUIRE(merovingian::database::store_event_with_state(
                opened_b.store,
                {create_event_id, room_id, user_id, R"({"type":"m.room.create","state_key":""})", 1U, 1U, {}, {}, {}},
                merovingian::database::PersistentStateEvent{room_id, "m.room.create", "", create_event_id}));
            REQUIRE(merovingian::database::store_event_with_state(
                opened_b.store,
                {member_event_id,
                 room_id,
                 user_id,
                 R"({"type":"m.room.member","state_key":")" + user_id + R"("})",
                 2U,
                 2U,
                 {create_event_id},
                 {create_event_id},
                 {}},
                merovingian::database::PersistentStateEvent{room_id, "m.room.member", user_id, member_event_id}));

            THEN("handle A, which never saw any of this, has no knowledge of the room before reloading")
            {
                REQUIRE(std::ranges::none_of(opened_a.store.rooms,
                                             [&room_id](merovingian::database::PersistentRoom const& r) {
                                                 return r.room_id == room_id;
                                             }));
            }

            AND_WHEN("reload_room is called on handle A for that room_id")
            {
                auto const reloaded = merovingian::database::reload_room(opened_a.store, room_id);

                THEN("it succeeds and handle A now has the room, membership, state, and event with its DAG "
                     "relations reconstructed")
                {
                    REQUIRE(reloaded);
                    REQUIRE(std::ranges::any_of(opened_a.store.rooms,
                                                [&room_id](merovingian::database::PersistentRoom const& r) {
                                                    return r.room_id == room_id;
                                                }));

                    auto const membership_it = std::ranges::find_if(
                        opened_a.store.memberships,
                        [&room_id, &user_id](merovingian::database::PersistentMembership const& m) {
                            return m.room_id == room_id && m.user_id == user_id;
                        });
                    REQUIRE(membership_it != opened_a.store.memberships.end());
                    REQUIRE(membership_it->membership == "join");

                    REQUIRE(std::ranges::count_if(opened_a.store.state,
                                                  [&room_id](merovingian::database::PersistentStateEvent const& s) {
                                                      return s.room_id == room_id;
                                                  }) == 2U);

                    auto const member_event_it = std::ranges::find_if(
                        opened_a.store.events, [&member_event_id](merovingian::database::PersistentEvent const& e) {
                            return e.event_id == member_event_id;
                        });
                    REQUIRE(member_event_it != opened_a.store.events.end());
                    REQUIRE(member_event_it->prev_event_ids == std::vector<std::string>{create_event_id});
                    REQUIRE(member_event_it->auth_event_ids == std::vector<std::string>{create_event_id});
                }
            }
        }
    }
}

// The role-switching functions existed and were covered by the scenario above
// long before anything called them: open_postgresql_persistent_store never
// issued SET ROLE, so a deployment that had provisioned the roles still served
// every request with its login role's full privileges. Testing the functions in
// isolation could never have caught that — this drives the open path itself.
SCENARIO("PostgreSQL store open assumes the configured roles and fails closed otherwise",
         "[database][postgresql][integration][pgroles]")
{
    GIVEN("a live PostgreSQL URI plus migration and runtime role names")
    {
        auto const uri = postgresql_uri_from_environment();
        auto const runtime_role = runtime_role_from_environment();
        if (uri.empty() || runtime_role.empty())
        {
            SUCCEED("skipped: live PG URI or role env vars are not set");
            return;
        }

        WHEN("the store is opened with the provisioned runtime role")
        {
            auto const opened = merovingian::database::open_postgresql_persistent_store(uri, runtime_role);

            THEN("the open succeeds")
            {
                REQUIRE(opened.ok);
            }
        }

        WHEN("the store is opened naming a runtime role that cannot be assumed")
        {
            auto const opened =
                merovingian::database::open_postgresql_persistent_store(uri, "merovingian_role_that_does_not_exist");

            THEN("the open is refused rather than serving with wider privileges")
            {
                // Fail closed: continuing here would serve traffic as the login
                // role, which is exactly the outcome the separation exists to
                // prevent — and it would do so silently.
                REQUIRE_FALSE(opened.ok);
                REQUIRE(opened.reason.find("runtime role") != std::string::npos);
            }
        }

        WHEN("the store is opened with no role names at all")
        {
            auto const opened = merovingian::database::open_postgresql_persistent_store(uri);

            THEN("it opens normally, preserving single-role deployments")
            {
                REQUIRE(opened.ok);
            }
        }
    }
}

// --- 0.12.5 security audit, finding 18 ---------------------------------------
//
// open_postgresql_persistent_store() applied pending migrations as the login
// role, which carries every privilege both sibling roles have, so the privilege
// separation the two roles exist for did not cover the one operation that
// actually needs DDL. Migrations now run after SET ROLE to the configured
// migration role, and the open fails closed if that role cannot be assumed.

namespace
{

// Hand ownership of the public schema to the migration role, exactly as the
// transfer at the end of packaging/postgresql/provision-roles.sql does.
//
// ALTER TABLE is permitted only to an object's owner, so a database whose
// schema was created by the login role cannot be migrated under the migration
// role until this runs -- that is the whole of audit finding 18's upgrade step.
// The scenario below arranges it rather than assuming an external provisioning
// step already did: in CI that step necessarily runs before any schema exists,
// so it matches nothing and the schema is created by the login role afterwards.
[[nodiscard]] auto grant_schema_ownership_to(std::string_view uri, std::string_view migration_role) -> bool
{
    auto connection = merovingian::database::open_postgresql_connection(uri);
    if (!connection.ok)
    {
        return false;
    }

    // Listed and altered from here rather than inside a DO $$ ... $$ block:
    // dollar-quoting collides with libpq's own $n parameter scanning, so the
    // block is rejected before PostgreSQL ever sees it.
    //
    // Scoped to what the connecting role owns, not REASSIGN OWNED: that
    // operates on everything the role owns including pinned system objects,
    // and fails outright when the login role is the cluster bootstrap
    // superuser -- which is what CI's postgres container produces.
    auto const alter_all = [&connection, migration_role](std::string_view list_sql,
                                                         std::string_view alter_prefix) -> bool {
        auto const listed = connection.connection.execute({"list_owned_objects", std::string{list_sql}, {}});
        if (!listed.ok)
        {
            return false;
        }
        for (auto const& row : listed.rows)
        {
            if (row.empty())
            {
                continue;
            }
            // Object names here come from the catalogue for a schema this test
            // just created, not from user input.
            auto const sql =
                std::string{alter_prefix} + "\"" + row.front() + "\" OWNER TO \"" + std::string{migration_role} + "\"";
            if (!connection.connection.execute({"alter_object_owner", sql, {}}).ok)
            {
                return false;
            }
        }
        return true;
    };

    return alter_all("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tableowner = current_user",
                     "ALTER TABLE public.") &&
           alter_all(
               "SELECT sequencename FROM pg_sequences WHERE schemaname = 'public' AND sequenceowner = current_user",
               "ALTER SEQUENCE public.");
}

// Roll the live database back one migration so the next open has real DDL to
// apply. Migrations are not written idempotently, so the column migration 14
// adds is dropped alongside its schema_migrations row; re-applying the
// migration is what restores both.
// Leaves exactly the newest migration pending: runs that migration's own
// downgrade step from the catalog and forgets its row. Undoing an older one
// (this used to hard-code version 14) leaves a gap that the planner rightly
// refuses ("migration versions must be contiguous") once newer migrations
// exist, and the damaged schema then fails every later scenario. Idempotent:
// Catch2 re-runs a WHEN once per leaf section, so a second call must find the
// migration already pending rather than undo it twice.
[[nodiscard]] auto make_migration_pending(std::string_view uri) -> bool
{
    auto connection = merovingian::database::open_postgresql_connection(uri);
    if (!connection.ok)
    {
        return false;
    }
    auto const newest = merovingian::database::current_schema_version();
    auto const newest_row = connection.connection.execute(
        {"newest_migration_row",
         "SELECT count(*) FROM schema_migrations WHERE version = '" + std::to_string(newest) + "'",
         {}});
    if (!newest_row.ok || newest_row.rows.size() != 1U || newest_row.rows.front().empty())
    {
        return false;
    }
    if (newest_row.rows.front().front() == "0")
    {
        return true;
    }
    auto const downgrades = merovingian::database::downgrade_migration_catalog();
    auto const undo = std::ranges::find_if(downgrades, [newest](merovingian::database::MigrationStep const& step) {
        return step.version + 1U == newest;
    });
    if (undo == downgrades.end())
    {
        return false;
    }
    for (auto const& statement : undo->statements)
    {
        if (!connection.connection.execute(statement).ok)
        {
            return false;
        }
    }
    auto const removed = connection.connection.execute(
        {"forget_migration_row", "DELETE FROM schema_migrations WHERE version = '" + std::to_string(newest) + "'", {}});
    return removed.ok;
}

} // namespace

SCENARIO("PostgreSQL migrations execute as the migration role, never as the login role",
         "[database][postgresql][integration][pgroles][security]")
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

        WHEN("the schema is already current and a migration role is configured")
        {
            auto const opened =
                merovingian::database::open_postgresql_persistent_store(uri, runtime_role, migration_role);

            THEN("the open succeeds and the schema is at the current version")
            {
                REQUIRE(opened.ok);
                REQUIRE(opened.store.schema.version == merovingian::database::current_schema_version());
            }
        }

        WHEN("the schema is already current but the named migration role cannot be assumed")
        {
            auto const opened = merovingian::database::open_postgresql_persistent_store(
                uri, runtime_role, "merovingian_migration_role_that_does_not_exist");

            THEN("the open still succeeds, because no DDL is attempted")
            {
                // A migration role that cannot be assumed must break an upgrade,
                // not every routine restart.
                REQUIRE(opened.ok);
            }
        }

        WHEN("a migration is pending and the named migration role cannot be assumed")
        {
            REQUIRE(grant_schema_ownership_to(uri, migration_role));
            REQUIRE(make_migration_pending(uri));
            auto const opened = merovingian::database::open_postgresql_persistent_store(
                uri, runtime_role, "merovingian_migration_role_that_does_not_exist");

            THEN("the open is refused rather than running DDL as the login role")
            {
                // Fail closed: falling back to the login role here would execute
                // schema mutation with the widest privileges in the deployment,
                // silently, on exactly the path the separation exists for.
                REQUIRE_FALSE(opened.ok);
                REQUIRE(opened.reason.find("migration role") != std::string::npos);
            }

            AND_THEN("the pending migration then applies under the real migration role")
            {
                auto const recovered =
                    merovingian::database::open_postgresql_persistent_store(uri, runtime_role, migration_role);
                REQUIRE(recovered.ok);
                REQUIRE(recovered.store.schema.version == merovingian::database::current_schema_version());
            }
        }

        WHEN("a migration is pending and no migration role is configured")
        {
            REQUIRE(make_migration_pending(uri));
            auto const opened = merovingian::database::open_postgresql_persistent_store(uri, runtime_role);

            THEN("it migrates as the login role, preserving single-role deployments")
            {
                REQUIRE(opened.ok);
                REQUIRE(opened.store.schema.version == merovingian::database::current_schema_version());
            }
        }
    }
}

// AUTH-1 follow-up: the in-memory audit window is a bounded view, so code that
// must not lose old rows (the admin safety-report listing) reads the table.
SCENARIO("PostgreSQL audit rows outlive the in-memory window and hydrate newest-last",
         "[database][postgresql][integration][audit][auth-1]")
{
    GIVEN("a live PostgreSQL store holding earlier reports and then more rows than the window keeps")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened.ok);
        auto& store = opened.store;

        // Event types are unique to this run so rows from other scenarios and
        // earlier runs in the shared database cannot be mistaken for ours.
        auto const suffix = unique_test_suffix();
        auto const report_prefix = "trust_safety_audit_" + suffix + ".";
        auto const flood_type = "flood_" + suffix;
        for (auto i = 0; i < 3; ++i)
        {
            REQUIRE(merovingian::database::append_audit_event(store, {"policy", report_prefix + "accept_report",
                                                                      "@reporter:example.org", "$e" + std::to_string(i),
                                                                      "spam"}));
        }
        auto const flood = merovingian::database::max_in_memory_audit_events + 76U;
        for (auto i = std::size_t{0U}; i < flood; ++i)
        {
            REQUIRE(merovingian::database::append_audit_event(
                store, {"auth", flood_type, "<unknown>", std::to_string(i), "flood"}));
        }

        WHEN("the rows are queried by event-type prefix")
        {
            auto const found = merovingian::database::load_audit_events_by_type_prefix(store, report_prefix, 1000U);
            auto const limited = merovingian::database::load_audit_events_by_type_prefix(store, report_prefix, 2U);
            auto const wildcard = merovingian::database::load_audit_events_by_type_prefix(store, "%", 1000U);

            THEN("every earlier report is found, newest first, although the window no longer holds them")
            {
                REQUIRE(store.audit_log.size() == merovingian::database::max_in_memory_audit_events);
                REQUIRE(std::ranges::none_of(store.audit_log, [&report_prefix](auto const& event) {
                    return event.event_type.starts_with(report_prefix);
                }));
                REQUIRE(found.size() == 3U);
                REQUIRE(found.front().target == "$e2");
                REQUIRE(found.back().target == "$e0");
                REQUIRE(limited.size() == 2U);
                REQUIRE(limited.front().target == "$e2");
                // The prefix is data, not a LIKE pattern.
                REQUIRE(wildcard.empty());
            }
        }

        WHEN("the store is reopened")
        {
            opened = {};
            auto reopened = merovingian::database::open_postgresql_persistent_store(uri);
            REQUIRE(reopened.ok);

            THEN("the hydrated window is the newest rows in insertion order")
            {
                auto const& log = reopened.store.audit_log;
                REQUIRE(log.size() == merovingian::database::max_in_memory_audit_events);
                REQUIRE(log.front().event_type == flood_type);
                REQUIRE(log.front().target == "76");
                REQUIRE(log.back().target == std::to_string(flood - 1U));
                for (auto i = std::size_t{1U}; i < log.size(); ++i)
                {
                    REQUIRE(std::stoul(log[i].target) == std::stoul(log[i - 1U].target) + 1U);
                }
            }
        }
    }
}
