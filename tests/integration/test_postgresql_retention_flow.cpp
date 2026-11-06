// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "scratch_postgresql_database.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <libpq-fe.h>

namespace
{

namespace db = merovingian::database;

struct Finish final
{
    auto operator()(PGconn* connection) const noexcept -> void
    {
        PQfinish(connection);
    }
};

struct Clear final
{
    auto operator()(PGresult* result) const noexcept -> void
    {
        PQclear(result);
    }
};

struct FreeEscaped final
{
    auto operator()(char* text) const noexcept -> void
    {
        PQfreemem(text);
    }
};

[[nodiscard]] auto env_or_empty(char const* name) -> std::string
{
    auto const* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string{value};
}

// `name` as a quoted SQL identifier: a role name read from the environment can only ever name a role.
[[nodiscard]] auto quoted_identifier(std::string const& conninfo, std::string const& name) -> std::string
{
    auto const connection = std::unique_ptr<PGconn, Finish>{PQconnectdb(conninfo.c_str())};
    REQUIRE(PQstatus(connection.get()) == CONNECTION_OK);
    auto const quoted =
        std::unique_ptr<char, FreeEscaped>{PQescapeIdentifier(connection.get(), name.c_str(), name.size())};
    REQUIRE(quoted != nullptr);
    return std::string{quoted.get()};
}

// Runs `sql` as the connecting (owner) role, past the store under test. Returns the first column of the first row, or
// "" for a command.
[[nodiscard]] auto run_sql(std::string const& conninfo, std::string const& sql) -> std::string
{
    auto const connection = std::unique_ptr<PGconn, Finish>{PQconnectdb(conninfo.c_str())};
    REQUIRE(PQstatus(connection.get()) == CONNECTION_OK);
    auto const result = std::unique_ptr<PGresult, Clear>{PQexec(connection.get(), sql.c_str())};
    auto const status = PQresultStatus(result.get());
    INFO("sql " << sql << " -> " << PQerrorMessage(connection.get()));
    REQUIRE((status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK));
    if (status == PGRES_TUPLES_OK && PQntuples(result.get()) > 0)
    {
        return PQgetvalue(result.get(), 0, 0);
    }
    return {};
}

[[nodiscard]] auto count_of(std::string const& conninfo, std::string const& table, std::string const& where) -> int
{
    return std::stoi(run_sql(conninfo, "SELECT count(*) FROM " + table + " WHERE " + where));
}

[[nodiscard]] auto now_ms() -> std::uint64_t
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

constexpr auto day_ms = std::uint64_t{86'400'000U};

// A store on a database of the scenario's own, assuming the runtime role (DML only) when the environment names one.
struct OpenedStore final
{
    db::PersistentStore store{};
    bool ok{false};
};

[[nodiscard]] auto open_on(std::string const& conninfo) -> OpenedStore
{
    auto const runtime_role = env_or_empty("MEROVINGIAN_TEST_POSTGRESQL_RUNTIME_ROLE");
    auto const migration_role = env_or_empty("MEROVINGIAN_TEST_POSTGRESQL_MIGRATION_ROLE");
    if (!runtime_role.empty())
    {
        // The schema is created by the connecting (owner) role, then the runtime role gets what
        // packaging/postgresql/provision-roles.sql gives it on existing objects: USAGE on the schema and DML on
        // every table, and nothing else. The store under test then assumes that role.
        auto const bootstrap = db::open_postgresql_persistent_store(conninfo);
        INFO(bootstrap.reason);
        REQUIRE(bootstrap.ok);
        auto const grantee = quoted_identifier(conninfo, runtime_role);
        std::ignore = run_sql(conninfo, "GRANT USAGE ON SCHEMA public TO " + grantee);
        std::ignore =
            run_sql(conninfo, "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO " + grantee);
        std::ignore = run_sql(conninfo, "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO " + grantee);
    }
    auto opened = db::open_postgresql_persistent_store(conninfo, runtime_role,
                                                       runtime_role.empty() ? std::string{} : migration_role);
    INFO(opened.reason);
    return {std::move(opened.store), opened.ok};
}

} // namespace

SCENARIO("PostgreSQL audit retention deletes by age in bounded batches and keeps unstamped rows",
         "[database][postgresql][integration][retention][pg]")
{
    GIVEN("a PostgreSQL database holding old, recent and unstamped audit rows")
    {
        auto const uri = env_or_empty("MEROVINGIAN_TEST_POSTGRESQL_URI");
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        auto opened = open_on(scratch.conninfo());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const now = now_ms();
        for (auto index = 0; index < 5; ++index)
        {
            REQUIRE(db::append_audit_event(store,
                                           {"policy", "pg.old", "a", "t", std::to_string(index), now - 400U * day_ms}));
        }
        REQUIRE(db::append_audit_event(store, {"policy", "pg.recent", "a", "t", "recent"}));
        std::ignore =
            run_sql(scratch.conninfo(),
                    "INSERT INTO audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES "
                    "('policy', 'pg.unstamped', 'a', 't', 'unstamped', '0')");
        auto const cutoff = now - 365U * day_ms;

        WHEN("the probe runs and then a batch of three is deleted")
        {
            auto const exists_before = db::audit_rows_older_than_exist(store, cutoff);
            REQUIRE(db::delete_audit_rows_older_than(store, cutoff, 3U));

            THEN("the probe saw old rows, exactly three went, and the recent and unstamped rows are untouched")
            {
                REQUIRE(exists_before.has_value());
                REQUIRE(*exists_before);
                REQUIRE(count_of(scratch.conninfo(), "audit_log", "event_type = 'pg.old'") == 2);
                REQUIRE(count_of(scratch.conninfo(), "audit_log", "event_type = 'pg.recent'") == 1);
                REQUIRE(count_of(scratch.conninfo(), "audit_log", "event_type = 'pg.unstamped'") == 1);
            }

            AND_WHEN("another batch removes the rest")
            {
                REQUIRE(db::delete_audit_rows_older_than(store, cutoff, 100U));

                THEN("none are left, the probe says so, and the recent and unstamped rows remain")
                {
                    REQUIRE(count_of(scratch.conninfo(), "audit_log", "event_type = 'pg.old'") == 0);
                    auto const exists_after = db::audit_rows_older_than_exist(store, cutoff);
                    REQUIRE(exists_after.has_value());
                    REQUIRE_FALSE(*exists_after);
                    REQUIRE(count_of(scratch.conninfo(), "audit_log", "event_type = 'pg.recent'") == 1);
                    REQUIRE(count_of(scratch.conninfo(), "audit_log", "event_type = 'pg.unstamped'") == 1);
                }
            }
        }
    }
}

SCENARIO("PostgreSQL audit rows keep their order after retention has freed and reused space",
         "[database][postgresql][integration][retention][pg]")
{
    GIVEN("a kept row, old rows deleted and vacuumed away, then newer rows appended into the freed space")
    {
        auto const uri = env_or_empty("MEROVINGIAN_TEST_POSTGRESQL_URI");
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        auto const now = now_ms();
        {
            auto opened = open_on(scratch.conninfo());
            REQUIRE(opened.ok);
            auto& store = opened.store;
            REQUIRE(db::append_audit_event(store, {"policy", "pg.order.kept", "a", "t", "kept", now - 5000U}));
            for (auto index = 0; index < 20; ++index)
            {
                REQUIRE(db::append_audit_event(
                    store, {"policy", "pg.order.old", "a", "t", std::to_string(index), now - 400U * day_ms}));
            }
            REQUIRE(db::delete_audit_rows_older_than(store, now - 365U * day_ms, 100U));
            std::ignore = run_sql(scratch.conninfo(), "VACUUM audit_log");
            REQUIRE(db::append_audit_event(store, {"policy", "pg.order.r1", "a", "t", "r1", now - 3000U}));
            REQUIRE(db::append_audit_event(store, {"policy", "pg.order.r2", "a", "t", "r2", now - 2000U}));
            REQUIRE(db::append_audit_event(store, {"policy", "pg.order.r3", "a", "t", "r3", now - 1000U}));
        }

        WHEN("the store is opened again and the prefix is queried")
        {
            auto reopened = open_on(scratch.conninfo());
            REQUIRE(reopened.ok);
            auto const newest_first = db::load_audit_events_by_type_prefix(reopened.store, "pg.order.", 10U);

            THEN("hydration holds the rows oldest first by time and the query returns them newest first")
            {
                auto hydrated = std::vector<std::string>{};
                for (auto const& event : reopened.store.audit_log)
                {
                    if (event.event_type.starts_with("pg.order."))
                    {
                        hydrated.push_back(event.reason);
                    }
                }
                REQUIRE(hydrated == std::vector<std::string>{"kept", "r1", "r2", "r3"});
                REQUIRE(newest_first.size() == 4U);
                REQUIRE(newest_first[0].reason == "r3");
                REQUIRE(newest_first[1].reason == "r2");
                REQUIRE(newest_first[2].reason == "r1");
                REQUIRE(newest_first[3].reason == "kept");
            }
        }
    }
}

SCENARIO("PostgreSQL credential retention deletes only the named rows",
         "[database][postgresql][integration][retention][pg]")
{
    GIVEN("a revoked and a live access token and an expired and a live refresh token")
    {
        auto const uri = env_or_empty("MEROVINGIAN_TEST_POSTGRESQL_URI");
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        auto opened = open_on(scratch.conninfo());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const now = std::chrono::system_clock::now();
        REQUIRE(db::store_access_token(store, {"@u:example.org", "D1", "token-hash:v4:revoked", true, std::nullopt}));
        REQUIRE(db::store_access_token(store, {"@u:example.org", "D2", "token-hash:v4:live", false, std::nullopt}));
        REQUIRE(db::store_refresh_token(
            store, {"@u:example.org", "D1", "token-hash:v4:r-expired", false, now - std::chrono::hours{1}}));
        REQUIRE(db::store_refresh_token(
            store, {"@u:example.org", "D2", "token-hash:v4:r-live", false, now + std::chrono::hours{1}}));

        WHEN("the unusable credentials are collected, deleted and forgotten")
        {
            auto const unusable = db::collect_unusable_credentials(store, now, std::chrono::hours{0});
            REQUIRE(db::delete_credential_rows(store, unusable.access_token_hashes, unusable.refresh_token_hashes));
            db::forget_credentials(store, unusable);

            THEN("the database and memory lose exactly the revoked access token and the expired refresh token")
            {
                REQUIRE(unusable.access_token_hashes.size() == 1U);
                REQUIRE(unusable.refresh_token_hashes.size() == 1U);
                REQUIRE(count_of(scratch.conninfo(), "access_tokens", "token_hash = 'token-hash:v4:revoked'") == 0);
                REQUIRE(count_of(scratch.conninfo(), "access_tokens", "token_hash = 'token-hash:v4:live'") == 1);
                REQUIRE(count_of(scratch.conninfo(), "refresh_tokens", "token_hash = 'token-hash:v4:r-expired'") == 0);
                REQUIRE(count_of(scratch.conninfo(), "refresh_tokens", "token_hash = 'token-hash:v4:r-live'") == 1);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.refresh_tokens.size() == 1U);
            }
        }
    }
}

SCENARIO("PostgreSQL registration and logout writes commit together or not at all",
         "[database][postgresql][integration][retention][pg]")
{
    GIVEN("a PostgreSQL store")
    {
        auto const uri = env_or_empty("MEROVINGIAN_TEST_POSTGRESQL_URI");
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        auto opened = open_on(scratch.conninfo());
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("an account and its profile are stored")
        {
            REQUIRE(db::store_user_with_profile(store, {"@ok:example.org", "hash", false, false, false},
                                                {"@ok:example.org", "", ""}));

            THEN("both rows exist in the database and in memory")
            {
                REQUIRE(count_of(scratch.conninfo(), "users", "user_id = '@ok:example.org'") == 1);
                REQUIRE(count_of(scratch.conninfo(), "profiles", "user_id = '@ok:example.org'") == 1);
                REQUIRE(store.users.size() == 1U);
                REQUIRE(store.profiles.size() == 1U);
            }
        }

        WHEN("the profile statement fails after the user statement succeeded")
        {
            std::ignore = run_sql(scratch.conninfo(),
                                  "ALTER TABLE profiles ADD CONSTRAINT refuse_boom CHECK (displayname <> 'boom')");
            auto const stored = db::store_user_with_profile(store, {"@bad:example.org", "hash", false, false, false},
                                                            {"@bad:example.org", "boom", ""});

            THEN("nothing is stored, in the database or in memory")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(count_of(scratch.conninfo(), "users", "user_id = '@bad:example.org'") == 0);
                REQUIRE(count_of(scratch.conninfo(), "profiles", "user_id = '@bad:example.org'") == 0);
                REQUIRE(store.users.empty());
                REQUIRE(store.profiles.empty());
            }
        }

        WHEN("a device's credentials are revoked together")
        {
            REQUIRE(db::store_access_token(store,
                                           {"@dev:example.org", "D1", "token-hash:v4:presented", false, std::nullopt}));
            REQUIRE(db::store_access_token(store,
                                           {"@dev:example.org", "D1", "token-hash:v4:sibling", false, std::nullopt}));
            REQUIRE(db::store_refresh_token(store,
                                            {"@dev:example.org", "D1", "token-hash:v4:refresh", false, std::nullopt}));
            REQUIRE(db::revoke_device_credentials(store, "token-hash:v4:presented", "@dev:example.org", "D1"));

            THEN("every access and refresh token of the device is revoked in the database and in memory")
            {
                REQUIRE(count_of(scratch.conninfo(), "access_tokens",
                                 "user_id = '@dev:example.org' AND revoked = 'true'") == 2);
                REQUIRE(count_of(scratch.conninfo(), "refresh_tokens", "revoked = 'true'") == 1);
                for (auto const& token : store.access_tokens)
                {
                    REQUIRE(token.revoked);
                }
                REQUIRE(store.refresh_tokens.front().revoked);
            }
        }

        WHEN("the refresh-token revocation fails after the access-token revocation succeeded")
        {
            REQUIRE(db::store_access_token(
                store, {"@fail:example.org", "D1", "token-hash:v4:fail-access", false, std::nullopt}));
            REQUIRE(db::store_refresh_token(
                store, {"@fail:example.org", "D1", "token-hash:v4:fail-refresh", false, std::nullopt}));
            std::ignore =
                run_sql(scratch.conninfo(),
                        "ALTER TABLE refresh_tokens ADD CONSTRAINT keep_fail CHECK (user_id <> '@fail:example.org' OR "
                        "revoked <> 'true')");
            auto const revoked =
                db::revoke_device_credentials(store, "token-hash:v4:fail-access", "@fail:example.org", "D1");

            THEN("the whole revocation rolled back and memory is unchanged")
            {
                REQUIRE_FALSE(revoked);
                REQUIRE(count_of(scratch.conninfo(), "access_tokens",
                                 "user_id = '@fail:example.org' AND revoked = 'false'") == 1);
                REQUIRE_FALSE(store.access_tokens.back().revoked);
                REQUIRE_FALSE(store.refresh_tokens.back().revoked);
            }
        }
    }
}
