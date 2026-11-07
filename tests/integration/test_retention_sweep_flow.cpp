// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/retention_sweep.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>

namespace
{

class TemporarySqliteDatabase final
{
public:
    TemporarySqliteDatabase()
    {
        auto const ticks = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = merovingian::tests::temporary_directory() /
                ("merovingian-retention-sweep-" + std::to_string(ticks) + ".sqlite3");
        remove_files();
    }
    ~TemporarySqliteDatabase()
    {
        remove_files();
    }
    TemporarySqliteDatabase(TemporarySqliteDatabase const&) = delete;
    auto operator=(TemporarySqliteDatabase const&) -> TemporarySqliteDatabase& = delete;
    TemporarySqliteDatabase(TemporarySqliteDatabase&&) = delete;
    auto operator=(TemporarySqliteDatabase&&) -> TemporarySqliteDatabase& = delete;

    [[nodiscard]] auto path() const noexcept -> std::filesystem::path const&
    {
        return path_;
    }

private:
    auto remove_files() const noexcept -> void
    {
        auto error = std::error_code{};
        std::filesystem::remove(path_, error);
        error.clear();
        std::filesystem::remove(path_.string() + "-wal", error);
        error.clear();
        std::filesystem::remove(path_.string() + "-shm", error);
        error.clear();
        std::filesystem::remove(path_.string() + "-journal", error);
    }

    std::filesystem::path path_{};
};

[[nodiscard]] auto sqlite_config(std::filesystem::path const& sqlite_path, std::uint32_t audit_retention_days)
    -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.audit_log_retention_days = audit_retention_days;
    merovingian::tests::enable_token_registration(security);
    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            std::move(database),
            std::move(security),
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}

// Counts the rows of `table` straight from the file, past every in-memory mirror.
[[nodiscard]] auto durable_row_count(std::filesystem::path const& path, std::string const& table,
                                     std::string const& where = "1 = 1") -> std::int64_t
{
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(path.string().c_str(), &raw) == SQLITE_OK);
    sqlite3_stmt* statement = nullptr;
    auto const sql = "SELECT count(*) FROM " + table + " WHERE " + where;
    REQUIRE(sqlite3_prepare_v2(raw, sql.c_str(), -1, &statement, nullptr) == SQLITE_OK);
    auto count = std::int64_t{-1};
    if (sqlite3_step(statement) == SQLITE_ROW)
    {
        count = sqlite3_column_int64(statement, 0);
    }
    sqlite3_finalize(statement);
    sqlite3_close(raw);
    return count;
}

auto const never_stopped = merovingian::homeserver::StopFlag{};

} // namespace

SCENARIO("The retention sweep deletes the sessions and tokens that can no longer authenticate",
         "[integration][sqlite][retention][g7]")
{
    GIVEN("a user with a live session, a logged-out session and a long-expired session")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(database.path(), 365U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const registration = merovingian::homeserver::register_local_user(
            runtime, "alice", "CorrectHorse7!Battery", merovingian::tests::registration_token);
        REQUIRE(registration.ok);
        auto const user_id = std::string{registration.value};
        auto const live = merovingian::homeserver::login_local_user(runtime, user_id, "CorrectHorse7!Battery", "LIVE");
        auto const logged_out =
            merovingian::homeserver::login_local_user(runtime, user_id, "CorrectHorse7!Battery", "OUT");
        auto const expired =
            merovingian::homeserver::login_local_user(runtime, user_id, "CorrectHorse7!Battery", "OLD");
        REQUIRE(live.ok);
        REQUIRE(logged_out.ok);
        REQUIRE(expired.ok);
        REQUIRE(merovingian::homeserver::logout_local_user(runtime, logged_out.value).ok);

        auto const now = std::chrono::system_clock::now();
        auto const long_ago = now - merovingian::homeserver::expired_access_token_grace - std::chrono::hours{1};
        auto& persistent = runtime.database.persistent_store;
        for (auto& session : runtime.database.sessions)
        {
            if (session.device_id == "OLD")
            {
                session.expires_at = long_ago;
            }
        }
        for (auto& token : persistent.access_tokens)
        {
            if (token.device_id == "OLD")
            {
                token.expires_at = long_ago;
            }
        }
        // The durable row must agree with the mirror: expire it through the file.
        {
            sqlite3* raw = nullptr;
            REQUIRE(sqlite3_open(database.path().string().c_str(), &raw) == SQLITE_OK);
            auto const sql = "UPDATE access_tokens SET expires_at = '" +
                             merovingian::database::expires_at_text(long_ago) + "' WHERE device_id = 'OLD'";
            REQUIRE(sqlite3_exec(raw, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
            sqlite3_close(raw);
        }
        auto const rows_before = durable_row_count(database.path(), "access_tokens");
        REQUIRE(rows_before == 3);

        // A refresh token that expired, one revoked but still valid (reuse detection needs it) and a live one.
        for (auto const& [hash, revoked, expires_at] : {
                 std::tuple{std::string{"token-hash:v4:expired-refresh"}, false, now - std::chrono::hours{1}},
                 std::tuple{std::string{"token-hash:v4:revoked-refresh"}, true,  now + std::chrono::hours{1}},
                 std::tuple{std::string{"token-hash:v4:live-refresh"},    false, now + std::chrono::hours{1}}
        })
        {
            REQUIRE(
                merovingian::database::store_refresh_token(persistent, {user_id, "LIVE", hash, revoked, expires_at}));
        }

        WHEN("the retention sweep runs")
        {
            auto const next = merovingian::homeserver::run_retention_sweep(runtime, now, never_stopped);

            THEN("only the live session's access token is left, in the database and in memory")
            {
                REQUIRE(durable_row_count(database.path(), "access_tokens") == 1);
                REQUIRE(runtime.database.sessions.size() == 1U);
                REQUIRE(runtime.database.sessions.front().device_id == "LIVE");
                REQUIRE(persistent.access_tokens.size() == 1U);
                REQUIRE(next == merovingian::homeserver::retention_sweep_interval);
            }

            AND_THEN("the live session still authenticates and the others do not")
            {
                REQUIRE(merovingian::homeserver::authenticated_user(runtime, live.value) == user_id);
                REQUIRE_FALSE(merovingian::homeserver::authenticated_user(runtime, logged_out.value).has_value());
                REQUIRE_FALSE(merovingian::homeserver::authenticated_user(runtime, expired.value).has_value());
            }

            AND_THEN("only the expired refresh token is deleted: a revoked one that is still valid is kept")
            {
                REQUIRE(durable_row_count(database.path(), "refresh_tokens",
                                          "token_hash = 'token-hash:v4:expired-refresh'") == 0);
                REQUIRE(durable_row_count(database.path(), "refresh_tokens",
                                          "token_hash = 'token-hash:v4:revoked-refresh'") == 1);
                REQUIRE(durable_row_count(database.path(), "refresh_tokens",
                                          "token_hash = 'token-hash:v4:live-refresh'") == 1);
            }
        }
    }
}

SCENARIO("An access token that expired recently is kept for the grace period", "[integration][sqlite][retention][g7]")
{
    GIVEN("a session that expired an hour ago")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(database.path(), 365U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registration = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse7!Battery",
                                                                               merovingian::tests::registration_token);
        REQUIRE(registration.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, std::string{registration.value},
                                                                     "CorrectHorse7!Battery", "RECENT");
        REQUIRE(login.ok);
        auto const now = std::chrono::system_clock::now();
        for (auto& token : runtime.database.persistent_store.access_tokens)
        {
            token.expires_at = now - std::chrono::hours{1};
        }

        WHEN("the retention sweep runs")
        {
            std::ignore = merovingian::homeserver::run_retention_sweep(runtime, now, never_stopped);

            THEN("the row is still there, so a later request is still told it expired")
            {
                REQUIRE(runtime.database.persistent_store.access_tokens.size() == 1U);
                REQUIRE(durable_row_count(database.path(), "access_tokens") == 1);
            }
        }
    }
}

SCENARIO("The retention sweep deletes audit rows past the configured retention and says so",
         "[integration][sqlite][retention][g7]")
{
    GIVEN("audit rows from 400 days ago and from today, and a 365 day retention")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(database.path(), 365U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const now = std::chrono::system_clock::now();
        auto const now_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
        auto const day_ms = std::uint64_t{86'400'000U};
        auto const baseline = durable_row_count(database.path(), "audit_log");
        for (auto index = 0; index < 1200; ++index)
        {
            REQUIRE(merovingian::database::append_audit_event(
                runtime.database.persistent_store,
                {"policy", "test.old", "actor", "target", "old " + std::to_string(index), now_ms - 400U * day_ms}));
        }
        REQUIRE(merovingian::database::append_audit_event(runtime.database.persistent_store,
                                                          {"policy", "test.recent", "actor", "target", "recent"}));
        REQUIRE(durable_row_count(database.path(), "audit_log", "event_type = 'test.old'") == 1200);

        WHEN("the retention sweep runs")
        {
            auto const next = merovingian::homeserver::run_retention_sweep(runtime, now, never_stopped);

            THEN("the old rows are gone, the recent ones stay and the purge is recorded")
            {
                REQUIRE(durable_row_count(database.path(), "audit_log", "event_type = 'test.old'") == 0);
                REQUIRE(durable_row_count(database.path(), "audit_log", "event_type = 'test.recent'") == 1);
                REQUIRE(durable_row_count(database.path(), "audit_log", "event_type = 'audit.retention.purged'") == 1);
                REQUIRE(durable_row_count(database.path(), "audit_log") >= baseline + 2);
                REQUIRE(next == merovingian::homeserver::retention_sweep_interval);
            }
        }
    }
}

SCENARIO("With retention set to zero the audit log is never trimmed", "[integration][sqlite][retention][g7]")
{
    GIVEN("a very old audit row and audit_log_retention_days of 0")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(database.path(), 0U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const now = std::chrono::system_clock::now();
        REQUIRE(merovingian::database::append_audit_event(
            runtime.database.persistent_store, {"policy", "test.ancient", "actor", "target", "ancient", 1U}));

        WHEN("the retention sweep runs")
        {
            std::ignore = merovingian::homeserver::run_retention_sweep(runtime, now, never_stopped);

            THEN("the row is still there")
            {
                REQUIRE(durable_row_count(database.path(), "audit_log", "event_type = 'test.ancient'") == 1);
            }
        }
    }
}

SCENARIO("One audit deletion batch never deletes more rows than its limit", "[integration][sqlite][retention][g7]")
{
    GIVEN("two hundred and fifty expired audit rows")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(database.path(), 365U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        for (auto index = 0; index < 250; ++index)
        {
            REQUIRE(merovingian::database::append_audit_event(
                runtime.database.persistent_store, {"policy", "test.batch", "a", "t", std::to_string(index), 1000U}));
        }

        WHEN("one batch of 100 is deleted")
        {
            REQUIRE(
                merovingian::database::delete_audit_rows_older_than(runtime.database.persistent_store, 5000U, 100U));

            THEN("exactly 150 remain, and a row stamped 0 is never touched")
            {
                REQUIRE(durable_row_count(database.path(), "audit_log", "event_type = 'test.batch'") == 150);
            }
        }
    }
}
