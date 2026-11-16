// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/OAuthClientStoreResult.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentOAuthClient.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/AuthorizationGrant.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/PendingAuthorisation.hpp"
#include "merovingian/homeserver/PendingAuthorisationStore.hpp"
#include "merovingian/homeserver/RetentionSweep.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"

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
#include <variant>
#include <vector>

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
        std::ignore = persistent.access_tokens.set_expires_at_where(
            [](merovingian::database::PersistentAccessToken const& token) {
                return token.device_id == "OLD";
            },
            long_ago);
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
        std::ignore = runtime.database.persistent_store.access_tokens.set_expires_at_where(
            [](merovingian::database::PersistentAccessToken const&) {
                return true;
            },
            now - std::chrono::hours{1});

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

namespace
{

[[nodiscard]] auto oauth_client_at(std::string id, std::chrono::system_clock::time_point at)
    -> merovingian::database::PersistentOAuthClient
{
    auto const at_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(at.time_since_epoch()).count());
    return {std::move(id), R"({"client_name":"Example"})", at_ms, at_ms};
}

[[nodiscard]] auto oauth_session_of(std::string user_id, std::string device_id, std::string client_id)
    -> merovingian::database::PersistentOAuthSession
{
    return {std::move(user_id), std::move(device_id), std::move(client_id), "urn:matrix:client:api:*", 1000U};
}

} // namespace

SCENARIO("The retention sweep deletes OAuth clients unused for 30 days, never one with a session",
         "[integration][sqlite][retention][oauth]")
{
    GIVEN("a client unused for 31 days, one unused as long that holds a session, and one used 29 days ago")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(database.path(), 365U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& persistent = runtime.database.persistent_store;
        auto const registration = merovingian::homeserver::register_local_user(
            runtime, "alice", "CorrectHorse7!Battery", merovingian::tests::registration_token);
        REQUIRE(registration.ok);
        auto const user_id = std::string{registration.value};
        REQUIRE(merovingian::homeserver::login_local_user(runtime, user_id, "CorrectHorse7!Battery", "OAUTHDEV").ok);

        auto const now = std::chrono::system_clock::now();
        auto const now_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
        auto const day = std::chrono::hours{24};
        REQUIRE(merovingian::database::store_oauth_client(persistent, oauth_client_at("old-idle", now - (31 * day))) ==
                merovingian::database::OAuthClientStoreResult::inserted);
        REQUIRE(merovingian::database::store_oauth_client(persistent, oauth_client_at("old-held", now - (31 * day))) ==
                merovingian::database::OAuthClientStoreResult::inserted);
        REQUIRE(
            merovingian::database::store_oauth_client(persistent, oauth_client_at("recent-idle", now - (29 * day))) ==
            merovingian::database::OAuthClientStoreResult::inserted);
        REQUIRE(
            merovingian::database::store_oauth_session(persistent, oauth_session_of(user_id, "OAUTHDEV", "old-held")));

        WHEN("the retention sweep runs")
        {
            auto const next = merovingian::homeserver::run_retention_sweep(runtime, now, never_stopped);

            THEN("only the sessionless client past 30 days is deleted, from the database and from memory")
            {
                REQUIRE(durable_row_count(database.path(), "oauth_clients", "client_id = 'old-idle'") == 0);
                REQUIRE(durable_row_count(database.path(), "oauth_clients", "client_id = 'old-held'") == 1);
                REQUIRE(durable_row_count(database.path(), "oauth_clients", "client_id = 'recent-idle'") == 1);
                REQUIRE(merovingian::database::find_oauth_client(persistent, "old-idle") == nullptr);
                REQUIRE(merovingian::database::find_oauth_client(persistent, "old-held") != nullptr);
                REQUIRE(merovingian::database::find_oauth_client(persistent, "recent-idle") != nullptr);
                REQUIRE(next == merovingian::homeserver::retention_sweep_interval);
            }

            AND_THEN("no pending authorisation or code names a client")
            {
                REQUIRE_FALSE(
                    merovingian::homeserver::oauth_client_has_pending_authorisation(runtime, "recent-idle", now_ms));
            }
        }

        WHEN("a pending authorisation names the idle client and an unredeemed code another, and the sweep runs")
        {
            auto authorisation = merovingian::homeserver::PendingAuthorisation{};
            authorisation.client_id = "old-idle";
            REQUIRE(std::holds_alternative<std::string>(runtime.oauth_pending_authorisations.create(
                std::move(authorisation), "browser-token", "198.51.100.7", now_ms)));
            REQUIRE(
                merovingian::database::store_oauth_client(persistent, oauth_client_at("old-coded", now - (31 * day))) ==
                merovingian::database::OAuthClientStoreResult::inserted);
            auto grant = merovingian::homeserver::AuthorizationGrant{};
            grant.client_id = "old-coded";
            REQUIRE(std::holds_alternative<std::string>(runtime.oauth_codes.issue(std::move(grant), now_ms)));
            REQUIRE(merovingian::homeserver::oauth_client_has_pending_authorisation(runtime, "old-idle", now_ms));
            REQUIRE(merovingian::homeserver::oauth_client_has_pending_authorisation(runtime, "old-coded", now_ms));
            std::ignore = merovingian::homeserver::run_retention_sweep(runtime, now, never_stopped);

            THEN("both clients are kept")
            {
                REQUIRE(merovingian::database::find_oauth_client(persistent, "old-idle") != nullptr);
                REQUIRE(durable_row_count(database.path(), "oauth_clients", "client_id = 'old-idle'") == 1);
                REQUIRE(merovingian::database::find_oauth_client(persistent, "old-coded") != nullptr);
                REQUIRE(durable_row_count(database.path(), "oauth_clients", "client_id = 'old-coded'") == 1);
            }

            AND_THEN("once the authorisation's ten minutes are over, the seam answers false for that client")
            {
                auto const expired_ms = now_ms + merovingian::homeserver::PendingAuthorisationStore::lifetime_ms;
                REQUIRE_FALSE(
                    merovingian::homeserver::oauth_client_has_pending_authorisation(runtime, "old-idle", expired_ms));
            }
        }
    }
}

SCENARIO("The OAuth client sweep deletes at most 500 clients per transaction",
         "[integration][sqlite][retention][oauth]")
{
    GIVEN("1001 clients unused for 40 days")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(database.path(), 365U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& persistent = runtime.database.persistent_store;
        auto const now = std::chrono::system_clock::now();
        for (auto index = 0; index < 1001; ++index)
        {
            REQUIRE(merovingian::database::store_oauth_client(
                        persistent, oauth_client_at("client-" + std::to_string(index),
                                                    now - std::chrono::hours{24 * 40} + std::chrono::seconds{index})) ==
                    merovingian::database::OAuthClientStoreResult::inserted);
        }

        WHEN("the retention sweep runs")
        {
            auto const before = merovingian::database::committed_transaction_count(persistent);
            std::ignore = merovingian::homeserver::run_retention_sweep(runtime, now, never_stopped);
            auto const transactions = merovingian::database::committed_transaction_count(persistent) - before;

            THEN("every client goes, in three transactions of at most 500")
            {
                REQUIRE(durable_row_count(database.path(), "oauth_clients") == 0);
                REQUIRE(merovingian::database::oauth_client_count(persistent) == 0U);
                REQUIRE(transactions == 3U);
            }
        }
    }
}

SCENARIO("Every way a device is deleted deletes its OAuth session row", "[integration][sqlite][oauth][device]")
{
    GIVEN("alice with four OAuth devices, each holding a session")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(database.path(), 365U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& persistent = runtime.database.persistent_store;
        auto const registration = merovingian::homeserver::register_local_user(
            runtime, "alice", "CorrectHorse7!Battery", merovingian::tests::registration_token);
        REQUIRE(registration.ok);
        auto const user_id = std::string{registration.value};
        REQUIRE(merovingian::database::store_oauth_client(
                    persistent, oauth_client_at("client-a", std::chrono::system_clock::now())) ==
                merovingian::database::OAuthClientStoreResult::inserted);
        auto tokens = std::vector<std::string>{};
        for (auto const* device : {"DEVA", "DEVB", "DEVC", "DEVD"})
        {
            auto const login =
                merovingian::homeserver::login_local_user(runtime, user_id, "CorrectHorse7!Battery", device);
            REQUIRE(login.ok);
            tokens.emplace_back(login.value);
            REQUIRE(
                merovingian::database::store_oauth_session(persistent, oauth_session_of(user_id, device, "client-a")));
        }
        auto const session_rows = [&database](std::string const& device) {
            return durable_row_count(database.path(), "oauth_sessions", "device_id = '" + device + "'");
        };
        REQUIRE(session_rows("DEVA") == 1);

        WHEN("DEVA logs out, DEVD is deleted through the device API, then DEVB logs out everywhere")
        {
            REQUIRE(merovingian::homeserver::logout_local_user(runtime, tokens[0]).ok);
            auto const after_logout_a = session_rows("DEVA");
            auto const b_after_logout_a = session_rows("DEVB");
            REQUIRE(merovingian::homeserver::delete_local_device(runtime, user_id, "DEVD").ok);
            auto const after_delete_d = session_rows("DEVD");
            REQUIRE(merovingian::homeserver::logout_all_local_user(runtime, tokens[1]).ok);

            THEN("each removed device's session row is gone from the database and from memory, and the client "
                 "is then sessionless")
            {
                REQUIRE(after_logout_a == 0);
                REQUIRE(b_after_logout_a == 1);
                REQUIRE(after_delete_d == 0);
                REQUIRE(durable_row_count(database.path(), "oauth_sessions") == 0);
                REQUIRE(merovingian::database::oauth_sessions_of_user(persistent, user_id).empty());
                REQUIRE_FALSE(merovingian::database::oauth_client_has_session(persistent, "client-a"));
                REQUIRE(durable_row_count(database.path(), "oauth_clients", "client_id = 'client-a'") == 1);
            }
        }
    }
}

SCENARIO("The retention sweep deletes an OAuth session row once its device holds no live token",
         "[integration][sqlite][retention][oauth][oauth-session-end]")
{
    GIVEN("two clients unused for 31 days, one session whose refresh token expires in an hour, one in 90 days")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_config(database.path(), 365U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& persistent = runtime.database.persistent_store;
        auto const registration = merovingian::homeserver::register_local_user(
            runtime, "alice", "CorrectHorse7!Battery", merovingian::tests::registration_token);
        REQUIRE(registration.ok);
        auto const user_id = std::string{registration.value};
        auto const now = std::chrono::system_clock::now();
        auto const day = std::chrono::hours{24};
        auto const add_session = [&](std::string const& device, std::string const& client,
                                     std::chrono::system_clock::time_point refresh_expires_at) {
            REQUIRE(merovingian::database::store_oauth_client(persistent, oauth_client_at(client, now - (31 * day))) ==
                    merovingian::database::OAuthClientStoreResult::inserted);
            REQUIRE(merovingian::database::store_oauth_session(persistent, oauth_session_of(user_id, device, client)));
            REQUIRE(merovingian::database::store_access_token(
                persistent, {user_id, device, "token-hash:v4:access-" + device, false, now + std::chrono::minutes{5}}));
            REQUIRE(merovingian::database::store_refresh_token(
                persistent, {user_id, device, "token-hash:v4:refresh-" + device, false, refresh_expires_at}));
        };
        add_session("DEVENDING", "client-ending", now + std::chrono::hours{1});
        add_session("DEVLIVE", "client-live", now + (90 * day));
        auto const session_rows = [&database](std::string const& device) {
            return durable_row_count(database.path(), "oauth_sessions", "device_id = '" + device + "'");
        };

        WHEN("the sweep runs while both refresh tokens are live")
        {
            std::ignore = merovingian::homeserver::run_retention_sweep(runtime, now, never_stopped);

            THEN("both sessions and both clients are kept")
            {
                REQUIRE(session_rows("DEVENDING") == 1);
                REQUIRE(session_rows("DEVLIVE") == 1);
                REQUIRE(merovingian::database::find_oauth_client(persistent, "client-ending") != nullptr);
                REQUIRE(merovingian::database::find_oauth_client(persistent, "client-live") != nullptr);
            }
        }

        WHEN("the sweep runs two hours later, when one refresh token has expired")
        {
            std::ignore =
                merovingian::homeserver::run_retention_sweep(runtime, now + std::chrono::hours{2}, never_stopped);

            THEN("that session's row goes, from the database and from memory, and its client goes with it")
            {
                REQUIRE(session_rows("DEVENDING") == 0);
                REQUIRE(merovingian::database::find_oauth_session(persistent, user_id, "DEVENDING") == nullptr);
                REQUIRE(durable_row_count(database.path(), "oauth_clients", "client_id = 'client-ending'") == 0);
                REQUIRE(merovingian::database::find_oauth_client(persistent, "client-ending") == nullptr);
            }

            THEN("the session whose refresh token is live, and its client, are kept")
            {
                REQUIRE(session_rows("DEVLIVE") == 1);
                REQUIRE(merovingian::database::find_oauth_session(persistent, user_id, "DEVLIVE") != nullptr);
                REQUIRE(merovingian::database::find_oauth_client(persistent, "client-live") != nullptr);
            }
        }
    }
}
