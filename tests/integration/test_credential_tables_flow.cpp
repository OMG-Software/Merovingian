// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"

// F-08 part 1 (security audit run 4): every token lookup and revocation scanned the whole access_tokens and
// refresh_tokens vectors under runtime.mutex, so the cost of a refresh grew with every other user's rows. The two
// tables are now CredentialTable (rows plus a digest index by hash, an index by (user, device), by user and, for
// refresh tokens, by predecessor), and SessionTable gained a per-device index. These tests prove the cost with the
// rows-examined counters, never with time, and that the indexes agree with the rows after every kind of change.
//
// Spec: Matrix Client-Server API v1.19, "POST /refresh" and "Account management" (a token the server revokes
// MUST stop authenticating; the old refresh token is revoked once the new pair is used). The tests pin that the
// answers did not change when the lookups became indexed. ../../docs/matrix-v1.19-spec/client-server-api.md

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
#include "merovingian/database/CredentialTable.hpp"
#include "merovingian/database/PersistentAccessToken.hpp"
#include "merovingian/database/PersistentRefreshToken.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalSession.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/SessionTable.hpp"
#include "merovingian/homeserver/AuthService.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;

[[nodiscard]] auto credential_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto fake_hash(std::string_view kind, std::size_t number) -> std::string
{
    return "token-hash:v4:" + std::string{kind} + std::to_string(number);
}

[[nodiscard]] auto rows_examined(db::PersistentStore const& store) -> std::uint64_t
{
    return store.access_tokens.rows_examined().value() + store.refresh_tokens.rows_examined().value();
}

// Rows of other users, spread over 50 users with one device each, so no other user's rows are alice's.
auto pad_with_other_users(db::PersistentStore& store, std::size_t count) -> void
{
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        auto const user = "@other" + std::to_string(index % 50U) + ":example.org";
        auto const device = "OTHER" + std::to_string(index);
        REQUIRE(db::store_access_token(store, {user, device, fake_hash("pad-a", index), false, std::nullopt, {}}));
        REQUIRE(db::store_refresh_token(store, {user, device, fake_hash("pad-r", index), false, std::nullopt, {}}));
    }
}

struct OperationCosts final
{
    std::uint64_t store_tokens{0U};
    std::uint64_t revoke_access_for_device{0U};
    std::uint64_t revoke_refresh_for_device{0U};
    std::uint64_t revoke_with_predecessor{0U};
    std::uint64_t refresh_session{0U};
    std::uint64_t unknown_refresh_token{0U};
};

// One runtime holding alice and `others` rows of other users; the rows each operation examined.
[[nodiscard]] auto measure_costs(std::size_t others) -> OperationCosts
{
    REQUIRE(sodium_init() >= 0);
    auto started = hs::start_runtime(credential_config());
    REQUIRE(started.started);
    auto& runtime = started.runtime;
    auto& store = runtime.database.persistent_store;

    auto const registered =
        hs::register_local_user(runtime, "alice", "CorrectHorse7!", merovingian::tests::registration_token);
    REQUIRE(registered.ok);
    REQUIRE(hs::login_local_user(runtime, registered.value, "CorrectHorse7!", "DEVICE1").ok);
    auto const issued = hs::issue_refresh_token_for_session(runtime, registered.value, "DEVICE1");
    REQUIRE(issued.ok);
    pad_with_other_users(store, others);

    auto costs = OperationCosts{};

    auto before = rows_examined(store);
    auto const refreshed = hs::refresh_local_session(runtime, issued.value);
    REQUIRE(refreshed.ok);
    costs.refresh_session = rows_examined(store) - before;

    before = rows_examined(store);
    REQUIRE(hs::refresh_local_session(runtime, "mvs_not_a_token_anyone_holds").ok == false);
    costs.unknown_refresh_token = rows_examined(store) - before;

    before = rows_examined(store);
    REQUIRE(db::store_access_token(
        store, {registered.value, "DEVICE2", fake_hash("alice-a", 1U), false, std::nullopt, fake_hash("pred", 1U)}));
    REQUIRE(db::store_refresh_token(
        store, {registered.value, "DEVICE2", fake_hash("alice-r", 1U), false, std::nullopt, fake_hash("pred", 1U)}));
    costs.store_tokens = rows_examined(store) - before;

    before = rows_examined(store);
    REQUIRE(db::revoke_refresh_tokens_with_predecessor(store, fake_hash("pred", 1U)) == 1U);
    costs.revoke_with_predecessor = rows_examined(store) - before;

    before = rows_examined(store);
    REQUIRE(db::revoke_access_tokens_for_device(store, registered.value, "DEVICE2") == 1U);
    costs.revoke_access_for_device = rows_examined(store) - before;

    before = rows_examined(store);
    std::ignore = db::revoke_refresh_tokens_for_device(store, registered.value, "DEVICE2");
    costs.revoke_refresh_for_device = rows_examined(store) - before;
    return costs;
}

} // namespace

// Indexed lookups cost the rows they touch, not the rows the table holds. Padding the tables with 200 and then 400
// rows of other users must not change the number of rows any credential operation examines.
SCENARIO("Credential operations examine the same rows however many other users' tokens exist", "[f08][credential]")
{
    GIVEN("the rows each operation examines with 200 other-user rows and with 400")
    {
        auto const small = measure_costs(200U);
        auto const large = measure_costs(400U);

        THEN("storing a token examines the same rows at both sizes")
        {
            REQUIRE(small.store_tokens == large.store_tokens);
        }
        THEN("each per-device revoke examines the same rows at both sizes")
        {
            REQUIRE(small.revoke_access_for_device > 0U);
            REQUIRE(small.revoke_access_for_device == large.revoke_access_for_device);
            REQUIRE(small.revoke_refresh_for_device > 0U);
            REQUIRE(small.revoke_refresh_for_device == large.revoke_refresh_for_device);
        }
        THEN("the per-predecessor revoke examines the same rows at both sizes")
        {
            REQUIRE(small.revoke_with_predecessor > 0U);
            REQUIRE(small.revoke_with_predecessor == large.revoke_with_predecessor);
        }
        THEN("one refresh examines the same rows at both sizes")
        {
            REQUIRE(small.refresh_session > 0U);
            REQUIRE(small.refresh_session == large.refresh_session);
        }
        THEN("an unknown refresh token examines the same rows at both sizes, with no scan after the miss")
        {
            REQUIRE(small.unknown_refresh_token == large.unknown_refresh_token);
        }
    }
}

SCENARIO("Every site that mints a refresh token stamps the wall clock", "[f08][credential]")
{
    GIVEN("a registered user with a device")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(credential_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered =
            hs::register_local_user(runtime, "alice", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(registered.ok);
        REQUIRE(hs::login_local_user(runtime, registered.value, "CorrectHorse7!", "DEVICE1").ok);
        auto const before =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();

        WHEN("a refresh token is issued and then rotated")
        {
            auto const issued = hs::issue_refresh_token_for_session(runtime, registered.value, "DEVICE1");
            REQUIRE(issued.ok);
            auto const rotated = hs::refresh_local_session(runtime, issued.value);
            REQUIRE(rotated.ok);

            THEN("both rows carry a time no earlier than the start of the test")
            {
                auto const& rows = runtime.database.persistent_store.refresh_tokens;
                REQUIRE(rows.size() == 2U);
                for (auto const& row : rows)
                {
                    REQUIRE(row.issued_at_ms >= before);
                }
            }
        }
    }
}

// F-08 part 2 (ADR-0590): a login on a held device replaces its credentials, a rotation keeps at most
// `max_retired_refresh_tokens_per_device` retired refresh rows, and the retention sweep drops a retired refresh row
// of a device that no longer exists. Every cost is proved with the rows-examined counters.
namespace
{

constexpr auto kPassword = "CorrectHorse7!";
constexpr auto kRetiredCap = std::size_t{32U};

struct DeviceRows final
{
    std::size_t access{0U};
    std::size_t refresh{0U};
    std::size_t retired_refresh{0U};
    std::size_t unrevoked_refresh{0U};
    std::size_t sessions{0U};
};

[[nodiscard]] auto device_rows(db::PersistentStore const& store, std::string_view user_id, std::string_view device_id)
    -> DeviceRows
{
    auto rows = DeviceRows{};
    for (auto const& token : store.access_tokens)
    {
        rows.access += token.user_id == user_id && token.device_id == device_id ? 1U : 0U;
    }
    for (auto const& token : store.refresh_tokens)
    {
        if (token.user_id == user_id && token.device_id == device_id)
        {
            ++rows.refresh;
            ++(token.revoked ? rows.retired_refresh : rows.unrevoked_refresh);
        }
    }
    return rows;
}

[[nodiscard]] auto session_count(hs::HomeserverRuntime const& runtime, std::string_view user_id,
                                 std::string_view device_id) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& session : runtime.database.sessions)
    {
        count += session.user_id == user_id && session.device_id == device_id ? 1U : 0U;
    }
    return count;
}

[[nodiscard]] auto sqlite_credential_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

// A login with a refresh token, as POST /login does: the access token, then the refresh token.
struct LoginTokens final
{
    std::string access;
    std::string refresh;
};

[[nodiscard]] auto login_with_refresh(hs::HomeserverRuntime& runtime, std::string const& user_id,
                                      std::string_view device_id) -> LoginTokens
{
    auto const login = hs::login_local_user(runtime, user_id, kPassword, device_id, true);
    REQUIRE(login.ok);
    auto const issued = hs::issue_refresh_token_for_session(runtime, user_id, device_id);
    REQUIRE(issued.ok);
    return {login.value, issued.value};
}

// Rotations stamp the wall clock in milliseconds and the oldest retired row goes first, so a test that checks
// which row went starts each rotation in a new millisecond.
auto next_millisecond() -> void
{
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
}

[[nodiscard]] auto make_runtime(merovingian::config::Config const& config) -> hs::RuntimeStartResult
{
    REQUIRE(sodium_init() >= 0);
    auto started = hs::start_runtime(config);
    REQUIRE(started.started);
    return started;
}

[[nodiscard]] auto register_alice(hs::HomeserverRuntime& runtime) -> std::string
{
    auto const registered =
        hs::register_local_user(runtime, "alice", kPassword, merovingian::tests::registration_token);
    REQUIRE(registered.ok);
    return registered.value;
}

struct RowCosts final
{
    std::uint64_t login{0U};
    std::uint64_t rotation{0U};
};

// The rows one login on a held device, and one rotation, examined: access and refresh tables and sessions together.
[[nodiscard]] auto measure_replacement_costs(std::size_t others) -> RowCosts
{
    auto started = make_runtime(credential_config());
    auto& runtime = started.runtime;
    auto& store = runtime.database.persistent_store;
    auto const alice = register_alice(runtime);
    auto const first = login_with_refresh(runtime, alice, "DEVICE1");
    pad_with_other_users(store, others);
    for (auto index = std::size_t{0U}; index < others; ++index)
    {
        runtime.database.sessions.push_back({"@other" + std::to_string(index % 50U) + ":example.org",
                                             "OTHER" + std::to_string(index), fake_hash("pad-a", index), false,
                                             std::nullopt});
    }
    auto const examined = [&runtime, &store] {
        return rows_examined(store) + runtime.database.sessions.rows_examined().value();
    };

    auto costs = RowCosts{};
    auto before = examined();
    auto const second = login_with_refresh(runtime, alice, "DEVICE1");
    costs.login = examined() - before;

    before = examined();
    REQUIRE(hs::refresh_local_session(runtime, second.refresh).ok);
    costs.rotation = examined() - before;
    REQUIRE(first.access != second.access);
    return costs;
}

} // namespace

SCENARIO("N logins and N refreshes on one device leave a bounded number of rows, also after a reload",
         "[f08-rows][credential][sqlite]")
{
    GIVEN("a SQLite-backed server with a user")
    {
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-f08-rows-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        std::filesystem::remove(path);
        auto started = make_runtime(sqlite_credential_config(path));
        auto& runtime = started.runtime;
        auto const alice = register_alice(runtime);

        WHEN("the user logs in 40 times on one device")
        {
            auto latest = LoginTokens{};
            for (auto round = 0; round < 40; ++round)
            {
                latest = login_with_refresh(runtime, alice, "DEVICE1");
            }
            auto const live = device_rows(runtime.database.persistent_store, alice, "DEVICE1");
            auto const live_sessions = session_count(runtime, alice, "DEVICE1");
            auto reopened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);
            auto const durable = device_rows(reopened.store, alice, "DEVICE1");

            THEN("one access row, one refresh row and one session remain, in memory and in the database")
            {
                REQUIRE(live.access == 1U);
                REQUIRE(live.refresh == 1U);
                REQUIRE(live.unrevoked_refresh == 1U);
                REQUIRE(live_sessions == 1U);
                REQUIRE(durable.access == 1U);
                REQUIRE(durable.refresh == 1U);
            }

            AND_WHEN("the device then refreshes 40 times")
            {
                auto refresh_token = latest.refresh;
                for (auto round = 0; round < 40; ++round)
                {
                    auto const rotated = hs::refresh_local_session(runtime, refresh_token);
                    REQUIRE(rotated.ok);
                    refresh_token = rotated.refresh_token;
                }
                auto const rotated_live = device_rows(runtime.database.persistent_store, alice, "DEVICE1");
                auto const rotated_sessions = session_count(runtime, alice, "DEVICE1");
                auto reloaded = db::open_sqlite_persistent_store(path.string());
                REQUIRE(reloaded.ok);
                auto const rotated_durable = device_rows(reloaded.store, alice, "DEVICE1");

                THEN("at most one access row, two unrevoked and exactly 32 retired refresh rows and one session remain")
                {
                    REQUIRE(rotated_live.access == 1U);
                    REQUIRE(rotated_live.unrevoked_refresh == 2U);
                    REQUIRE(rotated_live.retired_refresh == kRetiredCap);
                    REQUIRE(rotated_sessions == 1U);
                    REQUIRE(rotated_durable.access == 1U);
                    REQUIRE(rotated_durable.unrevoked_refresh == 2U);
                    REQUIRE(rotated_durable.retired_refresh == kRetiredCap);
                }
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A retired refresh row is evicted only when retired, including on a retry after a lost response",
         "[f08-rows][credential]")
{
    GIVEN("a device that holds exactly 32 retired refresh rows")
    {
        auto started = make_runtime(credential_config());
        auto& runtime = started.runtime;
        auto& store = runtime.database.persistent_store;
        auto const alice = register_alice(runtime);
        auto current = login_with_refresh(runtime, alice, "DEVICE1");
        for (auto round = 0; round < 40; ++round)
        {
            next_millisecond();
            auto const rotated = hs::refresh_local_session(runtime, current.refresh);
            REQUIRE(rotated.ok);
            current = {rotated.access_token, rotated.refresh_token};
        }
        REQUIRE(device_rows(store, alice, "DEVICE1").retired_refresh == kRetiredCap);

        WHEN("the device presents its token twice, as when the first response was lost")
        {
            next_millisecond();
            auto const lost = hs::refresh_local_session(runtime, current.refresh);
            REQUIRE(lost.ok);
            next_millisecond();
            auto const retry = hs::refresh_local_session(runtime, current.refresh);
            REQUIRE(retry.ok);

            THEN("no unrevoked row was evicted, the retired count is still 32 and the newest pair works")
            {
                auto const rows = device_rows(store, alice, "DEVICE1");
                REQUIRE(rows.retired_refresh == kRetiredCap);
                // The presented token and the retry's token are the unrevoked rows; the lost pair's was retired.
                REQUIRE(rows.unrevoked_refresh == 2U);
                REQUIRE(store.refresh_tokens.size() == kRetiredCap + 2U);
                REQUIRE(hs::authenticated_user(runtime, retry.access_token).has_value());
                REQUIRE(hs::refresh_local_session(runtime, retry.refresh_token).ok);
            }
        }

        WHEN("the table is asked which rows exceed the cap with no retired rows beyond it")
        {
            auto const none = store.refresh_tokens.oldest_retired_beyond(alice, "DEVICE1", kRetiredCap);
            auto const all = store.refresh_tokens.oldest_retired_beyond(alice, "DEVICE1", 0U);

            THEN("nothing is named at the cap, and with a cap of 0 every retired row and no unrevoked row is named")
            {
                REQUIRE(none.empty());
                REQUIRE(all.size() == kRetiredCap);
                for (auto const& hash : all)
                {
                    auto const* row = store.refresh_tokens.find(hash);
                    REQUIRE(row != nullptr);
                    REQUIRE(row->revoked);
                }
            }
        }
    }
}

SCENARIO("Replacing a device's credentials examines the same rows however many other users' rows exist",
         "[f08-rows][credential]")
{
    GIVEN("the rows one login on a held device and one rotation examined with 200 and with 400 other-user rows")
    {
        auto const small = measure_replacement_costs(200U);
        auto const large = measure_replacement_costs(400U);

        THEN("both operations examine rows, and the same number at both sizes")
        {
            REQUIRE(small.login > 0U);
            REQUIRE(small.login == large.login);
            REQUIRE(small.rotation > 0U);
            REQUIRE(small.rotation == large.rotation);
        }
    }
}

SCENARIO("A login whose commit fails leaves the device's earlier credentials working", "[f08-rows][credential]")
{
    GIVEN("a device logged in with a refresh token")
    {
        auto started = make_runtime(credential_config());
        auto& runtime = started.runtime;
        auto& store = runtime.database.persistent_store;
        auto const alice = register_alice(runtime);
        auto const first = login_with_refresh(runtime, alice, "DEVICE1");
        auto const before = device_rows(store, alice, "DEVICE1");

        WHEN("the login's transaction fails")
        {
            db::force_persist_failure_for_statement(store, "delete_device_access_tokens");
            auto const failed = hs::login_local_user(runtime, alice, kPassword, "DEVICE1", true);

            THEN("the login is a 500 with no token, nothing changed and the earlier tokens work")
            {
                REQUIRE_FALSE(failed.ok);
                REQUIRE(failed.status == 500U);
                REQUIRE(failed.value.empty());
                auto const after = device_rows(store, alice, "DEVICE1");
                REQUIRE(after.access == before.access);
                REQUIRE(after.refresh == before.refresh);
                REQUIRE(session_count(runtime, alice, "DEVICE1") == 1U);
                REQUIRE(hs::authenticated_user(runtime, first.access).has_value());
                REQUIRE(hs::refresh_local_session(runtime, first.refresh).ok);
            }
        }

        WHEN("a rotation's transaction fails")
        {
            db::force_persist_failure_for_statement(store, "delete_device_access_tokens");
            auto const failed = hs::refresh_local_session(runtime, first.refresh);

            THEN("it is a 500, the access token still works and the same refresh token rotates on retry")
            {
                REQUIRE_FALSE(failed.ok);
                REQUIRE(failed.status == 500U);
                REQUIRE(hs::authenticated_user(runtime, first.access).has_value());
                REQUIRE(hs::refresh_local_session(runtime, first.refresh).ok);
            }
        }
    }
}
