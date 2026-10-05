// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/joining_threads.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <semaphore>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

#include <sodium.h>

namespace
{

class TemporarySqliteDatabase final
{
public:
    TemporarySqliteDatabase()
    {
        auto const ticks = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = merovingian::tests::temporary_directory() /
                ("merovingian-security-audit-login-snapshot-" + std::to_string(ticks) + ".sqlite3");
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

[[nodiscard]] auto sqlite_auth_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();

    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);

    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            std::move(database),
            std::move(security),
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}

} // namespace

SCENARIO("a login cannot use a password invalidated during Argon2id verification",
         "[integration][sqlite][security_audit_login_snapshot]")
{
    GIVEN("Alice's old password and a precomputed replacement hash")
    {
        REQUIRE(sodium_init() >= 0);
        auto database = TemporarySqliteDatabase{};
        auto started = merovingian::homeserver::start_runtime(sqlite_auth_config(database.path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const old_password = std::string{"AliceOldPassword99!"};
        auto const new_password = std::string{"AliceNewPassword99!"};
        auto const replacement_hash = merovingian::auth::hash_password(new_password);
        REQUIRE(replacement_hash.has_value());

        auto const registration = merovingian::homeserver::register_local_user(runtime, "alice", old_password,
                                                                               merovingian::tests::registration_token);
        REQUIRE(registration.ok);
        auto const alice_user_id = std::string{registration.value};
        auto const initial_sessions = runtime.database.sessions.size();
        REQUIRE(initial_sessions == 0U);

        auto login_started = std::binary_semaphore{0};
        auto login_done = std::atomic<bool>{false};
        auto raced_login = merovingian::homeserver::OperationResult{};
        auto login_thread = merovingian::tests::JoiningThreads{};
        login_thread.emplace_back([&] {
            auto guard = std::unique_lock<merovingian::homeserver::RuntimeMutex>{runtime.mutex};
            auto const request_lock = merovingian::homeserver::RequestLockScope{guard};
            login_started.release();
            raced_login = merovingian::homeserver::login_local_user(runtime, alice_user_id, old_password,
                                                                    "ALICE_DURING_PASSWORD_CHANGE");
            login_done.store(true, std::memory_order_release);
        });

        login_started.acquire();
        {
            // This acquisition blocks until the login releases runtime.mutex
            // around the real Argon2id verification. Winning it before the
            // login re-acquires proves that the password change overlaps that
            // verification rather than merely following it.
            auto guard = std::unique_lock<merovingian::homeserver::RuntimeMutex>{runtime.mutex};
            REQUIRE_FALSE(login_done.load(std::memory_order_acquire));

            auto const previous_capacity = runtime.database.users.capacity();
            runtime.database.users.reserve(previous_capacity + 1U);
            auto user = std::ranges::find_if(runtime.database.users, [&alice_user_id](auto const& entry) {
                return entry.user_id == alice_user_id;
            });
            REQUIRE(user != runtime.database.users.end());

            REQUIRE(merovingian::database::update_user_password(runtime.database.persistent_store, alice_user_id,
                                                                *replacement_hash));
            user->password_hash = *replacement_hash;
        }

        login_thread.join();

        WHEN("the overlapping password change has persisted before login resumes")
        {
            THEN("the old password cannot issue a session and the replacement password works")
            {
                REQUIRE_FALSE(raced_login.ok);
                REQUIRE(raced_login.status == 403U);
                REQUIRE(raced_login.value.empty());
                REQUIRE(runtime.database.sessions.size() == initial_sessions);

                auto const fresh_login = merovingian::homeserver::login_local_user(runtime, alice_user_id, new_password,
                                                                                   "ALICE_AFTER_PASSWORD_CHANGE");
                REQUIRE(fresh_login.ok);
                REQUIRE(fresh_login.status == 200U);
                REQUIRE(merovingian::homeserver::authenticated_user(runtime, fresh_login.value) == alice_user_id);
                REQUIRE(runtime.database.sessions.size() == initial_sessions + 1U);
            }
        }
    }
}
