// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// AUTH-4 (security-audit-report-2026-09-29.md), residual: the Argon2id work of
// ordinary registration, password change and the user-interactive-auth password
// check runs with `runtime.mutex` released, and whatever the hash's use depends
// on is re-validated once the lock is re-taken.
//
// Every scenario holds the runtime mutex on a worker thread the way a request
// handler does (RequestLockScope), starts the operation, and then takes the
// mutex on the main thread. The main thread can only win it if the operation
// released it around the hash; and because the worker needs the mutex back to
// finish, the operation cannot have finished when the main thread holds it. No
// scenario asserts from a worker thread: results are read after join.

#include "../support/JoiningThreads.hpp"
#include "../support/RealPasswordHashCost.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/auth/Argon2idAdmission.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/PasswordVerificationResult.hpp"
#include "merovingian/homeserver/RequestLockScope.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <semaphore>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace
{

namespace hs = merovingian::homeserver;

[[nodiscard]] auto token_registration_config() -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "example.org";
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto count_users(hs::HomeserverRuntime const& runtime, std::string_view user_id) -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(runtime.database.users, [user_id](auto const& user) {
        return user.user_id == user_id;
    }));
}

[[nodiscard]] auto stored_hash_of(hs::HomeserverRuntime const& runtime, std::string_view user_id) -> std::string
{
    auto const it = std::ranges::find_if(runtime.database.users, [user_id](auto const& user) {
        return user.user_id == user_id;
    });
    return it == runtime.database.users.end() ? std::string{} : it->password_hash;
}

// Replaces a user's stored hash the way a concurrent password change would:
// durable row and in-memory row, under the runtime mutex. The vector is grown
// first so that any user pointer the operation under test wrongly kept across
// its released region would dangle.
auto replace_stored_hash(hs::HomeserverRuntime& runtime, std::string const& user_id, std::string const& new_hash)
    -> bool
{
    runtime.database.users.reserve(runtime.database.users.capacity() + 1U);
    auto const it = std::ranges::find_if(runtime.database.users, [&user_id](auto const& user) {
        return user.user_id == user_id;
    });
    if (it == runtime.database.users.end())
    {
        return false;
    }
    if (!merovingian::database::update_user_password(runtime.database.persistent_store, user_id, new_hash))
    {
        return false;
    }
    it->password_hash = new_hash;
    return true;
}

} // namespace

// Registration with a token verifies the token (Argon2id, lock released) before
// make_user hashes the password, so it cannot tell the two apart; appservice
// registration reaches the same make_user without a token step.
SCENARIO("Registration does not hold the runtime mutex while it hashes the password",
         "[integration][auth][security][audit][auth-4]")
{
    // Another request has to land inside the window the lock is released for, so the hash takes its real time.
    auto const real_hash_cost = merovingian::tests::RealPasswordHashCost{};
    GIVEN("a runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto request_started = std::binary_semaphore{0};
        auto registration_done = std::atomic<bool>{false};
        auto registration = hs::OperationResult{};
        auto worker = merovingian::tests::JoiningThreads{};
        worker.emplace_back([&] {
            auto guard = hs::RuntimeLock{runtime.mutex};
            auto const request_lock = hs::RequestLockScope{guard};
            request_started.release();
            registration = hs::register_appservice_user(runtime, "bridge_carol");
            registration_done.store(true, std::memory_order_release);
        });

        WHEN("another request needs the runtime mutex while the registration is hashing")
        {
            request_started.acquire();
            auto overlapped = false;
            {
                auto guard = hs::RuntimeLock{runtime.mutex};
                overlapped = !registration_done.load(std::memory_order_acquire);
            }
            worker.join();

            THEN("it gets the mutex before the hash has finished, and the registration then completes")
            {
                REQUIRE(overlapped);
                REQUIRE(registration.ok);
                REQUIRE(count_users(runtime, "@bridge_carol:example.org") == 1U);
            }
        }
    }
}

SCENARIO("Two concurrent registrations of one username produce exactly one account",
         "[integration][auth][security][audit][auth-4]")
{
    // Another request has to land inside the window the lock is released for, so the hash takes its real time.
    auto const real_hash_cost = merovingian::tests::RealPasswordHashCost{};
    GIVEN("a runtime and two clients registering the same username with different passwords")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const first_password = std::string{"FirstPassword99!x"};
        auto const second_password = std::string{"SecondPassword99!y"};
        auto results = std::array<hs::OperationResult, 2U>{};
        auto ready = std::atomic<int>{0};
        auto go = std::atomic<bool>{false};

        auto worker = merovingian::tests::JoiningThreads{};
        for (auto index = std::size_t{0U}; index < results.size(); ++index)
        {
            worker.emplace_back([&, index] {
                ready.fetch_add(1, std::memory_order_acq_rel);
                while (!go.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                auto guard = hs::RuntimeLock{runtime.mutex};
                auto const request_lock = hs::RequestLockScope{guard};
                results.at(index) =
                    hs::register_local_user(runtime, "dave", index == 0U ? first_password : second_password,
                                            std::string{merovingian::tests::registration_token});
            });
        }

        WHEN("both run")
        {
            while (ready.load(std::memory_order_acquire) < 2)
            {
                std::this_thread::yield();
            }
            go.store(true, std::memory_order_release);
            worker.join();

            THEN("exactly one succeeds, the other is told the username is taken, and one account exists")
            {
                auto const succeeded = static_cast<int>(results.at(0U).ok) + static_cast<int>(results.at(1U).ok);
                REQUIRE(succeeded == 1);
                auto const& loser = results.at(0U).ok ? results.at(1U) : results.at(0U);
                REQUIRE(loser.reason == "user already exists");
                REQUIRE(count_users(runtime, "@dave:example.org") == 1U);
            }

            THEN("the surviving account carries the winner's password, not the loser's")
            {
                auto const& winner_password = results.at(0U).ok ? first_password : second_password;
                auto const& loser_password = results.at(0U).ok ? second_password : first_password;
                REQUIRE(hs::login_local_user(runtime, "@dave:example.org", winner_password, "DEV1").ok);
                REQUIRE_FALSE(hs::login_local_user(runtime, "@dave:example.org", loser_password, "DEV2").ok);
            }
        }
    }
}

SCENARIO("A password change that races another password change is refused, not overwritten",
         "[integration][auth][security][audit][auth-4]")
{
    // Another request has to land inside the window the lock is released for, so the hash takes its real time.
    auto const real_hash_cost = merovingian::tests::RealPasswordHashCost{};
    GIVEN("alice is signed in and a replacement hash is prepared for the competing change")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_password = std::string{"AlicePass99!x"};
        auto const competing_password = std::string{"CompetingPass99!y"};
        auto const competing_hash = merovingian::auth::hash_password(competing_password);
        REQUIRE(competing_hash.has_value());
        auto const registered = hs::register_local_user(runtime, "alice", alice_password,
                                                        std::string{merovingian::tests::registration_token});
        REQUIRE(registered.ok);
        auto const signed_in = hs::login_local_user(runtime, registered.value, alice_password, "DEV1");
        REQUIRE(signed_in.ok);

        auto request_started = std::binary_semaphore{0};
        auto change_done = std::atomic<bool>{false};
        auto change = hs::OperationResult{};
        auto worker = merovingian::tests::JoiningThreads{};
        worker.emplace_back([&] {
            auto guard = hs::RuntimeLock{runtime.mutex};
            auto const request_lock = hs::RequestLockScope{guard};
            request_started.release();
            change = hs::change_local_user_password(runtime, signed_in.value, "LaterChange99!z");
            change_done.store(true, std::memory_order_release);
        });

        WHEN("the competing change lands while the later one is hashing")
        {
            request_started.acquire();
            auto overlapped = false;
            auto replaced = false;
            {
                auto guard = hs::RuntimeLock{runtime.mutex};
                overlapped = !change_done.load(std::memory_order_acquire);
                replaced = replace_stored_hash(runtime, registered.value, *competing_hash);
            }
            worker.join();

            THEN("the later change is refused and the competing password survives")
            {
                REQUIRE(overlapped);
                REQUIRE(replaced);
                REQUIRE_FALSE(change.ok);
                REQUIRE(stored_hash_of(runtime, registered.value) == *competing_hash);
                REQUIRE(hs::login_local_user(runtime, registered.value, competing_password, "DEV2").ok);
            }
        }
    }
}

SCENARIO("A password change races a logout of the session that authorised it",
         "[integration][auth][security][audit][auth-4]")
{
    // Another request has to land inside the window the lock is released for, so the hash takes its real time.
    auto const real_hash_cost = merovingian::tests::RealPasswordHashCost{};
    GIVEN("alice is signed in on one device")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_password = std::string{"AlicePass99!x"};
        auto const registered = hs::register_local_user(runtime, "alice", alice_password,
                                                        std::string{merovingian::tests::registration_token});
        REQUIRE(registered.ok);
        auto const signed_in = hs::login_local_user(runtime, registered.value, alice_password, "DEV1");
        REQUIRE(signed_in.ok);
        auto const hash_before = stored_hash_of(runtime, registered.value);

        auto request_started = std::binary_semaphore{0};
        auto change = hs::OperationResult{};
        auto worker = merovingian::tests::JoiningThreads{};
        worker.emplace_back([&] {
            auto guard = hs::RuntimeLock{runtime.mutex};
            auto const request_lock = hs::RequestLockScope{guard};
            request_started.release();
            change = hs::change_local_user_password(runtime, signed_in.value, "LaterChange99!z");
        });

        WHEN("the device is deleted while the new password is hashing")
        {
            request_started.acquire();
            auto deleted = false;
            {
                auto guard = hs::RuntimeLock{runtime.mutex};
                deleted = hs::delete_local_device(runtime, registered.value, "DEV1").ok;
            }
            worker.join();

            THEN("the revoked session cannot change the password")
            {
                REQUIRE(deleted);
                REQUIRE_FALSE(change.ok);
                REQUIRE(stored_hash_of(runtime, registered.value) == hash_before);
            }
        }
    }
}

SCENARIO("A user-interactive-auth password check is refused when the password changed during verification",
         "[integration][auth][security][audit][auth-4]")
{
    // Another request has to land inside the window the lock is released for, so the hash takes its real time.
    auto const real_hash_cost = merovingian::tests::RealPasswordHashCost{};
    GIVEN("alice is signed in, and a replacement hash is prepared for a competing password change")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_password = std::string{"AlicePass99!x"};
        auto const competing_hash = merovingian::auth::hash_password("CompetingPass99!y");
        REQUIRE(competing_hash.has_value());
        auto const registered = hs::register_local_user(runtime, "alice", alice_password,
                                                        std::string{merovingian::tests::registration_token});
        REQUIRE(registered.ok);
        auto const signed_in = hs::login_local_user(runtime, registered.value, alice_password, "DEV1");
        REQUIRE(signed_in.ok);

        auto request_started = std::binary_semaphore{0};
        auto check_done = std::atomic<bool>{false};
        auto check = hs::PasswordVerificationResult{};
        auto worker = merovingian::tests::JoiningThreads{};
        worker.emplace_back([&] {
            auto guard = hs::RuntimeLock{runtime.mutex};
            auto const request_lock = hs::RequestLockScope{guard};
            request_started.release();
            check = hs::verify_local_user_password(runtime, signed_in.value, alice_password);
            check_done.store(true, std::memory_order_release);
        });

        WHEN("the password changes while the old one is being verified")
        {
            request_started.acquire();
            auto overlapped = false;
            auto replaced = false;
            {
                auto guard = hs::RuntimeLock{runtime.mutex};
                overlapped = !check_done.load(std::memory_order_acquire);
                replaced = replace_stored_hash(runtime, registered.value, *competing_hash);
            }
            worker.join();

            THEN("the check overlapped the verification and the old password is not accepted")
            {
                REQUIRE(overlapped);
                REQUIRE(replaced);
                REQUIRE_FALSE(check.ok);
            }

            THEN("the stale check is not counted as a wrong guess")
            {
                REQUIRE(runtime.uia_failures_by_device.size() == 0U);
            }
        }
    }
}

namespace
{

constexpr auto alice_password = "AlicePass99!x";

auto exhaust_argon2id_admission(merovingian::homeserver::HomeserverRuntime& runtime) -> void
{
    runtime.argon2id_admission = std::make_unique<merovingian::auth::Argon2idAdmission>(0U);
}

auto restore_argon2id_admission(merovingian::homeserver::HomeserverRuntime& runtime) -> void
{
    runtime.argon2id_admission =
        std::make_unique<merovingian::auth::Argon2idAdmission>(merovingian::auth::default_argon2id_capacity());
}

[[nodiscard]] auto user_count(merovingian::homeserver::HomeserverRuntime const& runtime) -> std::size_t
{
    return runtime.database.users.size();
}
} // namespace

SCENARIO("Password hashing in make_user shares the Argon2id admission budget",
         "[homeserver][auth][security][audit][auth-4]")
{
    GIVEN("a runtime with no Argon2id capacity")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const users_before = user_count(runtime);
        exhaust_argon2id_admission(runtime);

        WHEN("the bootstrap admin is created")
        {
            auto const result = merovingian::homeserver::bootstrap_admin_user(runtime, "root", "RootPass99!x");

            THEN("it is refused with 429 and a retry delay, and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 429U);
                REQUIRE(result.retry_after_ms > 0U);
                REQUIRE(user_count(runtime) == users_before);
            }
        }

        WHEN("an appservice registers a user")
        {
            auto const result = merovingian::homeserver::register_appservice_user(runtime, "bridge_alice");

            THEN("it is refused with 429 and a retry delay, and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 429U);
                REQUIRE(result.retry_after_ms > 0U);
                REQUIRE(user_count(runtime) == users_before);
            }
        }
    }
}

SCENARIO("Password change sheds load when the Argon2id admission budget is spent",
         "[homeserver][auth][security][audit][auth-4]")
{
    GIVEN("alice is signed in and no Argon2id capacity remains")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = merovingian::homeserver::register_local_user(
            runtime, "alice", alice_password, std::string{merovingian::tests::registration_token});
        REQUIRE(registered.ok);
        auto const signed_in =
            merovingian::homeserver::login_local_user(runtime, registered.value, alice_password, "DEV1");
        REQUIRE(signed_in.ok);
        auto const hash_before = stored_hash_of(runtime, registered.value);
        REQUIRE_FALSE(hash_before.empty());
        exhaust_argon2id_admission(runtime);

        WHEN("she changes her password")
        {
            auto const result =
                merovingian::homeserver::change_local_user_password(runtime, signed_in.value, "NewAlicePass99!y");

            THEN("it is refused with 429 and a retry delay, and her password is unchanged")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 429U);
                REQUIRE(result.retry_after_ms > 0U);
                REQUIRE(stored_hash_of(runtime, registered.value) == hash_before);
            }
        }
    }
}

SCENARIO("A user-interactive-auth password check sheds load without counting as a failure",
         "[homeserver][auth][security][audit][auth-4]")
{
    GIVEN("alice is signed in and no Argon2id capacity remains")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = merovingian::homeserver::register_local_user(
            runtime, "alice", alice_password, std::string{merovingian::tests::registration_token});
        REQUIRE(registered.ok);
        auto const signed_in =
            merovingian::homeserver::login_local_user(runtime, registered.value, alice_password, "DEV1");
        REQUIRE(signed_in.ok);
        exhaust_argon2id_admission(runtime);

        WHEN("the password stage is attempted with the correct password")
        {
            auto const result =
                merovingian::homeserver::verify_local_user_password(runtime, signed_in.value, alice_password);

            THEN("it is not verified and carries a retry delay")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.retry_after_ms > 0U);
            }

            THEN("no failed UIA attempt is recorded")
            {
                REQUIRE(runtime.uia_failures_by_device.size() == 0U);
            }

            AND_WHEN("the budget is available again")
            {
                restore_argon2id_admission(runtime);
                auto const retried =
                    merovingian::homeserver::verify_local_user_password(runtime, signed_in.value, alice_password);

                THEN("the same password is accepted: shedding spent none of the account's guessing budget")
                {
                    REQUIRE(retried.ok);
                }
            }
        }
    }
}
