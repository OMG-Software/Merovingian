// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <cstdint>
#include <string>
#include <utility>

namespace
{

[[nodiscard]] auto memory_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::tests::in_memory_database_config(),
            std::move(security),
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}

} // namespace

SCENARIO("A registration commits the account, its profile and its audit row in two transactions, not three",
         "[integration][commits][p13]")
{
    GIVEN("a running server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(memory_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& store = runtime.database.persistent_store;

        WHEN("a user registers")
        {
            auto const before = store.committed_transactions;
            auto const registration = merovingian::homeserver::register_local_user(
                runtime, "carol", "CorrectHorse7!Battery", merovingian::tests::registration_token);
            auto const commits = store.committed_transactions - before;

            THEN("the account and an empty profile exist, written in a single transaction beside the audit row")
            {
                REQUIRE(registration.ok);
                REQUIRE(merovingian::database::find_profile(store, registration.value).has_value());
                REQUIRE(commits == 2U);
            }
        }

        WHEN("the profile write fails during registration")
        {
            store.force_failure_statement_names.insert("upsert_profile");
            auto const registration = merovingian::homeserver::register_local_user(
                runtime, "dave", "CorrectHorse7!Battery", merovingian::tests::registration_token);

            THEN("the registration is refused and no account is left without its profile")
            {
                REQUIRE_FALSE(registration.ok);
                REQUIRE(registration.status == 500U);
                REQUIRE(store.users.empty());
                REQUIRE(runtime.database.users.empty());
            }
        }
    }
}

SCENARIO("A logout revokes every credential of the device in one transaction", "[integration][commits][p13]")
{
    GIVEN("a user logged in on two devices, with a refresh token on the first")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(memory_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& store = runtime.database.persistent_store;
        auto const registration = merovingian::homeserver::register_local_user(runtime, "erin", "CorrectHorse7!Battery",
                                                                               merovingian::tests::registration_token);
        REQUIRE(registration.ok);
        auto const user_id = std::string{registration.value};
        auto const first = merovingian::homeserver::login_local_user(runtime, user_id, "CorrectHorse7!Battery", "ONE");
        auto const second = merovingian::homeserver::login_local_user(runtime, user_id, "CorrectHorse7!Battery", "TWO");
        REQUIRE(first.ok);
        REQUIRE(second.ok);
        REQUIRE(merovingian::database::store_refresh_token(
            store, {user_id, "ONE", "token-hash:v4:refresh-one", false, std::nullopt}));

        WHEN("the first device logs out")
        {
            auto const before = store.committed_transactions;
            auto const result = merovingian::homeserver::logout_local_user(runtime, first.value);
            auto const commits = store.committed_transactions - before;

            THEN("its access and refresh tokens are all revoked, the other device is untouched, and the credentials "
                 "cost one transaction")
            {
                REQUIRE(result.ok);
                REQUIRE_FALSE(merovingian::homeserver::authenticated_user(runtime, first.value).has_value());
                REQUIRE(merovingian::homeserver::authenticated_user(runtime, second.value) == user_id);
                for (auto const& token : store.refresh_tokens)
                {
                    REQUIRE(token.revoked == (token.device_id == "ONE"));
                }
                // Credentials, the device and its keys, and the audit row: three, where it used to be five.
                REQUIRE(commits == 3U);
            }
        }

        WHEN("the credential write fails during a logout")
        {
            store.force_failure_statement_names.insert("revoke_device_refresh_tokens");
            auto const result = merovingian::homeserver::logout_local_user(runtime, first.value);

            THEN("the logout fails, the session is not marked revoked and a retry can still succeed")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(merovingian::homeserver::authenticated_user(runtime, first.value) == user_id);
                auto const retry = merovingian::homeserver::logout_local_user(runtime, first.value);
                REQUIRE(retry.ok);
                REQUIRE_FALSE(merovingian::homeserver::authenticated_user(runtime, first.value).has_value());
            }
        }
    }
}
