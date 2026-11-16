// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Account creation without a session (ADR-0783): `create_local_account` makes the username checks and every
// registration gate POST /register makes, gives the caller's client key to the registration policy, and leaves no
// device, token or session behind.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/auth/Argon2idAdmission.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AccountCreationRequest.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace
{

namespace hs = merovingian::homeserver;

constexpr auto good_password = std::string_view{"CarolPass99!x"};
constexpr auto page_client_key = std::string_view{"198.51.100.7"};

[[nodiscard]] auto registration_config(bool enabled) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "example.org";
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.registration.enabled = enabled;
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto create(hs::HomeserverRuntime& runtime, std::string_view localpart,
                          std::string_view password = good_password,
                          std::string_view token = merovingian::tests::registration_token,
                          std::string_view client_key = page_client_key) -> hs::OperationResult
{
    return hs::create_local_account(runtime, hs::AccountCreationRequest{localpart, password, token, client_key});
}

[[nodiscard]] auto user_count(hs::HomeserverRuntime const& runtime) -> std::size_t
{
    return runtime.database.users.size();
}

[[nodiscard]] auto session_count(hs::HomeserverRuntime const& runtime) -> std::size_t
{
    return runtime.database.sessions.size();
}

} // namespace

SCENARIO("Account creation without a session makes POST /register's username checks",
         "[integration][auth][oauth][oauth-account]")
{
    GIVEN("a runtime with token registration")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(registration_config(true));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const users_before = user_count(runtime);

        WHEN("the localpart is not valid")
        {
            auto const result = create(runtime, "Carol Upper");

            THEN("it is 400 M_INVALID_USERNAME with POST /register's reason, and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 400U);
                REQUIRE(result.errcode == "M_INVALID_USERNAME");
                REQUIRE(result.reason == "desired username is not valid");
                REQUIRE(user_count(runtime) == users_before);
            }
        }

        WHEN("the localpart is one the server keeps for itself")
        {
            auto const result = create(runtime, "remote-media");

            THEN("it is 400 M_USER_IN_USE as for a taken name, and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 400U);
                REQUIRE(result.errcode == "M_USER_IN_USE");
                REQUIRE(result.reason == "desired username is already taken");
                REQUIRE(user_count(runtime) == users_before);
            }
        }

        WHEN("the localpart is already an account")
        {
            REQUIRE(create(runtime, "carol").ok);
            auto const result = create(runtime, "carol", "OtherPass99!y");

            THEN("it is refused as an existing user and the first account is unchanged")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason == "user already exists");
                REQUIRE(user_count(runtime) == users_before + 1U);
                REQUIRE(hs::verify_password_login(runtime, {"@carol:example.org", good_password, page_client_key, "D"})
                            .outcome == hs::PasswordLoginVerification::Outcome::verified);
            }
        }
    }
}

SCENARIO("Account creation without a session applies every registration gate",
         "[integration][auth][oauth][oauth-account]")
{
    GIVEN("a runtime with token registration")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(registration_config(true));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const users_before = user_count(runtime);

        WHEN("no registration token is given")
        {
            auto const result = create(runtime, "carol", good_password, {});

            THEN("it is 403 and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 403U);
                REQUIRE(user_count(runtime) == users_before);
            }
        }

        WHEN("a wrong registration token is given")
        {
            auto const result = create(runtime, "carol", good_password, "not-the-token");

            THEN("it is 403 registration token rejected and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 403U);
                REQUIRE(result.reason == "registration token rejected");
                REQUIRE(user_count(runtime) == users_before);
            }
        }

        WHEN("the password is too weak")
        {
            auto const result = create(runtime, "carol", "a");

            THEN("it is M_WEAK_PASSWORD and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.errcode == "M_WEAK_PASSWORD");
                REQUIRE(user_count(runtime) == users_before);
            }
        }

        WHEN("no Argon2id admission slot is free")
        {
            runtime.argon2id_admission = std::make_unique<merovingian::auth::Argon2idAdmission>(0U);
            auto const result = create(runtime, "carol");

            THEN("it is 429 with a retry delay and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 429U);
                REQUIRE(result.retry_after_ms > 0U);
                REQUIRE(user_count(runtime) == users_before);
            }
        }

        WHEN("the client key is empty")
        {
            auto const result = create(runtime, "carol", good_password, merovingian::tests::registration_token, {});

            THEN("the registration policy, which is given the key, refuses it with 403 and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 403U);
                REQUIRE(user_count(runtime) == users_before);
            }
        }
    }

    GIVEN("a runtime with registration turned off")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(registration_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const users_before = user_count(runtime);

        WHEN("an account is asked for with the right token")
        {
            auto const result = create(runtime, "carol");

            THEN("it is refused as registration disabled and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason == "registration_disabled");
                REQUIRE(user_count(runtime) == users_before);
            }
        }
    }
}

SCENARIO("Account creation without a session leaves no device, token or session, and spends no registration token",
         "[integration][auth][oauth][oauth-account]")
{
    GIVEN("a runtime with token registration")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(registration_config(true));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const sessions_before = session_count(runtime);

        WHEN("a refused attempt, then two accounts, use the same registration token")
        {
            auto const refused = create(runtime, "carol", "a");
            auto const carol = create(runtime, "carol");
            auto const dave = create(runtime, "dave");

            THEN("both accounts are created: the token file's token is not counted, so no attempt spends it")
            {
                REQUIRE_FALSE(refused.ok);
                REQUIRE(carol.ok);
                REQUIRE(carol.value == "@carol:example.org");
                REQUIRE(dave.ok);
            }

            THEN("neither account holds a session or a device")
            {
                REQUIRE(session_count(runtime) == sessions_before);
                for (auto const& session : runtime.database.sessions)
                {
                    REQUIRE(session.user_id != "@carol:example.org");
                    REQUIRE(session.user_id != "@dave:example.org");
                }
                auto devices = std::size_t{0U};
                merovingian::database::for_each_user_device(runtime.database.persistent_store, "@carol:example.org",
                                                            [&devices](auto const&) {
                                                                ++devices;
                                                                return true;
                                                            });
                REQUIRE(devices == 0U);
            }
        }
    }
}
