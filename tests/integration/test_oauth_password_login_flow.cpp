// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// The password check of POST /login, shared with the OAuth 2.0 login page (ADR-0783): `verify_password_login` applies
// the failed-login throttle, the Argon2id admission budget, the dummy hash for an unknown user and the account-state
// gates, and creates no device and no token.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/auth/Argon2idAdmission.hpp"
#include "merovingian/auth/Password.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/PasswordLoginRequest.hpp"
#include "merovingian/homeserver/PasswordLoginVerification.hpp"
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
using Outcome = hs::PasswordLoginVerification::Outcome;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};
constexpr auto page_source = std::string_view{"198.51.100.7"};
constexpr auto max_throttle_attempts = 64;

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

[[nodiscard]] auto verify(hs::HomeserverRuntime& runtime, std::string_view user_id, std::string_view password)
    -> hs::PasswordLoginVerification
{
    return hs::verify_password_login(runtime, hs::PasswordLoginRequest{user_id, password, page_source, "PAGEDEV"});
}

[[nodiscard]] auto user_of(hs::HomeserverRuntime& runtime, std::string_view user_id) -> hs::LocalUser*
{
    auto const it = std::ranges::find_if(runtime.database.users, [user_id](auto const& user) {
        return user.user_id == user_id;
    });
    return it == runtime.database.users.end() ? nullptr : &*it;
}

// Whether the device the check named exists: the check must never create it.
[[nodiscard]] auto holds_page_device(hs::HomeserverRuntime const& runtime, std::string_view user_id) -> bool
{
    return merovingian::database::has_user_device(runtime.database.persistent_store, user_id, "PAGEDEV");
}

[[nodiscard]] auto session_count_of(hs::HomeserverRuntime const& runtime, std::string_view user_id) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& session : runtime.database.sessions)
    {
        if (session.user_id == user_id)
        {
            ++count;
        }
    }
    return count;
}

} // namespace

SCENARIO("The shared password check verifies a login without creating a device or a token",
         "[integration][auth][oauth][oauth-login]")
{
    GIVEN("alice has an account")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = hs::register_local_user(runtime, "alice", alice_password,
                                                        std::string{merovingian::tests::registration_token});
        REQUIRE(registered.ok);
        auto const alice = registered.value;

        WHEN("her password is checked, written as the full user ID and as the bare localpart")
        {
            auto const full = verify(runtime, alice, alice_password);
            auto const bare = verify(runtime, hs::login_identifier_user_id("example.org", "alice"), alice_password);

            THEN("both are verified as alice, and she holds no device and no session")
            {
                REQUIRE(full.outcome == Outcome::verified);
                REQUIRE(full.user_id == alice);
                REQUIRE(bare.outcome == Outcome::verified);
                REQUIRE(bare.user_id == alice);
                REQUIRE_FALSE(holds_page_device(runtime, alice));
                REQUIRE(session_count_of(runtime, alice) == 0U);
            }
        }

        WHEN("a wrong password is checked")
        {
            auto const result = verify(runtime, alice, "WrongPass99!x");

            THEN("it is an invalid login with no user and no retry delay")
            {
                REQUIRE(result.outcome == Outcome::invalid_login);
                REQUIRE(result.user_id.empty());
                REQUIRE(result.retry_after_ms == 0U);
            }
        }

        WHEN("an identifier that already names a full user ID is normalised")
        {
            THEN("it is kept as typed, and a localpart is placed on this server")
            {
                REQUIRE(hs::login_identifier_user_id("example.org", "@bob:other.example") == "@bob:other.example");
                REQUIRE(hs::login_identifier_user_id("example.org", "bob") == "@bob:example.org");
            }
        }
    }
}

SCENARIO("The shared password check applies the failed-login throttle before the password",
         "[integration][auth][oauth][oauth-login]")
{
    GIVEN("alice has an account")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = hs::register_local_user(runtime, "alice", alice_password,
                                                        std::string{merovingian::tests::registration_token});
        REQUIRE(registered.ok);
        auto const alice = registered.value;

        WHEN("wrong passwords are tried from one source until the throttle answers")
        {
            auto throttled = hs::PasswordLoginVerification{};
            auto attempts = 0;
            for (; attempts < max_throttle_attempts; ++attempts)
            {
                throttled = verify(runtime, alice, "WrongPass99!x");
                if (throttled.outcome != Outcome::invalid_login)
                {
                    break;
                }
            }

            THEN("it is throttled with a retry delay, and the right password is throttled too")
            {
                REQUIRE(attempts < max_throttle_attempts);
                REQUIRE(throttled.outcome == Outcome::throttled);
                REQUIRE(throttled.retry_after_ms > 0U);
                auto const right = verify(runtime, alice, alice_password);
                REQUIRE(right.outcome == Outcome::throttled);
                REQUIRE(right.user_id.empty());
            }

            THEN("POST /login's path shares the same throttle and answers 429")
            {
                auto const legacy = hs::login_local_user(runtime, alice, alice_password, "DEV1", false, page_source);
                REQUIRE_FALSE(legacy.ok);
                REQUIRE(legacy.status == 429U);
                REQUIRE(legacy.reason == "too many failed login attempts");
                REQUIRE(legacy.retry_after_ms > 0U);
            }
        }
    }
}

SCENARIO("The shared password check sheds load at the Argon2id admission budget without counting a failure",
         "[integration][auth][oauth][oauth-login]")
{
    GIVEN("alice has an account and no Argon2id capacity remains")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = hs::register_local_user(runtime, "alice", alice_password,
                                                        std::string{merovingian::tests::registration_token});
        REQUIRE(registered.ok);
        auto const alice = registered.value;
        runtime.argon2id_admission = std::make_unique<merovingian::auth::Argon2idAdmission>(0U);

        WHEN("her password, and an unknown user's, are checked")
        {
            auto const known = verify(runtime, alice, alice_password);
            auto const unknown = verify(runtime, "@nobody:example.org", "WhateverPass99!x");

            THEN("both are busy with a retry delay: an unknown user reaches the hash as a known one does")
            {
                REQUIRE(known.outcome == Outcome::busy);
                REQUIRE(known.retry_after_ms > 0U);
                REQUIRE(unknown.outcome == Outcome::busy);
                REQUIRE(unknown.retry_after_ms == known.retry_after_ms);
            }

            AND_WHEN("the budget is available again")
            {
                runtime.argon2id_admission = std::make_unique<merovingian::auth::Argon2idAdmission>(
                    merovingian::auth::default_argon2id_capacity());
                auto const retried = verify(runtime, alice, alice_password);

                THEN("the same password is verified: shedding spent none of the account's guessing budget")
                {
                    REQUIRE(retried.outcome == Outcome::verified);
                }
            }
        }
    }
}

SCENARIO("The shared password check refuses an unknown user as a wrong password, and counts the failure",
         "[integration][auth][oauth][oauth-login]")
{
    GIVEN("a runtime with no account named nobody")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("nobody's password is checked until the throttle answers")
        {
            auto const first = verify(runtime, "@nobody:example.org", "WhateverPass99!x");
            auto last = first;
            auto attempts = 1;
            for (; attempts < max_throttle_attempts && last.outcome == Outcome::invalid_login; ++attempts)
            {
                last = verify(runtime, "@nobody:example.org", "WhateverPass99!x");
            }

            THEN("each attempt is an invalid login until the claimed ID is throttled, as for a real account")
            {
                REQUIRE(first.outcome == Outcome::invalid_login);
                REQUIRE(first.user_id.empty());
                REQUIRE(last.outcome == Outcome::throttled);
            }
        }
    }
}

SCENARIO("The shared password check applies the account-state gates after a correct password",
         "[integration][auth][oauth][oauth-login]")
{
    GIVEN("alice has an account")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_runtime(token_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = hs::register_local_user(runtime, "alice", alice_password,
                                                        std::string{merovingian::tests::registration_token});
        REQUIRE(registered.ok);
        auto const alice = registered.value;
        auto* const user = user_of(runtime, alice);
        REQUIRE(user != nullptr);

        WHEN("her account is deactivated")
        {
            user->deactivated = true;
            auto const result = verify(runtime, alice, alice_password);
            auto const legacy = hs::login_local_user(runtime, alice, alice_password, "DEV1");

            THEN("the check answers deactivated, as POST /login does")
            {
                REQUIRE(result.outcome == Outcome::account_deactivated);
                REQUIRE(result.user_id.empty());
                REQUIRE(legacy.status == 403U);
                REQUIRE(legacy.reason == "account deactivated");
            }
        }

        WHEN("her account is locked")
        {
            user->locked = true;
            auto const result = verify(runtime, alice, alice_password);
            auto const legacy = hs::login_local_user(runtime, alice, alice_password, "DEV1");

            THEN("the check answers an invalid login, as POST /login does")
            {
                REQUIRE(result.outcome == Outcome::invalid_login);
                REQUIRE(result.user_id.empty());
                REQUIRE(legacy.status == 403U);
                REQUIRE(legacy.reason == "invalid login");
            }
        }

        WHEN("her account is suspended")
        {
            user->suspended = true;
            auto const result = verify(runtime, alice, alice_password);
            auto const sessions_after_check = session_count_of(runtime, alice);
            auto const legacy = hs::login_local_user(runtime, alice, alice_password, "DEV1");

            THEN("the check verifies her, as POST /login lets a suspended account log in, and creates no device")
            {
                REQUIRE(result.outcome == Outcome::verified);
                REQUIRE(result.user_id == alice);
                REQUIRE(sessions_after_check == 0U);
                REQUIRE_FALSE(holds_page_device(runtime, alice));
                REQUIRE(legacy.ok);
            }
        }
    }
}
