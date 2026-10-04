// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |  SECURITY AUDIT AUTH-4                                                  |
// |  Medium-severity authentication finding from 2026-09-29 audit.          |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19                                  |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md               |
// +-------------------------------------------------------------------------+
//
// AUTH-4: Argon2id password and registration-token verification must not
// be allowed to consume unbounded CPU under the global runtime mutex. A
// bounded admission semaphore limits in-flight hash work; when saturated,
// the server sheds load with HTTP 429 / M_LIMIT_EXCEEDED before any work is
// performed.

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>

#include <sodium.h>

namespace
{

[[nodiscard]] auto registration_enabled_config(std::string server_name = "example.org") -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = std::move(server_name);
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

} // namespace

SCENARIO("Argon2idAdmission bounds concurrent hash work", "[auth][security][audit][auth4]")
{
    GIVEN("an admission semaphore with capacity two")
    {
        auto admission = merovingian::auth::Argon2idAdmission{2U};

        WHEN("two slots are acquired")
        {
            auto first = admission.try_acquire();
            auto second = admission.try_acquire();

            THEN("both slots are held")
            {
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
            }

            AND_WHEN("a third slot is requested")
            {
                auto third = admission.try_acquire();

                THEN("it is refused while the first two are held")
                {
                    REQUIRE_FALSE(third.has_value());
                }
            }

            AND_WHEN("one slot is released")
            {
                first.reset();
                auto third = admission.try_acquire();

                THEN("a waiting unit of work can take its place")
                {
                    REQUIRE(third.has_value());
                }
            }
        }
    }
}

SCENARIO("login_local_user sheds load when Argon2id admission is full", "[homeserver][auth][security][audit][auth4]")
{
    GIVEN("a started runtime with one known user and zero Argon2id capacity")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const user_id = "@alice:example.org";
        auto const password = "AlicePass99!";
        auto const created = merovingian::homeserver::register_local_user(
            runtime, "alice", password, std::string{merovingian::tests::registration_token});
        REQUIRE(created.ok);

        runtime.argon2id_admission = std::make_unique<merovingian::auth::Argon2idAdmission>(0U);

        WHEN("a login attempt is made while no hash slot is available")
        {
            auto const result = merovingian::homeserver::login_local_user(runtime, user_id, password, "DEV1");

            THEN("the request is rejected with HTTP 429 before any Argon2id work runs")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 429U);
                REQUIRE(result.retry_after_ms > 0U);
            }

            THEN("the failed-login counter is not incremented for a shed request")
            {
                REQUIRE(runtime.failed_logins.find(user_id) == runtime.failed_logins.end());
            }
        }
    }
}

SCENARIO("register_local_user sheds load when Argon2id admission is full", "[homeserver][auth][security][audit][auth4]")
{
    GIVEN("a started runtime with token registration enabled and zero Argon2id capacity")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        runtime.argon2id_admission = std::make_unique<merovingian::auth::Argon2idAdmission>(0U);

        WHEN("a registration that requires token verification is submitted while no hash slot is available")
        {
            auto const result = merovingian::homeserver::register_local_user(
                runtime, "bob", "BobPass99!", std::string{merovingian::tests::registration_token});

            THEN("the request is rejected with HTTP 429 before any Argon2id work runs")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 429U);
            }
        }
    }
}
