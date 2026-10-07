// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// AUTH-4 (security-audit-report-2026-09-29.md), residual: every Argon2id call a
// client request can reach shares the one admission budget `/login` already
// uses. When the budget is spent the server answers 429 M_LIMIT_EXCEEDED with a
// retry_after_ms at once, before any hash work, and a shed request changes
// nothing and counts as no failed attempt.
//
// Covered here: ordinary /register (make_user), appservice registration,
// POST /account/password (hashing the new password) and the user-interactive
// auth password check (verify_local_user_password).
//
// Spec: Matrix Client-Server API v1.19, "Rate limiting": a limited request is
// 429 M_LIMIT_EXCEEDED with retry_after_ms.
// ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/master_key.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include <sodium.h>

namespace
{

constexpr auto alice_password = "AlicePass99!x";

// Open registration: no registration token, so make_user's own hashing is the
// only Argon2id work an ordinary registration does.
[[nodiscard]] auto open_registration_config() -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "example.org";
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.registration.enabled = true;
    security.registration.require_token = false;
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

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

[[nodiscard]] auto stored_hash_of(merovingian::homeserver::HomeserverRuntime const& runtime, std::string_view user_id)
    -> std::string
{
    auto const it = std::ranges::find_if(runtime.database.users, [user_id](auto const& user) {
        return user.user_id == user_id;
    });
    return it == runtime.database.users.end() ? std::string{} : it->password_hash;
}

[[nodiscard]] auto contains(std::string const& haystack, std::string_view needle) -> bool
{
    return haystack.find(needle) != std::string::npos;
}

} // namespace

SCENARIO("Ordinary registration sheds load when the Argon2id admission budget is spent",
         "[homeserver][auth][security][audit][auth-4]")
{
    GIVEN("a runtime with open registration and no Argon2id capacity")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(open_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const users_before = user_count(runtime.homeserver);
        exhaust_argon2id_admission(runtime.homeserver);

        WHEN("a client registers through the service function")
        {
            auto const result =
                merovingian::homeserver::register_local_user(runtime.homeserver, "carol", "CarolPass99!x");

            THEN("it is refused with 429 and a retry delay, and no account exists")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 429U);
                REQUIRE(result.retry_after_ms > 0U);
                REQUIRE(user_count(runtime.homeserver) == users_before);
            }

            THEN("the failed-login counters are untouched")
            {
                REQUIRE(runtime.homeserver.login_failures_by_source.size() == 0U);
                REQUIRE(runtime.homeserver.login_failures_by_account.size() == 0U);
            }
        }

        WHEN("a client registers over HTTP")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, R"({"username":"carol","password":"CarolPass99!x"})"});

            THEN("it is answered with M_LIMIT_EXCEEDED carrying retry_after_ms, and no account exists")
            {
                REQUIRE(response.response.status == 429U);
                REQUIRE(contains(response.response.body, "M_LIMIT_EXCEEDED"));
                REQUIRE(contains(response.response.body, "retry_after_ms"));
                REQUIRE(user_count(runtime.homeserver) == users_before);
            }
        }

        WHEN("the budget is available again and the same client retries")
        {
            restore_argon2id_admission(runtime.homeserver);
            auto const result =
                merovingian::homeserver::register_local_user(runtime.homeserver, "carol", "CarolPass99!x");

            THEN("the registration succeeds")
            {
                REQUIRE(result.ok);
                REQUIRE(user_count(runtime.homeserver) == users_before + 1U);
            }
        }
    }
}

SCENARIO("Appservice registration shares the Argon2id admission budget", "[homeserver][auth][security][audit][auth-4]")
{
    GIVEN("a runtime with no Argon2id capacity")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(open_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const users_before = user_count(runtime);
        exhaust_argon2id_admission(runtime);

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
        auto started = merovingian::homeserver::start_runtime(open_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = merovingian::homeserver::register_local_user(runtime, "alice", alice_password);
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

SCENARIO("Password change over HTTP reports admission saturation as M_LIMIT_EXCEEDED",
         "[homeserver][auth][security][audit][auth-4]")
{
    GIVEN("alice is signed in and no Argon2id capacity remains")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(open_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered =
            merovingian::homeserver::register_local_user(runtime.homeserver, "alice", alice_password);
        REQUIRE(registered.ok);
        auto const signed_in =
            merovingian::homeserver::login_local_user(runtime.homeserver, registered.value, alice_password, "DEV1");
        REQUIRE(signed_in.ok);
        auto const hash_before = stored_hash_of(runtime.homeserver, registered.value);
        exhaust_argon2id_admission(runtime.homeserver);

        WHEN("she changes her password, answering the UIA challenge with the correct password")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/account/password", signed_in.value,
                 R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"AlicePass99!x"},"new_password":"NewAlicePass99!y"})"});

            THEN("it is answered with M_LIMIT_EXCEEDED carrying retry_after_ms and nothing changes")
            {
                REQUIRE(response.response.status == 429U);
                REQUIRE(contains(response.response.body, "M_LIMIT_EXCEEDED"));
                REQUIRE(contains(response.response.body, "retry_after_ms"));
                REQUIRE(stored_hash_of(runtime.homeserver, registered.value) == hash_before);
            }

            THEN("the saturated check is not recorded as a failed UIA attempt")
            {
                REQUIRE(runtime.homeserver.uia_failures_by_device.size() == 0U);
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
        auto started = merovingian::homeserver::start_runtime(open_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = merovingian::homeserver::register_local_user(runtime, "alice", alice_password);
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
