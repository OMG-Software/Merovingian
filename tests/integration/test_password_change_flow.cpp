// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// A password change end to end: the auth service, the persistent store and its injected write
// failures together. A change that cannot finish must commit nothing a client would have to undo.
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
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

} // namespace

// POST /account/password with `logout_devices` (default true) revokes the user's other devices,
// and this server also deletes the pushers those devices set (ADR-0264). The deletions run before
// the password or any token is written, so a failed deletion leaves the old password valid and
// the request can be retried.
SCENARIO("change_local_user_password commits nothing when a revoked device's pusher cannot be removed",
         "[integration][auth][password_change][security][db-5][password-change-pushers]")
{
    GIVEN("a user signed in on two devices, with a pusher set from the other device")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "OldPassword7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const caller = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE1");
        REQUIRE(caller.ok);
        auto const other = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE2");
        REQUIRE(other.ok);
        auto pusher = merovingian::database::PersistentPusher{};
        pusher.user_id = reg.value;
        pusher.app_id = "com.example.app";
        pusher.pushkey = "device2-key";
        pusher.kind = "http";
        pusher.device_id = "DEVICE2";
        REQUIRE(merovingian::database::store_pusher(runtime.database.persistent_store, pusher));

        WHEN("removing that pusher is forced to fail during a password change")
        {
            merovingian::database::force_persist_failure_for_statement(runtime.database.persistent_store,
                                                                       "delete_pusher");
            auto const result =
                merovingian::homeserver::change_local_user_password(runtime, caller.value, "NewPassword99!");

            THEN("the change is reported as failed and nothing it would change was committed")
            {
                // A failure must mean the password is unchanged, so the client can retry with the old one.
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 500U);
                REQUIRE(merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE3").ok);
                REQUIRE_FALSE(
                    merovingian::homeserver::login_local_user(runtime, reg.value, "NewPassword99!", "DEVICE4").ok);
                // The other device keeps its session, since its tokens were never revoked.
                REQUIRE(merovingian::homeserver::authenticated_user(runtime, other.value).has_value());
            }
        }
    }
}
