// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Error, boundary, and anomaly tests for auth_service functions not covered
// by test_homeserver_error_paths.cpp or test_homeserver_vertical_slice.cpp.
//
// Coverage:
//   - bootstrap_admin_user: admin privilege granted; duplicate rejected; non-admin
//     users cannot obtain admin status
//   - account_state_for_user: nullopt for unknown/empty; active for new registrations
//   - logout_all_local_user: unknown/empty token rejected; all sessions revoked
//   - change_local_user_password: unknown token rejected; old password rejected after
//     change; new password works; existing sessions invalidated (logout_devices=true)
//   - delete_local_device: unknown user/device rejected; valid deletion invalidates session
//   - issue_refresh_token_for_session: unknown user rejected
//   - refresh_local_session: empty/unknown token rejected; valid refresh issues new tokens;
//     single-use enforcement
//   - access_token_is_soft_logout: false for empty and unknown tokens

#include "../support/registration_token.hpp"
#include "merovingian/auth/identity.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

#include <sodium.h>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

} // namespace

// --- bootstrap_admin_user --------------------------------------------------------

SCENARIO("bootstrap_admin_user creates a new user with admin privilege", "[homeserver][auth][admin][bootstrap]")
{
    GIVEN("a started runtime with no users")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("bootstrap_admin_user is called with valid credentials")
        {
            auto const result = merovingian::homeserver::bootstrap_admin_user(runtime, "admin", "AdminPass99!");

            THEN("bootstrap succeeds and returns the fully-qualified user_id")
            {
                REQUIRE(result.ok);
                REQUIRE(result.value == "@admin:example.org");
            }
        }

        WHEN("bootstrap_admin_user is called twice with the same localpart")
        {
            auto const first = merovingian::homeserver::bootstrap_admin_user(runtime, "admin", "AdminPass99!");
            REQUIRE(first.ok);
            auto const second = merovingian::homeserver::bootstrap_admin_user(runtime, "admin", "DifferentPass!");

            THEN("the second bootstrap fails — localparts are unique per homeserver")
            {
                REQUIRE_FALSE(second.ok);
            }
        }
    }
}

SCENARIO("bootstrap_admin_user grants admin privilege detectable by authenticated_admin_user",
         "[homeserver][auth][admin][bootstrap]")
{
    GIVEN("a started runtime with a bootstrapped admin user logged in")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const bootstrap = merovingian::homeserver::bootstrap_admin_user(runtime, "admin", "AdminPass99!");
        REQUIRE(bootstrap.ok);
        auto const login =
            merovingian::homeserver::login_local_user(runtime, bootstrap.value, "AdminPass99!", "ADMIN_DEV");
        REQUIRE(login.ok);

        WHEN("the admin token is presented to authenticated_admin_user")
        {
            auto const admin_user = merovingian::homeserver::authenticated_admin_user(runtime, login.value);

            THEN("admin status is confirmed")
            {
                REQUIRE(admin_user.has_value());
                REQUIRE(*admin_user == "@admin:example.org");
            }
        }
    }
}

SCENARIO("bootstrap_admin_user does not grant admin privilege to regular registered users",
         "[homeserver][auth][admin][security]")
{
    GIVEN("a started runtime with a regular registered user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("the regular user's token is presented to authenticated_admin_user")
        {
            auto const admin_user = merovingian::homeserver::authenticated_admin_user(runtime, login.value);

            THEN("admin status is denied — regular registration does not confer admin rights")
            {
                REQUIRE_FALSE(admin_user.has_value());
            }
        }
    }
}

// --- account_state_for_user ------------------------------------------------------

SCENARIO("account_state_for_user returns nullopt for user_ids not in the store", "[homeserver][auth][account_state]")
{
    GIVEN("a started runtime with no users")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("account state is queried for an unknown user_id")
        {
            auto const state = merovingian::homeserver::account_state_for_user(runtime, "@ghost:example.org");

            THEN("nullopt is returned — unknown users have no state")
            {
                REQUIRE_FALSE(state.has_value());
            }
        }

        WHEN("account state is queried with an empty string")
        {
            auto const state = merovingian::homeserver::account_state_for_user(runtime, "");

            THEN("nullopt is returned — empty strings are not valid user IDs")
            {
                REQUIRE_FALSE(state.has_value());
            }
        }
    }
}

SCENARIO("account_state_for_user returns active for a freshly registered user", "[homeserver][auth][account_state]")
{
    GIVEN("a started runtime with a registered user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);

        WHEN("account state is queried for the registered user")
        {
            auto const state = merovingian::homeserver::account_state_for_user(runtime, reg.value);

            THEN("the state is active — new accounts start without restrictions")
            {
                REQUIRE(state.has_value());
                REQUIRE(*state == merovingian::auth::AccountState::active);
            }
        }
    }
}

// --- logout_all_local_user -------------------------------------------------------

SCENARIO("logout_all_local_user rejects unknown and empty access tokens", "[homeserver][auth][logout_all][error]")
{
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("logout_all is called with a token that was never issued")
        {
            auto const result = merovingian::homeserver::logout_all_local_user(runtime, "syt_unknown_token_xyz");

            THEN("the call fails closed")
            {
                REQUIRE_FALSE(result.ok);
            }
        }

        WHEN("logout_all is called with an empty token")
        {
            auto const result = merovingian::homeserver::logout_all_local_user(runtime, "");

            THEN("the call fails closed on empty input")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("logout_all_local_user revokes every session belonging to the authenticated user",
         "[homeserver][auth][logout_all]")
{
    GIVEN("a user with two active sessions on separate devices")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login_a =
            merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE_A");
        REQUIRE(login_a.ok);
        auto const login_b =
            merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE_B");
        REQUIRE(login_b.ok);

        WHEN("logout_all is called using the first session's token")
        {
            auto const revoke = merovingian::homeserver::logout_all_local_user(runtime, login_a.value);

            THEN("the operation succeeds and both sessions are invalidated")
            {
                REQUIRE(revoke.ok);
                auto const user_a = merovingian::homeserver::authenticated_user(runtime, login_a.value);
                auto const user_b = merovingian::homeserver::authenticated_user(runtime, login_b.value);
                REQUIRE_FALSE(user_a.has_value());
                REQUIRE_FALSE(user_b.has_value());
            }
        }
    }
}

// --- change_local_user_password --------------------------------------------------

SCENARIO("change_local_user_password rejects an unknown access token", "[homeserver][auth][password_change][error]")
{
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("password change is attempted with a token that was never issued")
        {
            auto const result =
                merovingian::homeserver::change_local_user_password(runtime, "syt_unknown_token", "NewPassword99!");

            THEN("the call fails closed — no unauthenticated password changes")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("change_local_user_password updates the credential and rejects the old password",
         "[homeserver][auth][password_change]")
{
    GIVEN("a registered user with an active session")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "OldPassword7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("the password is changed using the active session token")
        {
            auto const change =
                merovingian::homeserver::change_local_user_password(runtime, login.value, "NewPassword99!");

            THEN("the change succeeds, the old password is rejected, and the new password works")
            {
                REQUIRE(change.ok);

                // Old password must be rejected for new logins.
                auto const old_login =
                    merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE2");
                REQUIRE_FALSE(old_login.ok);

                // New password must work for new logins.
                auto const new_login =
                    merovingian::homeserver::login_local_user(runtime, reg.value, "NewPassword99!", "DEVICE2");
                REQUIRE(new_login.ok);
                REQUIRE_FALSE(new_login.value.empty());
            }
        }
    }
}

SCENARIO("change_local_user_password with logout_devices invalidates other device sessions",
         "[homeserver][auth][password_change]")
{
    GIVEN("a registered user with sessions on two devices")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "OldPassword7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login1 = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE1");
        REQUIRE(login1.ok);
        auto const login2 = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE2");
        REQUIRE(login2.ok);

        WHEN("password is changed using DEVICE1's token (logout_devices=true)")
        {
            auto const change =
                merovingian::homeserver::change_local_user_password(runtime, login1.value, "NewPassword99!");
            REQUIRE(change.ok);

            THEN("DEVICE2's session is invalidated")
            {
                // The second device's token must be revoked — logout_devices=true
                // targets all other sessions regardless of which device initiated the change.
                auto const other_session = merovingian::homeserver::authenticated_user(runtime, login2.value);
                REQUIRE_FALSE(other_session.has_value());
            }
        }
    }
}

// --- delete_local_device ---------------------------------------------------------

SCENARIO("delete_local_device rejects unknown user and device identifiers", "[homeserver][auth][delete_device][error]")
{
    GIVEN("a started runtime with a registered user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);

        WHEN("delete_local_device is called for a user that does not exist")
        {
            auto const result = merovingian::homeserver::delete_local_device(runtime, "@ghost:example.org", "DEVICE1");

            THEN("the call fails closed")
            {
                REQUIRE_FALSE(result.ok);
            }
        }

        WHEN("delete_local_device is called for a device_id that was never created")
        {
            auto const result = merovingian::homeserver::delete_local_device(runtime, reg.value, "GHOST_DEVICE");

            THEN("the call fails closed — an unknown device cannot be deleted")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("delete_local_device removes the session for the specified device", "[homeserver][auth][delete_device]")
{
    GIVEN("a registered user with an active session on a named device")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("that device is deleted by user_id and device_id")
        {
            auto const del = merovingian::homeserver::delete_local_device(runtime, reg.value, "DEVICE1");

            THEN("deletion succeeds and the session token is no longer valid")
            {
                REQUIRE(del.ok);
                auto const session = merovingian::homeserver::authenticated_user(runtime, login.value);
                REQUIRE_FALSE(session.has_value());
            }
        }
    }
}

// --- issue_refresh_token_for_session / refresh_local_session ---------------------

SCENARIO("issue_refresh_token_for_session fails for an unknown user", "[homeserver][auth][refresh][error]")
{
    GIVEN("a started runtime with no users")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a refresh token is requested for a user that does not exist")
        {
            auto const result =
                merovingian::homeserver::issue_refresh_token_for_session(runtime, "@ghost:example.org", "DEVICE1");

            THEN("the call fails closed")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("refresh_local_session rejects an unknown or empty refresh token", "[homeserver][auth][refresh][error]")
{
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("refresh is attempted with a token that was never issued")
        {
            auto const result =
                merovingian::homeserver::refresh_local_session(runtime, "totally_unknown_refresh_token");

            THEN("refresh fails closed")
            {
                REQUIRE_FALSE(result.ok);
            }
        }

        WHEN("refresh is attempted with an empty token")
        {
            auto const result = merovingian::homeserver::refresh_local_session(runtime, "");

            THEN("refresh fails closed on empty input")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("refresh_local_session issues a new access token from a valid refresh token", "[homeserver][auth][refresh]")
{
    GIVEN("a registered user with a session that has a refresh token")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        std::ignore = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        auto const issued = merovingian::homeserver::issue_refresh_token_for_session(runtime, reg.value, "DEVICE1");
        REQUIRE(issued.ok);
        REQUIRE_FALSE(issued.value.empty());

        WHEN("the refresh token is exchanged via refresh_local_session")
        {
            auto const refreshed = merovingian::homeserver::refresh_local_session(runtime, issued.value);

            THEN("a new access token and refresh token are returned with the correct user_id")
            {
                REQUIRE(refreshed.ok);
                REQUIRE_FALSE(refreshed.access_token.empty());
                REQUIRE_FALSE(refreshed.refresh_token.empty());
                REQUIRE(refreshed.user_id == reg.value);
            }
        }

        WHEN("the same refresh token is used a second time")
        {
            auto const first = merovingian::homeserver::refresh_local_session(runtime, issued.value);
            REQUIRE(first.ok);
            auto const second = merovingian::homeserver::refresh_local_session(runtime, issued.value);

            THEN("the second use is rejected — refresh tokens are single-use")
            {
                REQUIRE_FALSE(second.ok);
            }
        }
    }
}

// --- access_token_is_soft_logout -------------------------------------------------

SCENARIO("access_token_is_soft_logout returns false for empty and unknown tokens", "[homeserver][auth][soft_logout]")
{
    GIVEN("a started runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("soft_logout is queried for an empty token")
        {
            auto const soft = merovingian::homeserver::access_token_is_soft_logout(runtime, "");

            THEN("returns false — empty tokens are not expired sessions")
            {
                REQUIRE_FALSE(soft);
            }
        }

        WHEN("soft_logout is queried for a token that was never issued")
        {
            auto const soft =
                merovingian::homeserver::access_token_is_soft_logout(runtime, "syt_never_issued_token_xyz");

            THEN("returns false — unknown tokens are not soft-logout candidates")
            {
                REQUIRE_FALSE(soft);
            }
        }
    }
}
