// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
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
//     single-use enforcement; a locked account is refused with M_USER_LOCKED while a
//     suspended one is still served; a refresh whose device row was deleted fails closed
//   - access_token_is_soft_logout: false for empty and unknown tokens
//   - load_hashed_registration_token: a rotated token file invalidates the cached hash
//   - request_openid_token / federation_openid_userinfo: mint returns all
//     spec-required fields; userinfo redeems a valid token; unknown and
//     expired tokens both fail closed identically; an OpenID token is
//     rejected by the ordinary client-server auth gate and an ordinary
//     access token is rejected by federation_openid_userinfo (the
//     security-critical separation -- see docs/threat-model.md)

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/auth/identity.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include <sodium.h>
#include <unistd.h>

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

        // Corrected in 0.12.13 (audit item 6, approved by the user): this
        // scenario required refresh tokens to be single-use at once. Spec
        // (client-server-api.md, POST /refresh): "The old refresh token remains
        // valid until the new access token or refresh token is used, at which
        // point the old refresh token is revoked."
        WHEN("the same refresh token is used again before the new tokens are used")
        {
            auto const first = merovingian::homeserver::refresh_local_session(runtime, issued.value);
            REQUIRE(first.ok);
            auto const retry = merovingian::homeserver::refresh_local_session(runtime, issued.value);

            THEN("the retry succeeds, as it must when the first response was lost")
            {
                REQUIRE(retry.ok);
            }
        }

        WHEN("the same refresh token is used again after the new refresh token has been used")
        {
            auto const first = merovingian::homeserver::refresh_local_session(runtime, issued.value);
            REQUIRE(first.ok);
            auto const second = merovingian::homeserver::refresh_local_session(runtime, first.refresh_token);
            REQUIRE(second.ok);
            auto const reuse = merovingian::homeserver::refresh_local_session(runtime, issued.value);

            THEN("the reuse is rejected")
            {
                REQUIRE_FALSE(reuse.ok);
            }
        }
    }
}

// H-01 / H-02 (security audit 2026-09). Two independent gates on the refresh
// path. Locking is a spec MUST (§Account locking: 401 M_USER_LOCKED with
// soft_logout on every API but logout), and §Soft logout says a locked client
// "cannot obtain a new access token until the account has been unlocked" — so
// the refusal has to live in refresh_local_session itself, which authenticates
// with a refresh token and therefore never passes the access-token moderation
// gate in the dispatcher.
SCENARIO("refresh_local_session refuses to mint tokens for a locked account", "[homeserver][auth][refresh][moderation]")
{
    GIVEN("a registered user holding a refresh token whose account is then locked")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "lockme", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        std::ignore = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        auto const issued = merovingian::homeserver::issue_refresh_token_for_session(runtime, reg.value, "DEVICE1");
        REQUIRE(issued.ok);

        auto const user =
            std::ranges::find_if(runtime.database.users, [&reg](merovingian::homeserver::LocalUser const& candidate) {
                return candidate.user_id == reg.value;
            });
        REQUIRE(user != runtime.database.users.end());
        user->locked = true;

        WHEN("the refresh token is exchanged")
        {
            auto const refreshed = merovingian::homeserver::refresh_local_session(runtime, issued.value);

            THEN("the refresh is refused as M_USER_LOCKED and no credential is issued")
            {
                REQUIRE_FALSE(refreshed.ok);
                REQUIRE(refreshed.status == 401U);
                REQUIRE(refreshed.errcode == "M_USER_LOCKED");
                REQUIRE(refreshed.soft_logout);
                REQUIRE(refreshed.access_token.empty());
                REQUIRE(refreshed.refresh_token.empty());
            }
        }

        WHEN("the account is unlocked and the same refresh token is exchanged")
        {
            user->locked = false;
            auto const refreshed = merovingian::homeserver::refresh_local_session(runtime, issued.value);

            THEN("the refresh succeeds — the lock gates the request, it does not revoke the token")
            {
                REQUIRE(refreshed.ok);
                REQUIRE_FALSE(refreshed.access_token.empty());
            }
        }
    }
}

// Suspension is deliberately NOT a refusal here. The spec leaves the permitted
// actions of a suspended account to the implementation but SHOULD-lists "log in
// and create additional sessions" and "see and receive messages ... through
// /sync and /messages" among them, and this server's own suspension allowlist
// already permits POST /login — which mints unlimited fresh access tokens.
// Refusing /refresh while permitting /login would buy no security and would
// break the sync access the spec asks servers to preserve.
SCENARIO("refresh_local_session still serves a suspended account", "[homeserver][auth][refresh][moderation]")
{
    GIVEN("a registered user holding a refresh token whose account is then suspended")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "suspendme", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        std::ignore = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        auto const issued = merovingian::homeserver::issue_refresh_token_for_session(runtime, reg.value, "DEVICE1");
        REQUIRE(issued.ok);

        auto const user =
            std::ranges::find_if(runtime.database.users, [&reg](merovingian::homeserver::LocalUser const& candidate) {
                return candidate.user_id == reg.value;
            });
        REQUIRE(user != runtime.database.users.end());
        user->suspended = true;

        WHEN("the refresh token is exchanged")
        {
            auto const refreshed = merovingian::homeserver::refresh_local_session(runtime, issued.value);

            THEN("the refresh succeeds so the suspended user can keep syncing")
            {
                REQUIRE(refreshed.ok);
                REQUIRE_FALSE(refreshed.access_token.empty());
            }
        }
    }
}

// H-02 (security audit 2026-09). A refresh token outlives its device only
// through a failure — a partial deactivation, a revocation race, a leak. The
// token lifecycle assumes tokens are bound to real devices, so a refresh whose
// device row is gone must fail closed rather than resurrect the session.
SCENARIO("refresh_local_session refuses a refresh token whose device has been deleted",
         "[homeserver][auth][refresh][device]")
{
    GIVEN("a registered user holding a refresh token for a device that is then deleted")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "zombie", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        std::ignore = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        auto const issued = merovingian::homeserver::issue_refresh_token_for_session(runtime, reg.value, "DEVICE1");
        REQUIRE(issued.ok);
        REQUIRE(merovingian::database::delete_device(runtime.database.persistent_store, reg.value, "DEVICE1"));

        WHEN("the refresh token for the deleted device is exchanged")
        {
            auto const refreshed = merovingian::homeserver::refresh_local_session(runtime, issued.value);

            THEN("the refresh is refused and no credential is issued for the dead device")
            {
                REQUIRE_FALSE(refreshed.ok);
                REQUIRE(refreshed.status == 401U);
                REQUIRE(refreshed.access_token.empty());
                REQUIRE(refreshed.refresh_token.empty());
            }
        }

        WHEN("a second device still exists and its refresh token is exchanged")
        {
            std::ignore = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE2");
            auto const second = merovingian::homeserver::issue_refresh_token_for_session(runtime, reg.value, "DEVICE2");
            REQUIRE(second.ok);
            auto const refreshed = merovingian::homeserver::refresh_local_session(runtime, second.value);

            THEN("that refresh still succeeds")
            {
                REQUIRE(refreshed.ok);
                REQUIRE(refreshed.device_id == "DEVICE2");
            }
        }
    }
}

// --- load_hashed_registration_token: rotation invalidates the cache -----------

// M-01 (security audit 2026-09). The Argon2id hash of the registration token
// file is cached because hashing it on every registration would be a
// self-inflicted DoS. It was cached by path alone and never revalidated, so an
// operator who rotated the token on disk kept serving the old one until the
// next restart — a revoked credential that stays live is the failure mode
// credential rotation exists to prevent.
SCENARIO("load_hashed_registration_token reloads a rotated token file", "[homeserver][auth][registration][token]")
{
    GIVEN("a registration token file on disk")
    {
        REQUIRE(sodium_init() >= 0);
        auto const path = std::filesystem::path{merovingian::tests::temporary_directory() /
                                                ("merovingian-rotate-" + std::to_string(::getpid()) + ".txt")};
        {
            auto output = std::ofstream{path};
            output << "first-token-value\n";
        }
        auto registration = merovingian::config::RegistrationSecurityConfig{};
        registration.token_file = path.string();

        auto const first = merovingian::homeserver::load_hashed_registration_token(registration);
        REQUIRE(first.has_value());
        REQUIRE(merovingian::auth::registration_token_matches(*first, "first-token-value"));

        WHEN("the file is read again without changing")
        {
            auto const again = merovingian::homeserver::load_hashed_registration_token(registration);

            THEN("the same hash is served from cache")
            {
                REQUIRE(again.has_value());
                REQUIRE(*again == *first);
            }
        }

        WHEN("the operator rotates the token on disk")
        {
            // A same-second rewrite is the hard case: an mtime-seconds-only
            // check would miss it. The identity therefore includes size and
            // sub-second mtime as well.
            {
                auto output = std::ofstream{path, std::ios::trunc};
                output << "second-token-value-which-is-longer\n";
            }
            auto const rotated = merovingian::homeserver::load_hashed_registration_token(registration);

            THEN("the new token is accepted and the old one is not")
            {
                REQUIRE(rotated.has_value());
                REQUIRE(merovingian::auth::registration_token_matches(*rotated, "second-token-value-which-is-longer"));
                REQUIRE_FALSE(merovingian::auth::registration_token_matches(*rotated, "first-token-value"));
            }
        }

        std::error_code ec{};
        std::ignore = std::filesystem::remove(path, ec);
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

// --- load_hashed_registration_token ------------------------------------------------

SCENARIO("load_hashed_registration_token loads and hashes a token file once",
         "[homeserver][auth][registration][security]")
{
    GIVEN("a registration token file")
    {
        REQUIRE(sodium_init() >= 0);
        auto token_file = merovingian::tests::registration_token_file();
        auto config = merovingian::config::RegistrationSecurityConfig{};
        config.enabled = true;
        config.require_token = true;
        config.token_file = token_file;

        WHEN("the token file is hashed")
        {
            auto const first = merovingian::homeserver::load_hashed_registration_token(config);

            THEN("a non-empty Argon2id hash is returned")
            {
                REQUIRE(first.has_value());
                REQUIRE(!first->empty());
            }
        }

        WHEN("the hash is used to verify the original token")
        {
            auto const hash = merovingian::homeserver::load_hashed_registration_token(config);

            THEN("the correct token validates and an incorrect token is rejected")
            {
                REQUIRE(hash.has_value());
                REQUIRE(merovingian::auth::registration_token_matches(
                    *hash, std::string{merovingian::tests::registration_token}));
                REQUIRE_FALSE(merovingian::auth::registration_token_matches(*hash, "not-the-token"));
            }
        }

        WHEN("the same token file is hashed twice")
        {
            auto const first = merovingian::homeserver::load_hashed_registration_token(config);
            auto const second = merovingian::homeserver::load_hashed_registration_token(config);

            THEN("the second call returns the cached hash without re-reading the file")
            {
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
                REQUIRE(*first == *second);
            }
        }
    }

    GIVEN("a missing token file")
    {
        auto config = merovingian::config::RegistrationSecurityConfig{};
        config.enabled = true;
        config.require_token = true;
        config.token_file = "/nonexistent/registration/token/file.txt";

        WHEN("load_hashed_registration_token is called")
        {
            auto const hash = merovingian::homeserver::load_hashed_registration_token(config);

            THEN("no hash is returned so registration is rejected")
            {
                REQUIRE_FALSE(hash.has_value());
            }
        }
    }
}

// --- request_openid_token / federation_openid_userinfo ---------------------------

SCENARIO("request_openid_token mints a token with all spec-required fields",
         "[homeserver][auth][openid][client-server]")
{
    GIVEN("a registered user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);

        WHEN("an OpenID token is requested for that user")
        {
            auto const result = merovingian::homeserver::request_openid_token(runtime, reg.value);

            THEN("the mint succeeds and every spec-required field is populated")
            {
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
                // Spec MUST: access_token, expires_in, matrix_server_name, token_type
                // are all required in the 200 response.
                REQUIRE_FALSE(result.access_token.empty());
                REQUIRE(result.expires_in_seconds > 0U);
                REQUIRE(result.matrix_server_name == runtime.config.server().server_name);
            }
        }
    }
}

SCENARIO("federation_openid_userinfo redeems a token minted by request_openid_token",
         "[homeserver][auth][openid][federation]")
{
    GIVEN("a user with a freshly minted OpenID token")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const issued = merovingian::homeserver::request_openid_token(runtime, reg.value);
        REQUIRE(issued.ok);

        WHEN("the token is redeemed via federation_openid_userinfo")
        {
            auto const sub = merovingian::homeserver::federation_openid_userinfo(runtime, issued.access_token);

            THEN("the owning Matrix user ID is returned")
            {
                REQUIRE(sub.has_value());
                REQUIRE(*sub == reg.value);
            }
        }
    }
}

SCENARIO("federation_openid_userinfo fails closed for an unknown token",
         "[homeserver][auth][openid][federation][error]")
{
    GIVEN("a started runtime with no minted OpenID tokens")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("userinfo is called with a token that was never issued")
        {
            auto const sub = merovingian::homeserver::federation_openid_userinfo(runtime, "mvo_never_issued");

            THEN("no user ID is returned")
            {
                REQUIRE_FALSE(sub.has_value());
            }
        }

        WHEN("userinfo is called with an empty token")
        {
            auto const sub = merovingian::homeserver::federation_openid_userinfo(runtime, "");

            THEN("no user ID is returned")
            {
                REQUIRE_FALSE(sub.has_value());
            }
        }
    }
}

SCENARIO("federation_openid_userinfo fails closed for an expired token, identically to an unknown one",
         "[homeserver][auth][openid][federation][error]")
{
    GIVEN("a user whose OpenID token's expiry has already passed")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const issued = merovingian::homeserver::request_openid_token(runtime, reg.value);
        REQUIRE(issued.ok);
        // Confirm the token is valid before backdating it, so the later
        // rejection is provably caused by expiry rather than some other
        // lookup failure.
        REQUIRE(merovingian::homeserver::federation_openid_userinfo(runtime, issued.access_token).has_value());
        for (auto& row : runtime.database.persistent_store.openid_tokens)
        {
            row.expires_at = std::chrono::system_clock::now() - std::chrono::seconds{1};
        }

        WHEN("userinfo is called after the token has expired")
        {
            auto const expired_sub = merovingian::homeserver::federation_openid_userinfo(runtime, issued.access_token);
            auto const unknown_sub = merovingian::homeserver::federation_openid_userinfo(runtime, "mvo_never_issued");

            THEN("no user ID is returned, and the outcome is indistinguishable from an unknown token")
            {
                REQUIRE_FALSE(expired_sub.has_value());
                REQUIRE_FALSE(unknown_sub.has_value());
            }
        }
    }
}

SCENARIO("an OpenID token is rejected by the ordinary client-server auth gate", "[homeserver][auth][openid][security]")
{
    GIVEN("a user with a freshly minted OpenID token")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const issued = merovingian::homeserver::request_openid_token(runtime, reg.value);
        REQUIRE(issued.ok);
        // Sanity: the token is genuinely valid for its intended purpose.
        REQUIRE(merovingian::homeserver::federation_openid_userinfo(runtime, issued.access_token).has_value());

        WHEN("the OpenID token is presented to authenticated_user, as an ordinary bearer credential would be")
        {
            auto const user = merovingian::homeserver::authenticated_user(runtime, issued.access_token);

            THEN("it does not authenticate a client-server request")
            {
                // Security-critical: an OpenID token lives only in
                // openid_tokens, never access_tokens, so it must never pass
                // the ordinary client-server auth gate.
                REQUIRE_FALSE(user.has_value());
            }
        }
    }
}

SCENARIO("an ordinary access token is rejected by federation_openid_userinfo", "[homeserver][auth][openid][security]")
{
    GIVEN("a logged-in user's ordinary access token")
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
        // Sanity: the token is genuinely valid for its intended purpose.
        REQUIRE(merovingian::homeserver::authenticated_user(runtime, login.value).has_value());

        WHEN("the access token is presented to federation_openid_userinfo, as an OpenID token would be")
        {
            auto const sub = merovingian::homeserver::federation_openid_userinfo(runtime, login.value);

            THEN("it is not accepted as an OpenID token")
            {
                // Security-critical: federation_openid_userinfo consults
                // only openid_tokens, never access_tokens/sessions, so an
                // ordinary access token must never redeem as one.
                REQUIRE_FALSE(sub.has_value());
            }
        }
    }
}

// --- M-04: logout must invalidate the device's refresh token -----------------
// Spec: docs/matrix-v1.19-spec/client-server-api.md
//       #post_matrixclientv3logout — logout invalidates the access token and
//       the refresh token issued alongside it.
//
// The bug: logout_local_user revoked the access token and flipped the in-memory
// session, but never touched the refresh_tokens table. refresh_local_session
// admits any refresh row that is merely unrevoked, so the "logged out" client
// could mint a brand-new access token immediately afterwards and carry on.
// logout_all, device deletion and password change all revoked refresh tokens
// already; single-device logout was the one path that did not.
SCENARIO("logout_local_user revokes the device's refresh token, not just the access token",
         "[homeserver][auth][logout][security][m04]")
{
    GIVEN("a logged-in session that also holds a refresh token")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE_A");
        REQUIRE(login.ok);
        auto const refresh_issued =
            merovingian::homeserver::issue_refresh_token_for_session(runtime, reg.value, "DEVICE_A");
        REQUIRE(refresh_issued.ok);

        WHEN("the session is logged out")
        {
            auto const logout = merovingian::homeserver::logout_local_user(runtime, login.value);
            REQUIRE(logout.ok);

            THEN("the access token is rejected and the refresh token can no longer mint a new one")
            {
                REQUIRE_FALSE(merovingian::homeserver::authenticated_user(runtime, login.value).has_value());

                // The assertion that matters: a logout that leaves the refresh
                // token alive is cosmetic, because this call hands back a fresh
                // access token for the session the user just ended.
                auto const refreshed = merovingian::homeserver::refresh_local_session(runtime, refresh_issued.value);
                REQUIRE_FALSE(refreshed.ok);
                REQUIRE(refreshed.access_token.empty());
            }
        }
    }
}

// --- M-05: a password change must never resurrect a revoked token ------------
// Spec: docs/matrix-v1.19-spec/client-server-api.md
//       #post_matrixclientv3accountpassword — with logout_devices (the default)
//       the server invalidates the access tokens of the user's OTHER devices.
//
// The bug: the implementation revoked every token for the user and then called
// restore_tokens_for_device for the caller's own device. That restore was an
// unfiltered "SET revoked = false WHERE user_id AND device_id", so it could not
// distinguish tokens it had revoked microseconds earlier from tokens revoked
// days earlier by a logout or an admin action — and it un-revoked all of them.
//
// A password change is the action a user performs *after* discovering a
// compromise, so the remediation handed a previously-revoked token back to
// whoever held it. The fix revokes the other devices directly and deletes the
// restore path entirely, so no code can un-revoke a credential.
SCENARIO("change_local_user_password does not resurrect a previously revoked token on the caller's device",
         "[homeserver][auth][password_change][security][m05]")
{
    GIVEN("a device whose earlier session was logged out, and a current session on that same device")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "OldPassword7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);

        // The stolen-and-revoked credential: a session on DEVICE1 that was
        // explicitly logged out. Nothing may ever make this token valid again.
        auto const stolen = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE1");
        REQUIRE(stolen.ok);
        auto const stolen_logout = merovingian::homeserver::logout_local_user(runtime, stolen.value);
        REQUIRE(stolen_logout.ok);
        REQUIRE_FALSE(merovingian::homeserver::authenticated_user(runtime, stolen.value).has_value());

        // The user then signs in again on the same device and changes their
        // password, which is exactly what someone does after a compromise.
        auto const current = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE1");
        REQUIRE(current.ok);

        WHEN("the password is changed from that device with logout_devices enabled")
        {
            auto const change =
                merovingian::homeserver::change_local_user_password(runtime, current.value, "NewPassword99!");
            REQUIRE(change.ok);

            THEN("the previously revoked token on that device stays revoked")
            {
                // This is the finding: the old revoke-then-restore reinstated it.
                REQUIRE_FALSE(merovingian::homeserver::authenticated_user(runtime, stolen.value).has_value());
            }

            AND_THEN("the session that performed the change still works")
            {
                // The whole point of keeping the caller's device is that the user
                // is not logged out of the device they are sitting at.
                REQUIRE(merovingian::homeserver::authenticated_user(runtime, current.value).has_value());
            }
        }
    }
}

// A password change must still drop the user's other devices — the behaviour the
// revoke-then-restore pair was written to provide. Asserting it here means the
// M-05 fix cannot be "achieved" by simply not revoking anything.
SCENARIO("verify_local_user_password applies the same lockout as /login",
         "[homeserver][auth][reauth][lockout][security][m02]")
{
    GIVEN("a registered user with a valid access token")
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

        WHEN("the correct password is presented")
        {
            auto const result =
                merovingian::homeserver::verify_local_user_password(runtime, login.value, "CorrectHorse7!");

            THEN("verification succeeds and no lockout is reported")
            {
                REQUIRE(result.ok);
                REQUIRE(result.retry_after_ms == 0U);
            }
        }

        WHEN("the wrong password is presented enough times to reach the lockout threshold")
        {
            for (auto i = 0U; i < 5U; ++i)
            {
                auto const bad = merovingian::homeserver::verify_local_user_password(runtime, login.value, "wrong");
                REQUIRE_FALSE(bad.ok);
                REQUIRE(bad.retry_after_ms == 0U);
            }

            THEN("the next attempt is locked out, even with the correct password")
            {
                auto const locked = merovingian::homeserver::verify_local_user_password(runtime, login.value, "wrong");
                REQUIRE_FALSE(locked.ok);
                REQUIRE(locked.retry_after_ms > 0U);
            }

            THEN("the correct password during the lockout is still refused")
            {
                auto const correct =
                    merovingian::homeserver::verify_local_user_password(runtime, login.value, "CorrectHorse7!");
                REQUIRE_FALSE(correct.ok);
                REQUIRE(correct.retry_after_ms > 0U);
            }
        }
    }

    GIVEN("a locked-out account reached through /login")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        // Obtain a valid access token before tripping the lockout. The token
        // survives the lockout; the point is that re-auth shares the /login
        // failure counter.
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE_OK");
        REQUIRE(login.ok);

        // Trip the lockout through /login so the re-auth path shares the counter.
        for (auto i = 0U; i < 5U; ++i)
        {
            std::ignore =
                merovingian::homeserver::login_local_user(runtime, reg.value, "wrong", "DEVICE" + std::to_string(i));
        }

        WHEN("the same account is asked to re-authenticate using the pre-lockout token")
        {
            auto const reauth =
                merovingian::homeserver::verify_local_user_password(runtime, login.value, "CorrectHorse7!");

            THEN("the re-auth path sees the lockout and refuses even the correct password")
            {
                REQUIRE_FALSE(reauth.ok);
                REQUIRE(reauth.retry_after_ms > 0U);
            }
        }
    }
}

SCENARIO("change_local_user_password still revokes other devices after the M-05 fix",
         "[homeserver][auth][password_change][security][m05]")
{
    GIVEN("a user signed in on two devices")
    {
        REQUIRE(sodium_init() >= 0);
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
        auto const other_refresh =
            merovingian::homeserver::issue_refresh_token_for_session(runtime, reg.value, "DEVICE2");
        REQUIRE(other_refresh.ok);

        WHEN("the password is changed from the first device")
        {
            auto const change =
                merovingian::homeserver::change_local_user_password(runtime, caller.value, "NewPassword99!");
            REQUIRE(change.ok);

            THEN("the other device loses both its access token and its refresh token")
            {
                REQUIRE_FALSE(merovingian::homeserver::authenticated_user(runtime, other.value).has_value());
                // A revoked access token with a live refresh token is not a
                // revoked session, which is the same mistake as M-04.
                auto const refreshed = merovingian::homeserver::refresh_local_session(runtime, other_refresh.value);
                REQUIRE_FALSE(refreshed.ok);
            }
        }
    }
}

// --- DB-5: token revocation paths verify durable-store state --------------------
//
// revoke_* helpers return the number of in-memory rows updated, which equals the
// durable row count only when the backend commit succeeds. A backend failure also
// returns 0, so callers must verify the persistent store state instead of
// trusting the count. The scenarios below inject a memory-backend failure and
// assert that the auth endpoint reports a 500 rather than pretending revocation
// succeeded.

SCENARIO("logout_local_user fails closed when token revocation cannot persist",
         "[homeserver][auth][logout][security][db-5]")
{
    GIVEN("a started runtime with a logged-in user")
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

        WHEN("the access-token revocation statement is forced to fail")
        {
            merovingian::database::force_persist_failure_for_statement(runtime.database.persistent_store,
                                                                       "revoke_access_token");
            auto const result = merovingian::homeserver::logout_local_user(runtime, login.value);

            THEN("logout reports a persistence failure instead of success")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 500U);
                REQUIRE(result.reason == "token revocation persistence failed");
            }
        }
    }
}

SCENARIO("logout_all_local_user fails closed when token revocation cannot persist",
         "[homeserver][auth][logout_all][security][db-5]")
{
    GIVEN("a started runtime with a logged-in user")
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

        WHEN("the access-token revocation statement is forced to fail")
        {
            merovingian::database::force_persist_failure_for_statement(runtime.database.persistent_store,
                                                                       "revoke_user_access_tokens");
            auto const result = merovingian::homeserver::logout_all_local_user(runtime, login.value);

            THEN("logout_all reports a persistence failure instead of success")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 500U);
                REQUIRE(result.reason == "session revocation persistence failed");
            }
        }
    }
}

SCENARIO("delete_local_device fails closed when token revocation cannot persist",
         "[homeserver][auth][delete_device][security][db-5]")
{
    GIVEN("a started runtime with a logged-in user")
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

        WHEN("the access-token revocation statement is forced to fail")
        {
            merovingian::database::force_persist_failure_for_statement(runtime.database.persistent_store,
                                                                       "revoke_device_access_tokens");
            auto const result = merovingian::homeserver::delete_local_device(runtime, reg.value, "DEVICE1");

            THEN("device deletion reports a persistence failure instead of success")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 500U);
                REQUIRE(result.reason == "token revocation persistence failed");
            }
        }
    }
}

SCENARIO("change_local_user_password fails closed when other-device revocation cannot persist",
         "[homeserver][auth][password_change][security][db-5]")
{
    GIVEN("a user signed in on two devices")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "OldPassword7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const caller = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE1");
        REQUIRE(caller.ok);
        std::ignore = merovingian::homeserver::login_local_user(runtime, reg.value, "OldPassword7!", "DEVICE2");

        WHEN("the other-device revocation statement is forced to fail")
        {
            merovingian::database::force_persist_failure_for_statement(runtime.database.persistent_store,
                                                                       "revoke_user_access_tokens_except_device");
            auto const result =
                merovingian::homeserver::change_local_user_password(runtime, caller.value, "NewPassword99!");

            THEN("password change reports a persistence failure instead of success")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 500U);
                REQUIRE(result.reason == "token revocation persistence failed");
            }
        }
    }
}

SCENARIO("refresh_local_session fails closed when token revocation cannot persist",
         "[homeserver][auth][refresh][security][db-5]")
{
    GIVEN("a registered user with a refresh token")
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

        WHEN("the access-token revocation statement is forced to fail")
        {
            merovingian::database::force_persist_failure_for_statement(runtime.database.persistent_store,
                                                                       "revoke_device_access_tokens");
            auto const result = merovingian::homeserver::refresh_local_session(runtime, issued.value);

            THEN("refresh reports a persistence failure and issues no credential")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 500U);
                REQUIRE(result.access_token.empty());
                REQUIRE(result.refresh_token.empty());
            }
        }
    }
}
