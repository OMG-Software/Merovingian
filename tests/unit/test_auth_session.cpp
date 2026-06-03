// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/session.hpp"

#include <catch2/catch_test_macros.hpp>
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <chrono>
#include <string>

namespace
{

[[nodiscard]] auto active_session(std::chrono::system_clock::time_point now) -> merovingian::auth::SessionRecord
{
    auto token = merovingian::auth::AccessTokenRecord{
        "@alice:example.org",
        "DEVICE123",
        merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"},
        now + std::chrono::hours{1},
        false,
    };

    return {"@alice:example.org", "DEVICE123", token, false, false};
}

} // namespace

SCENARIO("Client auth endpoint scaffold classifies public and token-protected routes", "[auth][client-api]")
{
    GIVEN("client auth endpoint kinds")
    {
        WHEN("endpoint metadata is queried")
        {
            auto const login_requires_token = merovingian::auth::client_auth_endpoint_requires_access_token(
                merovingian::auth::ClientAuthEndpoint::login);
            auto const register_requires_token = merovingian::auth::client_auth_endpoint_requires_access_token(
                merovingian::auth::ClientAuthEndpoint::register_account);
            auto const logout_requires_token = merovingian::auth::client_auth_endpoint_requires_access_token(
                merovingian::auth::ClientAuthEndpoint::logout);
            auto const devices_requires_token = merovingian::auth::client_auth_endpoint_requires_access_token(
                merovingian::auth::ClientAuthEndpoint::list_devices);
            auto const login_mutates =
                merovingian::auth::client_auth_endpoint_mutates_session(merovingian::auth::ClientAuthEndpoint::login);
            auto const list_devices_mutates = merovingian::auth::client_auth_endpoint_mutates_session(
                merovingian::auth::ClientAuthEndpoint::list_devices);

            THEN("login and registration are public entry points and session-changing endpoints are marked")
            {
                REQUIRE_FALSE(login_requires_token);
                REQUIRE_FALSE(register_requires_token);
                REQUIRE(logout_requires_token);
                REQUIRE(devices_requires_token);
                REQUIRE(login_mutates);
                REQUIRE_FALSE(list_devices_mutates);
            }
        }
    }
}

SCENARIO("Registration policy remains disabled by default and token-gated when enabled", "[auth][client-api]")
{
    GIVEN("default, missing-token, and token-present registration policies")
    {
        auto const default_policy = merovingian::auth::RegistrationPolicy{};
        auto const missing_token_policy = merovingian::auth::RegistrationPolicy{true, true, false};
        auto const token_present_policy = merovingian::auth::RegistrationPolicy{true, true, true};

        // Tests that ran before us may have installed an audit sink
        // pointed at a now-destroyed LocalDatabase. The auth test
        // never exercises the audit log, so reset the sink to the
        // process-wide default (a no-op) — the `local_audit_sink`
        // early-returns on a null database anyway, but resetting
        // makes the intent explicit and avoids the call to
        // `append_local_audit` entirely. Sites that have a valid
        // `LocalDatabase&` should use `LocalDatabaseScope` instead.
        merovingian::observability::set_audit_sink(&merovingian::observability::default_audit_sink);

        WHEN("registration policy is evaluated")
        {
            auto const disabled = merovingian::auth::registration_policy(default_policy);
            auto const missing_token = merovingian::auth::registration_policy(missing_token_policy);
            auto const token_present = merovingian::auth::registration_policy(token_present_policy);

            THEN("registration fails closed until enabled with the required token")
            {
                REQUIRE_FALSE(disabled.allowed);
                REQUIRE(disabled.reason == "registration disabled");
                REQUIRE_FALSE(missing_token.allowed);
                REQUIRE(missing_token.reason == "registration token required");
                REQUIRE(token_present.allowed);
            }
        }
    }
}

SCENARIO("Session invalidation covers device logout and global logout", "[auth][client-api][tokens]")
{
    GIVEN("an active session and invalidated variants")
    {
        auto const now = std::chrono::system_clock::now();
        auto active = active_session(now);
        auto device_deleted = active;
        device_deleted.device_deleted = true;
        auto globally_revoked = active;
        globally_revoked.global_logout_generation_revoked = true;
        auto token_mismatch = active;
        token_mismatch.access_token.device_id = "OTHERDEVICE";

        WHEN("session state is evaluated")
        {
            auto const active_decision = merovingian::auth::session_is_active(active, now);
            auto const device_deleted_decision = merovingian::auth::session_is_active(device_deleted, now);
            auto const globally_revoked_decision = merovingian::auth::session_is_active(globally_revoked, now);
            auto const mismatch_decision = merovingian::auth::session_is_active(token_mismatch, now);

            THEN("only the active matching device session remains usable")
            {
                REQUIRE(active_decision.active);
                REQUIRE_FALSE(device_deleted_decision.active);
                REQUIRE(device_deleted_decision.reason == "device deleted");
                REQUIRE_FALSE(globally_revoked_decision.active);
                REQUIRE(globally_revoked_decision.reason == "global logout");
                REQUIRE_FALSE(mismatch_decision.active);
                REQUIRE(mismatch_decision.reason == "token subject mismatch");
            }
        }
    }
}

SCENARIO("Client auth audit summaries do not include plaintext access tokens", "[auth][client-api][audit]")
{
    GIVEN("a client auth decision and a plaintext access token outside the audit event")
    {
        auto constexpr plaintext_token = "0123456789abcdefghijklmnopqrstuvwxyz";

        WHEN("an audit event summary is generated")
        {
            auto const event = merovingian::auth::make_client_auth_audit_event(
                merovingian::auth::ClientAuthEndpoint::login, "@alice:example.org", "DEVICE123", false,
                "account locked");
            auto const summary = merovingian::auth::client_auth_audit_summary(event);

            THEN("the summary contains boundary metadata without token material")
            {
                REQUIRE(event.event_type == "client_auth.login");
                REQUIRE(event.outcome == "denied");
                REQUIRE(summary.find("client_auth.login") != std::string::npos);
                REQUIRE(summary.find("@alice:example.org") != std::string::npos);
                REQUIRE(summary.find(plaintext_token) == std::string::npos);
            }
        }
    }
}
