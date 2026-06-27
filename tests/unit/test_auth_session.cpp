// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/session.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <catch2/catch_test_macros.hpp>

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

        // Tests that ran before us may have left the audit sink
        // installed against a `LocalDatabase` that is now out of
        // scope. The auth test never exercises the audit log, so
        // reset the sink to the process-wide default (a no-op) —
        // the `local_audit_sink` early-returns on a null database
        // anyway, but resetting makes the intent explicit. With
        // `HomeserverRuntime` owning the audit-sink install via its
        // `audit_sink_scope` member, the install is normally cleared
        // on runtime destruction; this call is a belt-and-braces
        // defence for the rare test that constructs a `LocalDatabase`
        // by some other path (e.g. a direct call to
        // `bootstrap_local_database`).
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

SCENARIO("Session liveness rejects expired tokens even when not revoked", "[auth][client-api][tokens][expiry]")
{
    GIVEN("an active session and an expired-but-not-revoked variant")
    {
        auto const now = std::chrono::system_clock::now();
        auto active = active_session(now);
        auto expired = active;
        // Same identity and hash, not revoked — only the TTL has elapsed.
        expired.access_token.expires_at = now - std::chrono::hours{1};
        auto non_expiring = active;
        non_expiring.access_token.expires_at = std::chrono::system_clock::time_point::max();

        WHEN("session liveness is evaluated against the current time")
        {
            auto const active_decision = merovingian::auth::session_is_active(active, now);
            auto const expired_decision = merovingian::auth::session_is_active(expired, now);
            auto const non_expiring_decision = merovingian::auth::session_is_active(non_expiring, now);

            THEN("only the unexpired sessions remain usable")
            {
                REQUIRE(active_decision.active);
                REQUIRE_FALSE(expired_decision.active);
                REQUIRE(expired_decision.reason == "token expired");
                REQUIRE(non_expiring_decision.active);
            }
        }
    }
}

SCENARIO("Expired and revoked tokens yield distinct rejection reasons for soft-logout routing",
         "[auth][tokens][expiry][security]")
{
    // access_token_is_soft_logout() distinguishes "found-but-expired" (soft logout:
    // use refresh token) from "found-but-revoked" (hard logout: clear session).
    // This scenario verifies the underlying token_is_active policy produces the
    // correct reason string for each case so that distinction remains reliable.
    GIVEN("an expired-but-not-revoked token and a revoked-but-not-expired token")
    {
        auto const now = std::chrono::system_clock::now();

        auto expired_token = merovingian::auth::AccessTokenRecord{
            "@alice:example.org",
            "DEVICE123",
            merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"},
            now - std::chrono::hours{1},
            false,
        };

        auto revoked_token = merovingian::auth::AccessTokenRecord{
            "@alice:example.org",
            "DEVICE123",
            merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"},
            now + std::chrono::hours{1},
            true,
        };

        WHEN("each token is checked for activity")
        {
            auto const expired_decision = merovingian::auth::token_is_active(expired_token, now);
            auto const revoked_decision = merovingian::auth::token_is_active(revoked_token, now);

            THEN("expired yields 'token expired' and revoked yields 'token revoked'")
            {
                REQUIRE_FALSE(expired_decision.accepted);
                REQUIRE(expired_decision.reason == "token expired");

                REQUIRE_FALSE(revoked_decision.accepted);
                REQUIRE(revoked_decision.reason == "token revoked");

                // The two reasons must be distinct: soft_logout routing depends on
                // "token expired" meaning the token can be refreshed, not revoked.
                REQUIRE(expired_decision.reason != revoked_decision.reason);
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
