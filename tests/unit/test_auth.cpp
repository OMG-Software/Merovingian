// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/auth/identity.hpp>
#include <merovingian/auth/token.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>

SCENARIO("Auth identity validators enforce Matrix-shaped identifiers", "[auth]")
{
    GIVEN("valid and invalid Matrix identity strings")
    {
        auto constexpr valid_user = "@alice:example.org";
        auto constexpr invalid_user = "alice:example.org";
        auto constexpr valid_device = "DEVICE123";
        auto constexpr invalid_device = "DEVICE 123";

        WHEN("identity values are validated")
        {
            auto const valid_user_result = merovingian::auth::user_id_is_valid(valid_user);
            auto const invalid_user_result = merovingian::auth::user_id_is_valid(invalid_user);
            auto const valid_device_result = merovingian::auth::device_id_is_valid(valid_device);
            auto const invalid_device_result = merovingian::auth::device_id_is_valid(invalid_device);

            THEN("only Matrix-shaped values are accepted")
            {
                REQUIRE(valid_user_result);
                REQUIRE_FALSE(invalid_user_result);
                REQUIRE(valid_device_result);
                REQUIRE_FALSE(invalid_device_result);
            }
        }
    }
}

SCENARIO("Auth login policy blocks locked and suspended accounts", "[auth]")
{
    GIVEN("active, locked, and suspended users")
    {
        auto active = merovingian::auth::UserIdentity{"@alice:example.org"};
        auto locked = merovingian::auth::UserIdentity{"@bob:example.org", merovingian::auth::AccountState::locked};
        auto suspended = merovingian::auth::UserIdentity{"@carol:example.org", merovingian::auth::AccountState::suspended};

        WHEN("login policy is evaluated")
        {
            auto const active_decision = merovingian::auth::login_policy(active);
            auto const locked_decision = merovingian::auth::login_policy(locked);
            auto const suspended_decision = merovingian::auth::login_policy(suspended);

            THEN("only the active account can proceed")
            {
                REQUIRE(active_decision.allowed);
                REQUIRE_FALSE(locked_decision.allowed);
                REQUIRE_FALSE(suspended_decision.allowed);
                REQUIRE(locked_decision.reason == "account locked");
                REQUIRE(suspended_decision.reason == "account suspended");
            }
        }
    }
}

SCENARIO("Auth password policy requires a hardened minimum shape", "[auth]")
{
    GIVEN("weak and stronger password candidates")
    {
        auto constexpr weak_password = "password";
        auto constexpr stronger_password = "CorrectHorse7!";

        WHEN("password policy is evaluated")
        {
            auto const weak_accepted = merovingian::auth::password_is_acceptable(weak_password);
            auto const stronger_accepted = merovingian::auth::password_is_acceptable(stronger_password);

            THEN("weak passwords are rejected")
            {
                REQUIRE_FALSE(weak_accepted);
                REQUIRE(stronger_accepted);
            }
        }
    }
}

SCENARIO("Auth token policy accepts only active hashed tokens", "[auth][tokens]")
{
    GIVEN("an active token and revoked or expired variants")
    {
        auto const now = std::chrono::system_clock::now();
        auto active = merovingian::auth::AccessTokenRecord{
            "@alice:example.org",
            "DEVICE123",
            merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"},
            now + std::chrono::hours{1},
            false,
        };
        auto revoked = active;
        revoked.revoked = true;
        auto expired = active;
        expired.expires_at = now - std::chrono::seconds{1};

        WHEN("token policy is evaluated")
        {
            auto const active_decision = merovingian::auth::token_is_active(active, now);
            auto const revoked_decision = merovingian::auth::token_is_active(revoked, now);
            auto const expired_decision = merovingian::auth::token_is_active(expired, now);

            THEN("only the active hashed token is accepted")
            {
                REQUIRE(active_decision.accepted);
                REQUIRE_FALSE(revoked_decision.accepted);
                REQUIRE_FALSE(expired_decision.accepted);
                REQUIRE(revoked_decision.reason == "token revoked");
                REQUIRE(expired_decision.reason == "token expired");
            }
        }
    }
}

SCENARIO("Auth token helpers avoid plaintext token disclosure", "[auth][tokens]")
{
    GIVEN("a plaintext token secret")
    {
        auto constexpr token_secret = "0123456789abcdefghijklmnopqrstuvwxyz";

        WHEN("the token is redacted and compared")
        {
            auto const redacted = merovingian::auth::redacted_token_for_log(token_secret);
            auto const matching = merovingian::auth::constant_time_equal(token_secret, token_secret);
            auto const different = merovingian::auth::constant_time_equal(token_secret, "different-token-secret-000000000000");

            THEN("logs contain only metadata and comparison remains exact")
            {
                REQUIRE(redacted.find(token_secret) == std::string::npos);
                REQUIRE(redacted == "[redacted-token:length=36]");
                REQUIRE(matching);
                REQUIRE_FALSE(different);
            }
        }
    }
}
