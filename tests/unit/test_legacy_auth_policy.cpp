// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `legacy_auth_refusal`, the one decision on whether the legacy authentication API serves a use (plan P9, ADR-0801),
// and `legacy_login_hand_off_enabled` (plan P10, ADR-0802).

#include "merovingian/config/OAuthConfig.hpp"
#include "merovingian/homeserver/LegacyAuthPolicy.hpp"
#include "merovingian/homeserver/LegacyAuthUse.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string_view>

namespace
{

using merovingian::homeserver::LegacyAuthUse;

[[nodiscard]] auto oauth_config(bool enabled, bool legacy) -> merovingian::config::OAuthConfig
{
    auto oauth = merovingian::config::OAuthConfig{};
    oauth.enabled = enabled;
    oauth.legacy_api_enabled = legacy;
    return oauth;
}

} // namespace

SCENARIO("The legacy API serves every use while legacy_api_enabled is true", "[oauth][legacy-api]")
{
    GIVEN("a configuration with the legacy API on, the OAuth 2.0 API on or off")
    {
        auto const oauth = oauth_config(GENERATE(false, true), true);
        auto const use =
            GENERATE(LegacyAuthUse::login_flows, LegacyAuthUse::user_login, LegacyAuthUse::appservice_login,
                     LegacyAuthUse::user_registration, LegacyAuthUse::appservice_registration_with_login,
                     LegacyAuthUse::sso_redirect, LegacyAuthUse::login_token_mint);

        WHEN("a use is judged")
        {
            auto const refusal = merovingian::homeserver::legacy_auth_refusal(oauth, use);

            THEN("nothing is refused")
            {
                REQUIRE_FALSE(refusal.has_value());
            }
        }
    }
}

SCENARIO("With legacy_api_enabled false each use gets the spec's answer", "[oauth][legacy-api]")
{
    GIVEN("a configuration with the OAuth 2.0 API on and the legacy API off")
    {
        auto const oauth = oauth_config(true, false);

        WHEN("an application service logs in, or registers without inhibit_login")
        {
            auto const use =
                GENERATE(LegacyAuthUse::appservice_login, LegacyAuthUse::appservice_registration_with_login);
            auto const refusal = merovingian::homeserver::legacy_auth_refusal(oauth, use);

            THEN("it is 400 M_APPSERVICE_LOGIN_UNSUPPORTED")
            {
                REQUIRE(refusal.has_value());
                CHECK(refusal->status == 400U);
                CHECK(refusal->errcode == std::string_view{"M_APPSERVICE_LOGIN_UNSUPPORTED"});
            }
        }

        WHEN("a user registers")
        {
            auto const refusal = merovingian::homeserver::legacy_auth_refusal(oauth, LegacyAuthUse::user_registration);

            THEN("it is 403 M_FORBIDDEN")
            {
                REQUIRE(refusal.has_value());
                CHECK(refusal->status == 403U);
                CHECK(refusal->errcode == std::string_view{"M_FORBIDDEN"});
            }
        }

        WHEN("the login types are read, a user logs in, the SSO redirect is followed or a login token is minted")
        {
            auto const use = GENERATE(LegacyAuthUse::login_flows, LegacyAuthUse::user_login,
                                      LegacyAuthUse::sso_redirect, LegacyAuthUse::login_token_mint);
            auto const refusal = merovingian::homeserver::legacy_auth_refusal(oauth, use);

            THEN("it is 404 M_UNRECOGNIZED")
            {
                REQUIRE(refusal.has_value());
                CHECK(refusal->status == 404U);
                CHECK(refusal->errcode == std::string_view{"M_UNRECOGNIZED"});
            }
        }
    }
}

SCENARIO("The legacy login hand-off runs only with both APIs on", "[oauth][legacy-api][hand-off]")
{
    GIVEN("each combination of the two switches")
    {
        auto const enabled = GENERATE(false, true);
        auto const legacy = GENERATE(false, true);

        WHEN("the hand-off is asked about")
        {
            auto const hand_off = merovingian::homeserver::legacy_login_hand_off_enabled(oauth_config(enabled, legacy));

            THEN("it is on only when both are on")
            {
                REQUIRE(hand_off == (enabled && legacy));
            }
        }
    }
}
