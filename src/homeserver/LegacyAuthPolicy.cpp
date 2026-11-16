// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/LegacyAuthPolicy.hpp"

namespace merovingian::homeserver
{

auto legacy_auth_refusal(config::OAuthConfig const& oauth, LegacyAuthUse use) -> std::optional<LegacyAuthRefusal>
{
    if (oauth.legacy_api_enabled)
    {
        return std::nullopt;
    }
    switch (use)
    {
    case LegacyAuthUse::appservice_login:
        return LegacyAuthRefusal{400U, "M_APPSERVICE_LOGIN_UNSUPPORTED",
                                 "this server does not log in through the legacy authentication API"};
    case LegacyAuthUse::appservice_registration_with_login:
        return LegacyAuthRefusal{400U, "M_APPSERVICE_LOGIN_UNSUPPORTED",
                                 "this server does not log in through the legacy authentication API; set "
                                 "inhibit_login to true"};
    case LegacyAuthUse::user_registration:
        return LegacyAuthRefusal{403U, "M_FORBIDDEN",
                                 "registration through the legacy authentication API is not supported; register "
                                 "through the OAuth 2.0 API"};
    case LegacyAuthUse::login_flows:
    case LegacyAuthUse::user_login:
    case LegacyAuthUse::sso_redirect:
    case LegacyAuthUse::login_token_mint:
        break;
    }
    return LegacyAuthRefusal{};
}

auto legacy_login_hand_off_enabled(config::OAuthConfig const& oauth) noexcept -> bool
{
    return oauth.enabled && oauth.legacy_api_enabled;
}

} // namespace merovingian::homeserver
