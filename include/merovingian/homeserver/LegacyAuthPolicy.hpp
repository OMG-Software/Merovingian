// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/OAuthConfig.hpp"
#include "merovingian/homeserver/LegacyAuthRefusal.hpp"
#include "merovingian/homeserver/LegacyAuthUse.hpp"

#include <optional>

namespace merovingian::homeserver
{

// The one decision on whether the legacy authentication API serves `use` (plan P9, ADR-0813, ADR-0801). Every route
// that lists the legacy logins or issues a user a new session asks it, before it reads anything else from the request;
// never test `legacy_api_enabled` in a route.
//
// nullopt (served as before) while `oauth.legacy_api_enabled` is true, whatever `oauth.enabled` says. With it false:
//
//  - appservice_login, appservice_registration_with_login: 400 `M_APPSERVICE_LOGIN_UNSUPPORTED` (spec `POST /login`
//    `m.login.application_service`, and `POST /register`, both "MUST");
//  - user_registration: 403 `M_FORBIDDEN` (spec `POST /register` 403: "registration is generally not supported");
//  - login_flows, user_login, sso_redirect, login_token_mint: 404 `M_UNRECOGNIZED` (spec `GET /login` 404 and
//    "Authentication API discovery"; the others have no answer of their own, so they answer as an absent endpoint).
//
// Sessions already issued, `/refresh`, `/logout`, User-Interactive Authentication and every other endpoint are not
// uses: they carry on (P9).
[[nodiscard]] auto legacy_auth_refusal(config::OAuthConfig const& oauth, LegacyAuthUse use)
    -> std::optional<LegacyAuthRefusal>;

// Whether the legacy SSO redirect hands the browser to the built-in sign-in pages and back with a login token (plan
// P10, ADR-0802): both the OAuth 2.0 API and the legacy API on. `GET /login` then offers `m.login.sso` with
// `oauth_aware_preferred`.
[[nodiscard]] auto legacy_login_hand_off_enabled(config::OAuthConfig const& oauth) noexcept -> bool;

} // namespace merovingian::homeserver
