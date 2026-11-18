// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// What a request asks of the legacy authentication API, for `legacy_auth_refusal` (ADR-0801). Each value is one way
// the legacy API lists its logins or issues a user a new session; nothing else is gated by
// `server.oauth.legacy_api_enabled`.
enum class LegacyAuthUse : std::uint8_t
{
    // `GET /login`: the login types.
    login_flows,
    // `POST /login` with any type but `m.login.application_service`.
    user_login,
    // `POST /login` with `m.login.application_service`.
    appservice_login,
    // `POST /register` for a user (no `m.login.application_service`).
    user_registration,
    // `POST /register` with `m.login.application_service` without `"inhibit_login": true`.
    appservice_registration_with_login,
    // `GET /login/sso/redirect` and `GET /login/sso/redirect/{idpId}`.
    sso_redirect,
    // `POST /login/get_token`, and the `m.get_login_token` capability.
    login_token_mint,
};

} // namespace merovingian::homeserver
