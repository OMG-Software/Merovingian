// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::config
{

// CS8 (ADR-0548): the `m.login.token` login that `POST /_matrix/client/v1/login/get_token` mints. A login token
// hands a full session to another device, so the whole feature is off until the operator turns it on. Off:
// get_token is `404 M_UNRECOGNIZED`, `GET /login` offers no flow for it that this server mints (an SSO login token
// is a separate feature), and the `m.get_login_token` capability reports `enabled: false`.
struct LoginTokenSecurityConfig final
{
    bool enabled{false};
};

} // namespace merovingian::config
