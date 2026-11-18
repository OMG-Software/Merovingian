// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"

#include <cstdint>
#include <string_view>

namespace merovingian::homeserver
{

struct ClientServerRuntime;
struct LocalHttpRequest;

// The cookie of an account-page session (ADR-0796): `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`, for the fixed
// lifetime of the session. Strict, unlike the authorisation cookie: nothing reaches these pages from another site with
// a reason to carry it, so a link from elsewhere opens the sign-in form.
inline constexpr auto account_cookie_name = std::string_view{"__Host-mv-account"};
inline constexpr auto account_cookie_max_age_seconds = std::uint32_t{900U};

// `GET` and `POST /_merovingian/account` (spec "Account management"; plan P6, phase 8; ADR-0796 to ADR-0798). The
// dispatcher has matched the path and the method and checked that `server.oauth.enabled` is true. `guard` is the
// dispatcher's lock on runtime.mutex, released only by a deactivation's identity-server unbinds. Every answer is an
// HTML page or a redirect marked `LocalHttpResponse::page`, with `oauth::page_headers()`, so it carries no CORS header.
//
// `GET` reads `action` (one of the six spec actions; anything else shows the overview) and, for the two device actions,
// `device_id` (only one `auth::device_id_is_valid` accepts). Without a live session it shows the sign-in form, which
// carries both in hidden fields; with one, the page for the action.
//
// `POST` is refused unless `oauth::form_post_origin_is_accepted` accepts its `Origin` and `Sec-Fetch-Site`, before
// anything is read. The sign-in form (`action=sign_in`) needs nothing else; it verifies the password with
// `verify_password_login` (the throttle `/login` uses) and always issues a fresh session, answering 303 to the page
// asked for. Every other form needs the session cookie and the session's form token, compared in constant time. Each
// action calls the service function the client API calls: `delete_device_and_announce`,
// `change_password_on_account_page` (the core of the password reset), `deactivate_user_account` with
// `finish_account_deactivation`. A session whose user no longer passes `account_sign_in_gate` ends at once.
//
// Logs `user_id` and the action only, never a password, a cookie, a form token or the query.
[[nodiscard]] auto handle_account_page(ClientServerRuntime& rt, RuntimeLock& guard, LocalHttpRequest const& request)
    -> LocalHttpResponse;

} // namespace merovingian::homeserver
