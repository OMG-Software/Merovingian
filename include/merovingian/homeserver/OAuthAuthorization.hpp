// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace merovingian::homeserver
{

struct ClientServerRuntime;
struct LocalHttpRequest;

// The cookie that binds a pending authorisation to its browser (ADR-0788): `__Host-`, `Secure`, `HttpOnly`,
// `SameSite=Lax`, for the lifetime of a pending authorisation.
inline constexpr auto oauth_browser_cookie_name = std::string_view{"__Host-mv-oauth"};
inline constexpr auto oauth_browser_cookie_max_age_seconds = std::uint32_t{600U};
// The longest `state` returned to a client: a client sends a few dozen bytes, and the whole answer must fit in a
// browser's address bar.
inline constexpr auto max_oauth_state_bytes = std::size_t{2048U};
// The longest `login_hint` read: a user ID is at most 255 bytes (spec "User Identifiers").
inline constexpr auto max_oauth_login_hint_bytes = std::size_t{255U};

// `GET` and `POST /_merovingian/oauth2/authorize` (spec "Authorisation code grant", "Login flow", "User registration";
// RFC 6749 section 4.1; plan "The authorisation flow"; ADR-0787 to ADR-0789). The dispatcher has matched the path and
// the method and checked that `server.oauth.enabled` is true. Every answer is an HTML page or a redirect, marked
// `LocalHttpResponse::page`, so it carries no CORS header and is never rewritten.
//
// `GET`, the authorisation request, read from the query with core::FormFields (a parameter sent twice refuses it):
//
//  1. An unreadable query, a missing or unregistered `client_id`, a missing `redirect_uri`, or one
//     oauth::match_redirect_uri does not find among the client's registered URIs: a 400 error page and no redirect,
//     since no address has been validated.
//  2. From here a refusal is a 302 redirect to the matched URI with `error`, a fixed `error_description` and `state`
//     (unless it is over max_oauth_state_bytes), in the query or the fragment as `response_mode` says (the query when
//     it is absent or invalid). Checked in order: `state`; `response_type` (`code`); the client registered for
//     `authorization_code`; `response_mode` (`query` or `fragment`); PKCE (`S256` and a valid challenge); `scope`
//     (oauth::parse_scope); `prompt` (absent, `consent`, `login`, `select_account`, `create`; `none` is
//     `login_required`).
//  3. A pending authorisation is created, bound to the browser cookie (reused when the request carries a well-formed
//     one, else fresh), and the login page (the registration page for `prompt=create` when registration is enabled)
//     is answered 200 with the cookie. A store refusal is a 503 page.
//
// `POST`, a form of those pages: refused with a 403 page unless oauth::form_post_origin_is_accepted accepts its
// `Origin` and `Sec-Fetch-Site`, with a 400 page unless it is `application/x-www-form-urlencoded` that FormFields
// reads, and with the 400 expired page unless its `pending` field and the cookie name a live entry. Then `action`:
// `login` (verify_password_login), `register` (create_local_account), `show_login`, `show_register`, `approve` (an
// authorization code, 303 to the client) or `deny` (303 with `access_denied`).
//
// Requires runtime.homeserver.mutex held and published through a RequestLockScope: the password check and the account
// creation release it around Argon2id, and everything read before them is read again after. Never logs the query, the
// state, the challenge, the code, the cookie, the pending identifier or a password.
[[nodiscard]] auto handle_oauth_authorize(ClientServerRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;

// How long a login token minted by the hand-off can be redeemed. The spec recommends around five seconds for an SSO
// login token ("Client login via SSO"); 30 seconds leaves room for a mobile operating system to switch to the
// application, and the token is still single use (ADR-0802).
inline constexpr auto hand_off_login_token_lifetime_ms = std::uint32_t{30000U};

// `GET /_matrix/client/v3/login/sso/redirect` and `/{idpId}` with the OAuth 2.0 API and the legacy API both on (spec
// "OAuth 2.0 aware clients"; plan P10; ADR-0802). The dispatcher has checked both keys. `redirectUrl` (required) must
// pass oauth::hand_off_redirect_target with `server.oauth.hand_off_redirect_allowlist`, else a 400 page with no
// redirect. `action=register` starts on the registration page; any other `action`, or none, on the login page. The
// identity provider ID is not read. A pending authorisation of kind `login_token_hand_off` is created exactly as the
// authorisation request does, and the forms post to `/_merovingian/oauth2/authorize`: after the password, a
// confirmation page names the account and the destination; `approve` mints a login token into
// ClientServerRuntime::login_tokens (hand_off_login_token_lifetime_ms) and answers 303 to the address
// oauth::hand_off_return_address makes; `deny` answers a page and redirects nowhere. Same lock rules as
// handle_oauth_authorize. Never logs the address, the token, the cookie or the pending identifier.
[[nodiscard]] auto handle_login_hand_off(ClientServerRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;

} // namespace merovingian::homeserver
