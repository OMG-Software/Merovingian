// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::oauth
{

// The OAuth 2.0 `error` codes this module answers with. They are wire values (RFC 6749 section 5.2, RFC 7591
// section 3.2.2), sent as the `error` member of a JSON body or the `error` parameter of a redirect; an
// OAuthRefusal carries one of them.
inline constexpr std::string_view error_invalid_request = "invalid_request";
inline constexpr std::string_view error_invalid_grant = "invalid_grant";
inline constexpr std::string_view error_invalid_scope = "invalid_scope";
inline constexpr std::string_view error_invalid_redirect_uri = "invalid_redirect_uri";
inline constexpr std::string_view error_invalid_client_metadata = "invalid_client_metadata";
// RFC 6749 section 5.2, from the token and revocation endpoints: client authentication failed (an unknown client, or
// a client that sent a secret this server never issues: every client is public), and a `grant_type` this server does
// not serve.
inline constexpr std::string_view error_invalid_client = "invalid_client";
inline constexpr std::string_view error_unsupported_grant_type = "unsupported_grant_type";
// RFC 6749 section 4.1.2.1: the server cannot take the request now (the client registration cap, ADR-0780) or failed
// in a way the client cannot fix.
inline constexpr std::string_view error_temporarily_unavailable = "temporarily_unavailable";
inline constexpr std::string_view error_server_error = "server_error";
// RFC 6749 section 4.1.2.1: a `response_type` other than `code`, a client not registered for the grant it uses, and a
// user who denied the request. The device code grant also answers the last two in JSON (RFC 8628 section 3.5).
inline constexpr std::string_view error_unsupported_response_type = "unsupported_response_type";
inline constexpr std::string_view error_unauthorized_client = "unauthorized_client";
inline constexpr std::string_view error_access_denied = "access_denied";
// RFC 8628 section 3.5, from the token endpoint's device code grant (ADR-0804): the user has not answered yet; the
// device polled sooner than its interval (which grows by five seconds); the device code is unknown, expired or spent.
inline constexpr std::string_view error_authorization_pending = "authorization_pending";
inline constexpr std::string_view error_slow_down = "slow_down";
inline constexpr std::string_view error_expired_token = "expired_token";
// OpenID Connect Core 1.0 section 3.1.2.6: `prompt=none`, which this server cannot honour because every authorisation
// asks for the password (ADR-0787).
inline constexpr std::string_view error_login_required = "login_required";

} // namespace merovingian::oauth
