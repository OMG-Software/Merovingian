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
// RFC 6749 section 4.1.2.1: the server cannot take the request now (the client registration cap, ADR-0780) or failed
// in a way the client cannot fix.
inline constexpr std::string_view error_temporarily_unavailable = "temporarily_unavailable";
inline constexpr std::string_view error_server_error = "server_error";
// RFC 6749 section 4.1.2.1, sent only in a redirect from the authorisation endpoint: a `response_type` other than
// `code`, a client not registered for the authorization code grant, and a user who denied the request.
inline constexpr std::string_view error_unsupported_response_type = "unsupported_response_type";
inline constexpr std::string_view error_unauthorized_client = "unauthorized_client";
inline constexpr std::string_view error_access_denied = "access_denied";
// OpenID Connect Core 1.0 section 3.1.2.6: `prompt=none`, which this server cannot honour because every authorisation
// asks for the password (ADR-0787).
inline constexpr std::string_view error_login_required = "login_required";

} // namespace merovingian::oauth
