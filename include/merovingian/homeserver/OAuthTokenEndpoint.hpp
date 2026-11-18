// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpResponse.hpp"

namespace merovingian::homeserver
{

struct ClientServerRuntime;
struct LocalHttpRequest;

// `POST /_merovingian/oauth2/token` (spec "Token endpoint", "Authorisation code grant", "Refresh token grant";
// RFC 6749 sections 4.1.3, 5 and 6; RFC 7636 section 4.6; ADR-0791 to ADR-0793). The dispatcher has matched the path
// and the method and checked that `server.oauth.enabled` is true. Every answer is built by `oauth_json_response` or
// `oauth_error_response`.
//
// The body is `application/x-www-form-urlencoded` (oauth::api_form_content_type_is_accepted) read with
// core::FormFields: another type, an unreadable body or a repeated parameter is 400 `invalid_request`. Only public
// clients exist: a `client_secret` field is 400 `invalid_client`, client credentials in an `Authorization: Basic`
// header 401 `invalid_client` with `WWW-Authenticate: Basic` (RFC 6749 sections 2.3.1 and 5.2). A missing
// `grant_type` is `invalid_request`, one other than the two below `unsupported_grant_type`.
//
// `authorization_code`, in order: `client_id`, `code`, `redirect_uri` and `code_verifier` present (`invalid_request`);
// the client registered (`invalid_client`) for the `authorization_code` grant (`unauthorized_client`); the verifier
// well formed (`invalid_request`); the code redeemed: unknown is `invalid_grant`, and a replay is `invalid_grant` that
// also ends the session the code produced, if it produced one still held (ADR-0792); then the client ID, the redirect
// URI byte for byte and the PKCE verifier must match (`invalid_grant`, the code stays spent); then
// `account_sign_in_gate` and grant_oauth_session's device checks (`invalid_grant`). A grant writes the device, both
// tokens and the `oauth_sessions` row in one transaction (500 `server_error` with nothing written on failure) and
// answers 200 `{access_token, token_type: "Bearer", expires_in, refresh_token, scope}`.
//
// `refresh_token`: `refresh_token` and `client_id` present (`invalid_request`), the client registered
// (`invalid_client`) for the `refresh_token` grant (`unauthorized_client`), then refresh_local_session with the client
// ID: a token whose device has no `oauth_sessions` row for that client is refused before anything is rotated
// (ADR-0793). A refusal is 400 `invalid_grant`, a storage failure 500 `server_error`. The `scope` parameter is ignored:
// the session keeps the scope it was granted.
//
// Requires runtime.homeserver.mutex held; nothing here releases it. Never logs a code, a verifier or a token.
[[nodiscard]] auto handle_oauth_token(ClientServerRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;

} // namespace merovingian::homeserver
