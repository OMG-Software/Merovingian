// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpResponse.hpp"

namespace merovingian::homeserver
{

struct ClientServerRuntime;
struct LocalHttpRequest;

// `POST /_merovingian/oauth2/revoke` (spec "Token revocation"; RFC 7009; ADR-0795). The dispatcher has matched the
// path and the method and checked that `server.oauth.enabled` is true.
//
// The body is `application/x-www-form-urlencoded` read with core::FormFields: another type, an unreadable body or a
// missing `token` is 400 `invalid_request`. As at the token endpoint, a `client_secret` field is 400 `invalid_client`
// and `Authorization: Basic` credentials 401 `invalid_client`. `token_type_hint` is ignored, whatever its value (RFC
// 7009 section 2.1 lets the server search every kind of token); so are `client_id` and any other field.
//
// The token is looked up as an access token and as a refresh token (revocable_session_of_token). No session: 200 with
// an empty body (RFC 7009 section 2.2: an invalid token is not an error). A session, OAuth or legacy, whoever sent the
// request: it is ended as POST /logout ends it (end_device_session_and_announce: both tokens revoked, the device and
// its `oauth_sessions` row deleted, the deletion announced), audited `oauth.session.revoked`, then 200 with an empty
// body; 500 `server_error` when the revocation could not be stored. The token itself is the proof of possession, so
// there is no case for the spec's 401.
//
// Requires runtime.homeserver.mutex held; nothing here releases it. Never logs the token.
[[nodiscard]] auto handle_oauth_revoke(ClientServerRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;

} // namespace merovingian::homeserver
