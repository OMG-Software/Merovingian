// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpResponse.hpp"

namespace merovingian::homeserver
{

struct ClientServerRuntime;
struct LocalHttpRequest;

// `POST /_merovingian/oauth2/device`, the device authorization endpoint (spec "Device authorization grant"; RFC 8628
// section 3.1; plan P11; ADR-0804). The dispatcher has matched the path and the method and checked that
// `server.oauth.enabled` and `server.oauth.device_grant_enabled` are both true.
//
// Read as the token endpoint reads its body: `application/x-www-form-urlencoded` (`invalid_request` otherwise), parsed
// with core::FormFields, and a `client_secret` or `Authorization: Basic` refused (`invalid_client`). Then `client_id`
// (`invalid_request` when missing), a registered client (`invalid_client`) that lists the device code grant
// (`unauthorized_client`), and `scope` (oauth::parse_scope; `invalid_scope`). A 200 JSON answer holds `device_code`,
// `user_code` (`XXXX-XXXX`), `verification_uri` (the link page), `verification_uri_complete` (with `user_code`),
// `expires_in` (600) and `interval` (5). A full store is 503 `temporarily_unavailable`; a failed random source 500
// `server_error`. Every answer is an OAuth JSON answer (`oauth_json_response`, `no-store`) and gets the CORS headers.
// Logs `oauth.device.started` with the client ID; never the device code or the user code.
[[nodiscard]] auto handle_oauth_device_authorization(ClientServerRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;

} // namespace merovingian::homeserver
