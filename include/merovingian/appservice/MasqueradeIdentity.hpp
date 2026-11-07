// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::appservice
{

// Matrix v1.19 Application Service API §"Identity assertion": an appservice
// authenticates client-server requests with its `as_token` and optionally
// asserts a virtual `user_id` (and `device_id`) to act as, via the
// `user_id`/`device_id` query-string parameters. The rest of the
// client-server dispatcher (auth_service.cpp's authenticated_user/
// authenticated_session/authenticated_admin_user, and every deeper handler
// that re-derives identity from a bare `access_token` string) has no access
// to the request's query string, only to `access_token` — so the resolved
// masquerade identity is encoded into an internal token string that
// substitutes for the real `as_token` for the remainder of THIS request's
// dispatch.
//
// This encoding is an internal implementation detail, not a credential:
//   - It is synthesized exactly once, at the top of
//     handle_client_server_request_impl, only AFTER the presented
//     `access_token` has been matched against a registered appservice's
//     `as_token` via constant-time comparison, and only after the
//     asserted user_id has been checked against that appservice's
//     namespaces.
//   - It never appears on the wire (not sent to any client, not logged, not
//     persisted).
//   - The reserved prefix below is checked and rejected at the very top of
//     dispatch for any RAW incoming token: a request that arrives already
//     carrying this shape is never treated as authentic, so an external
//     caller cannot skip the as_token check by directly guessing/crafting
//     this format.
struct MasqueradeIdentity final
{
    std::string appservice_id{};
    std::string user_id{};
    std::string device_id{}; // empty = no device asserted
};

} // namespace merovingian::appservice
