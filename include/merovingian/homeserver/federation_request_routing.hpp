// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/local_http_router.hpp"

#include <string>

namespace merovingian::homeserver
{

// Extracts the room ID from an inbound federation HTTP request for worker
// shard routing.
//
// Room-scoped federation endpoints embed the room ID in the path (e.g.
// /_matrix/federation/v1/state/{roomId}). PUT /send/{txnId} carries the room
// ID inside the first PDU of the transaction body. Non-room endpoints
// (key server, profile queries, directory queries, etc.) return an empty
// string, which the caller routes to shard 0.
[[nodiscard]] auto federation_worker_room_id_from_request(LocalHttpRequest const& request) -> std::string;

// Returns true when a verified inbound federation request should stay in the
// main process even while the worker pool is active.
[[nodiscard]] auto federation_request_should_bypass_worker(LocalHttpRequest const& request) -> bool;

// Returns true when the request target is exactly `/_matrix/key/v2/server`
// (optionally followed by a query string). The key server endpoint must be
// matched precisely: a substring match would let unrelated paths such as
// `/evil/_matrix/key/v2/server` or `/_matrix/key/v2/server/extra` bypass
// worker routing and federation authorization verification.
[[nodiscard]] auto is_federation_key_server_endpoint(std::string_view target) noexcept -> bool;

// Returns true when the request target is exactly
// `/_matrix/federation/v1/openid/userinfo` (optionally followed by a query
// string carrying `?access_token=...`). Matrix v1.19 SS API §OpenID marks
// this endpoint "Requires authentication: No" -- it is called by arbitrary
// third-party services, not necessarily other homeservers -- so, like the
// key server endpoint above, it must never be routed through the X-Matrix
// signature-required federation dispatch path. Matched precisely for the
// same reason as is_federation_key_server_endpoint: a substring match would
// let an unrelated path bypass authorization verification.
[[nodiscard]] auto is_federation_openid_userinfo_endpoint(std::string_view target) noexcept -> bool;

} // namespace merovingian::homeserver
