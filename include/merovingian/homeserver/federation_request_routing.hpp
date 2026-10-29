// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/local_http_router.hpp"

#include <optional>
#include <string>
#include <string_view>

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

// Returns true for room-scoped federation reads that the main process can
// serve authoritatively when the worker's room snapshot is known to be stale.
// Only GET endpoints that consume room state (state, state_ids, backfill,
// get_missing_events, event_auth) qualify; writes must still reach the worker
// because they may trigger main-side relays and side effects.
[[nodiscard]] auto federation_worker_room_read_may_fallback_to_main(LocalHttpRequest const& request) noexcept -> bool;

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

// Returns true when the request target is exactly
// `/_matrix/federation/v1/version` (optionally followed by a query string).
// Matrix v1.19 marks this endpoint as unauthenticated.
[[nodiscard]] auto is_federation_version_endpoint(std::string_view target) noexcept -> bool;

// The `Allow` value for a request that uses a method the path does not serve: the path is one this
// server's federation surface (or `/_matrix/key/v2/server`, the version and the OpenID userinfo
// endpoint) serves, but not with `method`. nullopt when the method is served there, or when the path
// is not served at all. Spec (CS API "Standard error response"): `M_UNRECOGNIZED` is "a 405 HTTP
// status code if the endpoint is implemented, but the incorrect HTTP method is used".
[[nodiscard]] auto federation_unsupported_method_allow(std::string_view method, std::string_view target)
    -> std::optional<std::string>;

// The 405 `M_UNRECOGNIZED` response for such a request, with its `Allow` header.
[[nodiscard]] auto federation_method_not_allowed_response(std::string_view allow) -> LocalHttpResponse;

} // namespace merovingian::homeserver
