// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/SpaceHierarchyRequest.hpp"
#include "merovingian/homeserver/SpaceHierarchyResult.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

// The most rooms one GET /hierarchy request looks at, whatever the size of the space and the page
// asked for (ADR-0345). A room beyond it is not listed and the answer carries no `next_batch` for it.
inline constexpr std::size_t max_hierarchy_walk_visits = 4096U;

// Client-Server API: GET /_matrix/client/v1/rooms/{roomId}/hierarchy
// Spec: Matrix v1.19 Client-Server API §Spaces / Discovering rooms within spaces
[[nodiscard]] auto handle_client_space_hierarchy(HomeserverRuntime& runtime, std::string_view user_id,
                                                 SpaceHierarchyRequest const& request) -> SpaceHierarchyResult;

// Client-Server API: GET /_matrix/client/v1/room_summary/{roomIdOrAlias}
// Spec: Matrix v1.19 Client-Server API, "Room Summaries" (added in v1.15).
//
// `user_id` is empty for an unauthenticated caller. A room this server holds state for is answered
// from that state, whatever `via` says. A room it holds no state for is asked for over federation
// (`GET /_matrix/federation/v1/hierarchy/{roomId}`, the `room` chunk) from at most 3 of the `via`
// servers (grammar-checked by the caller, this server's own name skipped), under one ADR-0079
// slot and one `OutboundDeadline`, and shown only if the remote summary's own `join_rule`,
// `world_readable` and `allowed_room_ids` let the caller see it. With no slot the answer is
// 429 (`retry_after_ms` set) at once. The caller holds `runtime.mutex`; it is released only around
// each network call. An alias is resolved only in this server's directory.
//
// An unauthenticated caller sees a room whose join rule is `public`, `knock` or `knock_restricted`
// or whose history visibility is `world_readable`; any other room, and a room that does not exist,
// is refused alike with 401 `M_MISSING_TOKEN`. An authenticated caller sees what the hierarchy
// would show them, plus a room they have knocked on; any other room, and a room that does not
// exist, is 404 `M_NOT_FOUND`.
[[nodiscard]] auto handle_client_room_summary(HomeserverRuntime& runtime, std::string_view user_id,
                                              std::string_view room_id_or_alias, std::vector<std::string> const& via,
                                              std::string const& client_key) -> SpaceHierarchyResult;

// Server-Server API: GET /_matrix/federation/v1/hierarchy/{roomId}
// Returns the canonical-JSON response body for the requesting server `origin`,
// or an empty string when the room is unknown or `origin` could not peek or
// join it. A restricted room counts as joinable by `origin` only while a user
// of `origin` is joined to one of the rooms its join rule names.
[[nodiscard]] auto build_federation_space_hierarchy_response(HomeserverRuntime const& runtime, std::string_view room_id,
                                                             bool suggested_only, std::string_view origin)
    -> std::string;

} // namespace merovingian::homeserver
