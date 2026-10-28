// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/homeserver/runtime.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct SpaceHierarchyRequest final
{
    std::string room_id{};
    std::optional<std::string> from{};
    std::optional<std::size_t> limit{};
    std::optional<std::size_t> max_depth{};
    bool suggested_only{false};
    // Client-side operational page ceiling. Federation hierarchy responses
    // use their separate unpaginated response shape and do not consume this.
    std::size_t max_rooms{1000U};
    // The caller's address as the rate limiter keys it (rate_limit_client_key).
    // A child room this server does not hold is asked for over federation, which
    // takes a slot in the client-outbound budget under this key (ADR-0079).
    std::string client_key{};
};

struct SpaceHierarchyResult final
{
    std::uint16_t status{200U};
    std::string body{};
    // Set with status 429: the delay to advertise as `retry_after_ms`.
    std::uint32_t retry_after_ms{0U};
};

// Client-Server API: GET /_matrix/client/v1/rooms/{roomId}/hierarchy
// Spec: Matrix v1.19 Client-Server API §Spaces / Discovering rooms within spaces
[[nodiscard]] auto handle_client_space_hierarchy(HomeserverRuntime& runtime, std::string_view user_id,
                                                 SpaceHierarchyRequest const& request) -> SpaceHierarchyResult;

// Server-Server API: GET /_matrix/federation/v1/hierarchy/{roomId}
// Returns the canonical-JSON response body for the requesting server `origin`,
// or an empty string when the room is unknown or `origin` could not peek or
// join it. A restricted room counts as joinable by `origin` only while a user
// of `origin` is joined to one of the rooms its join rule names.
[[nodiscard]] auto build_federation_space_hierarchy_response(HomeserverRuntime const& runtime, std::string_view room_id,
                                                             bool suggested_only, std::string_view origin)
    -> std::string;

} // namespace merovingian::homeserver
