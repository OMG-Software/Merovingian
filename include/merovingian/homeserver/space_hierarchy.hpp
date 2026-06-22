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
};

struct SpaceHierarchyResult final
{
    std::uint16_t status{200U};
    std::string body{};
};

// Client-Server API: GET /_matrix/client/v1/rooms/{roomId}/hierarchy
// Spec: Matrix v1.18 Client-Server API §Spaces / Discovering rooms within spaces
[[nodiscard]] auto handle_client_space_hierarchy(HomeserverRuntime& runtime, std::string_view user_id,
                                                 SpaceHierarchyRequest const& request) -> SpaceHierarchyResult;

// Server-Server API: GET /_matrix/federation/v1/hierarchy/{roomId}
// Returns the canonical-JSON response body for the requesting server, or an
// empty string when the room is unknown or not viewable over federation.
[[nodiscard]] auto build_federation_space_hierarchy_response(HomeserverRuntime const& runtime,
                                                             std::string_view room_id,
                                                             bool suggested_only) -> std::string;

} // namespace merovingian::homeserver
