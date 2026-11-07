// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <optional>
#include <string>

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

} // namespace merovingian::homeserver
