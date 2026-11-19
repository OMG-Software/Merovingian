// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::sync
{

// The sticky events delivered per room per response unless the request asks for fewer (MSC4480, ADR-0855). A larger
// `limit` is lowered to this.
inline constexpr std::uint32_t max_sticky_events_per_room_response = 100U;

// MSC4480 extensions.sticky_events (also read as extensions["org.matrix.msc4354.sticky_events"]).
struct ExtStickyEventsRequest final
{
    bool enabled{false};
    // At most this many events per room per response; 100 by default and at most.
    std::uint32_t limit{max_sticky_events_per_room_response};
    // The request gave a `limit` below 1: refused by `sliding_sync_request_limit_violation` (400 M_INVALID_PARAM).
    bool limit_refused{false};
    // MSC4508's scope (`sync::extension_scope_rooms`): the lists and room subscriptions the extension applies to, by
    // list key and room ID. Absent is every one; an empty array is none; "*" is every one (the older MSC3575 form).
    std::optional<std::vector<std::string>> lists{};
    std::optional<std::vector<std::string>> rooms{};
    // Which names the request used; the response is written under each of them (ADR-0853).
    bool used_stable_name{false};
    bool used_unstable_name{false};
};

} // namespace merovingian::sync
