// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/StateEventReference.hpp"
#include "merovingian/events/StateGroup.hpp"
#include "merovingian/events/StateResolutionLimits.hpp"

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::events
{

// Fetches a single event (by id) that is not present in any submitted state
// group, so the resolver can walk auth_events chains past the two forked
// state snapshots it was handed. Returns nullopt when the event is unknown
// to the caller (e.g. not yet persisted). The resolver treats any such miss
// encountered while walking an auth chain as fatal to the whole resolution
// (fail closed) rather than proceeding with a partial chain — see
// resolve_state_v2.
// Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md — Definitions ("Auth
// chain", "Auth difference").
using EventLookupFn = std::function<std::optional<StateEventReference>(std::string_view event_id)>;

struct StateResolutionRequest final
{
    std::string room_version{};
    std::vector<StateGroup> state_groups{};
    EventLookupFn event_lookup{};
    // Required for room v12 (MSC4291, StateResolutionAlgorithm::v2_1)
    // resolutions: the m.room.create event is implicit in the room ID
    // (rooms/v12.md rule 2 — "!" + the create event's own reference hash),
    // and resolve_state_v2 derives the create event's id from this field
    // and fetches it through `event_lookup` (or a submitted state group)
    // to seed the iterative auth checks' otherwise-empty starting map —
    // see resolve_state_v2's implementation comment. Left empty for a
    // non-v12 resolution, which does not need it. A v12 resolution whose
    // derived create event cannot be fetched fails closed (ADR-0063)
    // rather than falling back to the state groups' own (spoofable)
    // unconflicted agreement — but a v12 resolution given no `room_id` at
    // all still falls back to that unconflicted agreement, for callers
    // (this module's own unit tests) using synthetic event ids that do not
    // follow the MSC4291 room_id convention. Every real production caller
    // (compute_state_before, recompute_current_state) always supplies
    // `room_id`, so that fallback is never reachable from untrusted
    // federation input.
    std::string room_id{};
    // Runtime policy, copied from the homeserver configuration by production
    // callers. Defaults retain the standalone helper API's historical use.
    StateResolutionLimits limits{};
};

} // namespace merovingian::events
