// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace merovingian::federation
{

// The state of `room_id` BEFORE `at_event_id`, as this server recorded it (ADR-0363, F-25, F-26).
struct StateAtEvent final
{
    // False when the event is unknown, is in another room, or this server has no state it can serve
    // whole for it: an outlier, a missing or broken state-group chain, a group naming an event this
    // store lacks or a rejected one, a resolution over its budget (ADR-0365). The federation
    // endpoints answer 404. Nothing is ever substituted from a walk of the graph or the current state.
    bool known{false};
    // The state event IDs, in no order. Empty with `known` true only for the room's first event.
    std::vector<std::string> event_ids{};
    // What the answer cost, so a test can show that it does not grow with the room's history: the
    // stored events whose JSON was parsed here (the requested event's, once), and whether the state
    // of several prev_events had to be resolved (which parses the entries of their groups, nothing else).
    std::size_t events_parsed{0U};
    bool resolved{false};
};

} // namespace merovingian::federation
