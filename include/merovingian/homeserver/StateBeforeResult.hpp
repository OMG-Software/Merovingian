// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStateGroupStateEntry.hpp"
#include "merovingian/database/PersistentStore.hpp"

#include <optional>
#include <string>
#include <vector>

namespace merovingian::homeserver
{

// Result of resolving the state immediately before an event from its
// prev_event_ids.
struct StateBeforeResult final
{
    // False when a prev_event has no recorded state group (an older,
    // pre-Phase-A event, or a genuine gap in our history of the room), or
    // resolution itself failed closed (an unreachable/missing auth-chain
    // event, or the walk cap — see ADR-0063). Either way the caller must not
    // store the event or substitute current state; see
    // federation::PduIngestionStatus::missing_prev_state.
    bool ok{false};
    std::vector<database::PersistentStateGroupStateEntry> state{};
    // Why `ok` is false, for the caller's log; empty when it is true.
    std::string reason{};
    // A stored state group whose full state is exactly `state`, when one is known: the one prev_event's group, the one
    // group every prev_event names, or the group an earlier event with the same distinct prev groups recorded its
    // state before in (ADR-0694). Unset after a fresh resolution, which record_event_state then stores once.
    std::optional<std::string> state_group_id{};
    // After a fresh resolution: the sorted distinct groups resolved and everything else the result depends on, the key
    // under which the group that comes to hold `state` is remembered.
    std::vector<std::string> resolved_group_ids{};
    std::string resolution_context{};
};

} // namespace merovingian::homeserver
