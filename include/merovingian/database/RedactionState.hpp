// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::database
{

// CSAZ-11. In-memory bookkeeping about m.room.redaction events, derived from `events`: rebuilt by
// rebuild_redaction_state after hydration and kept current as events are stored. Never persisted
// in a table of its own; what is durable is the redacted JSON of the target event itself.
struct RedactionState final
{
    // Target event ID -> IDs of the redaction events that name it (in `redacts` at the top level
    // or in `content`, whichever the event has; the room version decides which one counts).
    std::unordered_map<std::string, std::vector<std::string>> by_target{};
    // Redaction events that have not been applied: unjudged, waiting for their target, or not
    // allowed to apply. Clients are not sent these (rooms/v3.md "Handling redactions").
    std::unordered_set<std::string> withheld{};
    // Target event ID -> the redaction event that was applied to it.
    std::unordered_map<std::string, std::string> applied_by_target{};
};

} // namespace merovingian::database
