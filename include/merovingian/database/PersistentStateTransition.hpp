// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

// Tracks the state event that was replaced when a new state event was stored.
// Used to populate unsigned.replaces_state in the client event format.
struct PersistentStateTransition final
{
    std::string room_id{};
    std::string event_type{};
    std::string state_key{};
    std::string event_id{};
    std::string previous_event_id{};
};

} // namespace merovingian::database
