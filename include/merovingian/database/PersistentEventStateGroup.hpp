// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

// Maps an event to the state group holding the room's state immediately
// after it (ADR-0064). One row per event that has a known post-state.
struct PersistentEventStateGroup final
{
    std::string event_id{};
    std::string state_group_id{};
};

} // namespace merovingian::database
