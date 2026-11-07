// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PreparedStatement.hpp"

#include <string>
#include <vector>

namespace merovingian::database
{

// A current_state change prepared but not committed, so it can commit in the
// transaction of the event that caused it (ADR-0228). store_state is
// prepare_current_state, a commit and apply_current_state.
struct PreparedCurrentState final
{
    PersistentStateEvent state{};
    // The event the key named before; empty when the key had no row.
    std::string previous_event_id{};
    std::vector<PreparedStatement> statements{};
};

} // namespace merovingian::database
