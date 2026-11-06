// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_state_group.hpp"
#include "merovingian/database/statement.hpp"

#include <optional>
#include <string>
#include <vector>

namespace merovingian::database
{

// A create_or_reuse_state_group prepared but not committed, so it can commit
// in the transaction of the event whose state it holds (ADR-0228).
struct PreparedStateGroup final
{
    // The group that holds the state: the reused parent, or the new group.
    std::string state_group_id{};
    // The new group's row, or nullopt when the parent is reused and nothing
    // is written.
    std::optional<PersistentStateGroup> group{};
    // The new group's own entries (its delta, or the full snapshot).
    std::vector<PersistentStateGroupStateEntry> rows{};
    std::vector<PreparedStatement> statements{};
};

} // namespace merovingian::database
