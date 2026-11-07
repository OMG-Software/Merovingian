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

// How an event this server places itself is recorded: the state after it, the
// group that state is a delta of (nullopt: a full snapshot), and the forward
// extremities it replaces as the room's tip.
struct EventBookkeeping final
{
    std::vector<database::PersistentStateGroupStateEntry> state_after{};
    std::optional<std::string> parent_state_group_id{};
    std::vector<std::string> replaced_extremities{};
};

} // namespace merovingian::homeserver
