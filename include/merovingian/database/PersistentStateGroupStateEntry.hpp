// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

// One row of a state group's own state: `state_group_id`'s snapshot or delta
// contains (event_type, state_key) -> event_id. See PersistentStateGroup.
struct PersistentStateGroupStateEntry final
{
    std::string state_group_id{};
    std::string event_type{};
    std::string state_key{};
    std::string event_id{};
};

} // namespace merovingian::database
