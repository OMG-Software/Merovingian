// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

// A room's current forward extremity (ADR-0064): an accepted, non-soft-
// failed event with no accepted child yet. See
// database::update_forward_extremities.
struct PersistentForwardExtremity final
{
    std::string room_id{};
    std::string event_id{};
};

} // namespace merovingian::database
