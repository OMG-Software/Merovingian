// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/trust_safety/PolicyServerHook.hpp"

#include <string>

namespace merovingian::trust_safety
{

struct RoomPolicyRequest final
{
    std::string room_id{};
    bool held_for_review{false};
    bool blocked_by_local_policy{false};
    PolicyServerHook policy_server{};
};

} // namespace merovingian::trust_safety
