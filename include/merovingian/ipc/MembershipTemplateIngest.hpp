// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::ipc
{

// A make_join a federation worker hands to main (audit R04, ADR-0185): the
// template names an authorising user only after the allow conditions of a
// restricted room are checked, and those rooms' state may live in another
// shard, so main, which holds every room, builds it. Worker to main.
struct MembershipTemplateIngest final
{
    std::string room_id{};
    std::string user_id{};
    std::vector<std::string> supported_versions{};
};

} // namespace merovingian::ipc
