// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/RestrictedJoinVerdict.hpp"
#include "merovingian/homeserver/RestrictedJoinWork.hpp"

#include <string>

namespace merovingian::homeserver
{

struct RestrictedJoinDecision final
{
    RestrictedJoinVerdict verdict{RestrictedJoinVerdict::forbidden};
    // Set when `verdict` is `authorised`: the user ID to put in
    // content.join_authorised_via_users_server and the ID of that user's
    // current m.room.member event, which auth events selection names for the
    // join (server-server-api.md "Auth events selection").
    std::string authorising_user{};
    std::string authorising_member_event_id{};
    std::string reason{};
    RestrictedJoinWork work{};
};

} // namespace merovingian::homeserver
