// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/SignedThirdPartyInvite.hpp"

#include <string>

namespace merovingian::federation
{

// One `m.room.member` invite to be issued for a third-party invite, as `exchange_third_party_invite` carries it.
struct ThirdPartyInviteExchange final
{
    std::string room_id{};
    // The user who sent the original `m.room.third_party_invite`, and so the sender of the invite to be issued.
    std::string sender{};
    // The invited user (the event's `state_key`).
    std::string target_user_id{};
    SignedThirdPartyInvite signed_invite{};
};

} // namespace merovingian::federation
