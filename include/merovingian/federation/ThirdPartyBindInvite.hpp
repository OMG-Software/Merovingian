// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/SignedThirdPartyInvite.hpp"

#include <string>

namespace merovingian::federation
{

// One entry of a `/3pid/onbind` notification, checked.
struct ThirdPartyBindInvite final
{
    std::string address{};
    std::string medium{};
    std::string room_id{};
    std::string sender{};
    SignedThirdPartyInvite signed_invite{};
};

} // namespace merovingian::federation
