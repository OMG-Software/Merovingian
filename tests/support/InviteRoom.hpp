// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::tests::third_party_invite
{

// A room of alice's holding an m.room.third_party_invite for `token` whose key is `identity_key`'s.
struct InviteRoom final
{
    std::string room_id{};
    std::string alice_token{};
};

} // namespace merovingian::tests::third_party_invite
