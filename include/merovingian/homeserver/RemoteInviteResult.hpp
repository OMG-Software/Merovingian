// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/EventSignature.hpp"
#include "merovingian/homeserver/RemoteInviteOutcome.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::homeserver
{

struct RemoteInviteResult final
{
    RemoteInviteOutcome outcome{RemoteInviteOutcome::unreachable};
    std::uint16_t status{502U};
    std::string reason{};
    // Only for `delivered`: the event this server sent with the invited server's verified signatures
    // merged into its `signatures` (nothing else of the event changed), and those signatures. This, not
    // the event as first composed, is what is stored and sent to the room's other servers
    // (Server-Server API, "Inviting to a room": "Once the event has been signed by both the inviting
    // homeserver and the invited homeserver, it can be sent to all of the servers in the room").
    std::string cosigned_event_json{};
    std::vector<events::EventSignature> cosigned_signatures{};
    // `M_INVITE_BLOCKED` when the invited user's server refused with that errcode (SS7); else empty.
    std::string errcode{};
};

} // namespace merovingian::homeserver
