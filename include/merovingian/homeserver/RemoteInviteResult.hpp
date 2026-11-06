// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/event.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::homeserver
{

// How the server of an invited user answered `PUT /_matrix/federation/v2/invite`.
enum class RemoteInviteOutcome : std::uint8_t
{
    // It signed and returned the event, and the answer was checked: the same event, validly signed by
    // that server (`cosigned_event_json`).
    delivered,
    // It said no (a 4xx other than 408 and 429), or a 2xx whose event is not the invite with that server's
    // valid signature. `status` and `reason` are what to tell the client.
    refused,
    // It gave no usable answer; the invite should be queued for another attempt.
    unreachable,
};

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
};

} // namespace merovingian::homeserver
