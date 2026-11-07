// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

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

} // namespace merovingian::homeserver
