// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

// Parsed components of a membership endpoint URI. The federation router has
// already validated that the target matches the route's path template and
// segment count, so the suffix splits cleanly on '/'. Empty fields signal a
// malformed target.
struct MembershipPathParams final
{
    std::string room_id{};
    // For make_*: this is the user_id segment.
    // For send_* and invite: this is the event_id segment.
    std::string subject{};
};

} // namespace merovingian::federation
