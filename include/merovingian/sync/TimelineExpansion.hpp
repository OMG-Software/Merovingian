// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::sync
{

// Whether a room's timeline is built from its delta floor or resent from its latest events.
// MSC4186 "Changes to `timeline_limit`": when a request raises a seen room's timeline_limit the
// server SHOULD send the latest N events even if some were sent before (timeline_limit_expands).
enum class TimelineExpansion : std::uint8_t
{
    none,   // events after room_since_event_ordering only
    expand, // the latest timeline_limit events, whatever was sent before
};

} // namespace merovingian::sync
