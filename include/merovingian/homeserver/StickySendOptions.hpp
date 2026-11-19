// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/StickyEventCaps.hpp"

#include <cstddef>
#include <cstdint>

namespace merovingian::homeserver
{

// A client's request to send an event as a sticky event (MSC4354, ADR-0853), after the route has validated it.
// `duration_ms` is the value the client gave (1 to 2^53-1, never capped: the cap applies to the expiry only) and
// `caps` are `ClientApiLimits::max_sticky_events_per_sender` and `max_sticky_events_per_room`. Set only by the
// client-server dispatcher; it is never read from the wire, so no other caller can make an event sticky.
struct StickySendOptions final
{
    std::int64_t duration_ms{0};
    database::StickyEventCaps caps{0U, 0U};
};

} // namespace merovingian::homeserver
