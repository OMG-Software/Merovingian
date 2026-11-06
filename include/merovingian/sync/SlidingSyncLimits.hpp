// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::sync
{

// Bounds on what one sliding sync request may ask for. Each room named by a subscription
// costs a scan of the event store, so an unbounded request is a CPU amplifier. These are
// policy defaults; the homeserver supplies its validated runtime configuration to the parser.
// A timeline request above the configured ceiling is clamped. Exceeding any count cap is
// rejected with 400 M_INVALID_PARAM by sliding_sync_request_limit_violation().
//
// Each list is sorted and windowed on every request while the runtime lock is held, at one
// pass over the event store per list (ADR-0172), so the shape of the lists is capped too:
// how many lists, how many sort keys per list (MSC4186 defines three, and repeating one adds
// nothing), and how many bump_event_types per list. These are fixed policy, not configuration.
struct SlidingSyncLimits final
{
    std::uint32_t timeline_limit{100U};
    std::uint32_t room_subscriptions{256U};
    std::uint32_t required_state_entries{256U};
    std::uint32_t lists{32U};
    std::uint32_t sort_keys{3U};
    std::uint32_t bump_event_types{64U};
};

} // namespace merovingian::sync
