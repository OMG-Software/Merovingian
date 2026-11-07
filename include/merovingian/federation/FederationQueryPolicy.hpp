// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::federation
{

// Per-requested-event-graph work limits for federation history endpoints.
// These are operator policies, not protocol maxima. Matrix gives backfill a
// requested count and get_missing_events an optional count (default 10), but
// does not require a server to honour an arbitrarily large requested count.
struct FederationQueryPolicy final
{
    std::size_t max_backfill_pdus{500U};
    std::size_t max_missing_events_pdus{100U};
    std::size_t max_missing_events_latest{100U};
    std::size_t max_missing_events_traversal{4096U};
};

} // namespace merovingian::federation
