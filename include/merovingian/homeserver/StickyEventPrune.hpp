// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// How long the "sticky-events" job sleeps between sweeps (ADR-0854).
inline constexpr auto sticky_events_prune_interval = std::chrono::seconds{60};

// One sweep of the "sticky-events" job: deletes the expired `sticky_events` rows, and the `delayed_event_sticky_durations`
// rows of a delayed event that is missing or no longer scheduled (`database::prune_expired_sticky_events`), at
// `database::sticky_clock_now_ms`. Every reader already ignores an expired row, so the sweep only bounds the table.
// Takes HomeserverRuntime::mutex for the one transaction; makes no network call. A failed commit is logged as a
// warning with no row fields and retried by the next sweep. Returns how long to wait before the next sweep.
[[nodiscard]] auto prune_sticky_events(HomeserverRuntime& runtime) -> std::chrono::milliseconds;

} // namespace merovingian::homeserver
