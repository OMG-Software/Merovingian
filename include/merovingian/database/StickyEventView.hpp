// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStore.hpp"

#include <cstdint>
#include <string_view>

namespace merovingian::database
{

// How a sticky event's remaining lifetime is shown to clients (MSC4354, ADR-0853). Every client-facing event serializer
// calls `attach_sticky_remaining` after it has built the client form of an event, as it calls
// `attach_redacted_because`.

// The wall-clock milliseconds the sticky readers judge expiry against: `PersistentStore::test_sticky_clock_ms` when a
// test set it, else the system clock.
[[nodiscard]] auto sticky_clock_now_ms(PersistentStore const& store) -> std::int64_t;

// When `event_id` has an unexpired `sticky_events` row, adds `sticky_duration_remaining_ms` and
// `msc4354_sticky_duration_ttl_ms` (the same positive number, `events::sticky_remaining_ms`) to the event's `unsigned`,
// keeping what `unsigned` already holds. Otherwise does nothing: an expired or unknown event gets neither field.
auto attach_sticky_remaining(PersistentStore const& store, std::string_view event_id,
                             canonicaljson::Object& client_event) -> void;

// True when `client_event` is an object whose `unsigned` holds `sticky_duration_remaining_ms`: the event was still
// sticky when it was serialized. A sync section that may carry only sticky events (MSC4354, MSC4480) keeps an event
// only when this holds, since the clock is read again for each event after the section's events were chosen.
[[nodiscard]] auto carries_sticky_remaining(canonicaljson::Value const& client_event) -> bool;

} // namespace merovingian::database
