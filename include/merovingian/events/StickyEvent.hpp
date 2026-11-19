// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace merovingian::events
{

// Sticky events (MSC4354; ADR-0853, ADR-0854). Pure functions only: no clock, no storage. The send path, federation
// ingest and the tests all decide stickiness and expiry through these.

// The longest a sticky event stays sticky, in milliseconds (one hour). A longer duration is accepted and capped.
inline constexpr std::int64_t max_sticky_duration_ms = 3'600'000;

// The top-level PDU fields and the `unsigned` fields, in the stable and the unstable form (ADR-0853).
inline constexpr std::string_view sticky_field = "sticky";
inline constexpr std::string_view unstable_sticky_field = "msc4354_sticky";
inline constexpr std::string_view sticky_remaining_field = "sticky_duration_remaining_ms";
inline constexpr std::string_view unstable_sticky_remaining_field = "msc4354_sticky_duration_ttl_ms";

// The duration a PDU asks to be sticky for, as the client gave it (not capped). nullopt when the PDU is an ordinary
// event: it is a state event (has `state_key`), it names neither field, a named field is not an object whose
// `duration_ms` is an integer of at least 1, or both are named and their `duration_ms` differ.
[[nodiscard]] auto sticky_duration_of(canonicaljson::Value const& pdu) -> std::optional<std::int64_t>;

// A duration a client wrote as a query value or body text: one or more ASCII digits, nothing else (no sign, space or
// `+`), at least 1 and at most 2^53 - 1, the largest integer canonical JSON allows, since the value is written into
// the PDU. Leading zeros are accepted, as for `org.matrix.msc4140.delay`.
[[nodiscard]] auto parse_sticky_duration_text(std::string_view text) -> std::optional<std::int64_t>;

// When a sticky event stops being sticky: min(received_at_ms, origin_server_ts) + min(duration_ms, the cap). The sum
// saturates at the int64 limits, so no input overflows.
[[nodiscard]] auto sticky_expiry_ms(std::int64_t origin_server_ts, std::int64_t received_at_ms,
                                    std::int64_t duration_ms) noexcept -> std::int64_t;

// The milliseconds left until expires_at_ms; nullopt once it is zero or negative, so a served value is always positive.
[[nodiscard]] auto sticky_remaining_ms(std::int64_t expires_at_ms, std::int64_t now_ms) noexcept
    -> std::optional<std::int64_t>;

// The object `{"duration_ms": duration_ms}` that both PDU fields carry.
[[nodiscard]] auto sticky_object(std::int64_t duration_ms) -> canonicaljson::Value;

} // namespace merovingian::events
