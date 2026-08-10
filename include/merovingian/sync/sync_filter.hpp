// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// Parsed Matrix v1.19 sync filter. A filter selects which events appear in
// each portion of the /sync response. The Matrix `Filter` JSON has nested
// `room` / `presence` / `account_data` filters; we expose the subset the
// alpha homeserver applies: per-event-type allow/deny lists, per-sender
// allow/deny lists, room id allow/deny lists, and a `timeline.limit`.
struct EventTypeFilter final
{
    std::vector<std::string> types{};     // included if non-empty AND matched
    std::vector<std::string> not_types{}; // excluded
    std::vector<std::string> senders{};
    std::vector<std::string> not_senders{};
    std::size_t limit{0U}; // 0 == no cap
};

struct RoomFilter final
{
    std::vector<std::string> rooms{};
    std::vector<std::string> not_rooms{};
    EventTypeFilter timeline{};
    EventTypeFilter state{};
    EventTypeFilter ephemeral{};
    EventTypeFilter account_data{};
    bool include_leave{false};
};

struct SyncFilter final
{
    RoomFilter room{};
    EventTypeFilter presence{};
    EventTypeFilter account_data{};
    bool present{false}; // false when no filter was supplied
};

// Parse a filter argument as either a raw JSON object (Matrix allows the
// filter to be passed inline) or a server-side filter id. Filter IDs are
// not yet stored, so unrecognised inputs that don't look like JSON return
// an empty (non-present) filter rather than failing the request.
[[nodiscard]] auto parse_filter_argument(std::string_view filter_argument) -> SyncFilter;

// Parses a flat Matrix `RoomEventFilter` JSON object — the shape used by the
// `filter=` query parameter on `GET /messages` and
// `GET /rooms/{roomId}/context/{eventId}`. Unlike `SyncFilter`'s nested
// `room.timeline.*`/`room.state.*` filters, a `RoomEventFilter` puts
// `types`/`not_types`/`senders`/`not_senders`/`rooms`/`not_rooms` directly at
// the top level, so this reuses `RoomFilter` as storage: the flat
// type/sender fields populate `RoomFilter::timeline`, and `rooms`/`not_rooms`
// populate the matching `RoomFilter` fields directly.
//
// Returns `std::nullopt` when `filter_argument` is non-empty but is not
// valid JSON or not a JSON object — callers should fail the request with
// `M_BAD_JSON` in that case rather than silently ignoring a malformed
// filter. An empty `filter_argument` yields a default (pass-everything)
// filter.
[[nodiscard]] auto parse_room_event_filter_argument(std::string_view filter_argument) -> std::optional<RoomFilter>;

// Applies the EventType include/exclude rules. Returns true when the event
// should be kept. `event_type` and `sender` are matched against the
// allow/deny lists; empty lists mean "no restriction". When `event_type`
// is empty the caller is signalling that the type is not yet surfaced
// (e.g. a stored event whose JSON has not been re-parsed), and the type
// allow/deny predicates are skipped while sender predicates still apply.
[[nodiscard]] auto event_passes_filter(EventTypeFilter const& filter, std::string_view event_type,
                                       std::string_view sender) noexcept -> bool;

// True when a room id is allowed by the room filter's `rooms` / `not_rooms`
// constraint. The leave/invite/join classification is applied separately.
[[nodiscard]] auto room_passes_filter(RoomFilter const& filter, std::string_view room_id) noexcept -> bool;

} // namespace merovingian::sync
