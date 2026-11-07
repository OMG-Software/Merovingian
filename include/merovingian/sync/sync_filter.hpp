// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/EventTypeFilter.hpp"
#include "merovingian/sync/PreparedRoomEventFilter.hpp" // split-shim
#include "merovingian/sync/RoomFilter.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace merovingian::sync
{

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

// Checks a `Filter` definition uploaded with `POST /user/{userId}/filter` against the spec's
// Filter schema (Matrix v1.19 CS API § Filtering): the body is an object; `presence`,
// `account_data` and `room` are objects; `room`'s `timeline`, `state`, `ephemeral` and
// `account_data` are objects; in each event filter `types` and `not_types` are lists of
// strings, `senders` and `not_senders` lists of user IDs, `rooms` and `not_rooms` lists of
// room IDs, `limit` an integer and the flags booleans; `event_fields` is a list of strings and
// `event_format` is "client" or "federation". Returns a reason naming the first field that
// breaks the schema, or `std::nullopt` for a definition that follows it. Unknown members are
// ignored, as the spec allows servers to. The parse functions above stay lenient, so a filter
// stored before this check still loads.
[[nodiscard]] auto validate_filter_definition(std::string_view filter_json) -> std::optional<std::string>;

// Applies the EventType include/exclude rules. Returns true when the event
// should be kept. `event_type` and `sender` are matched against the
// allow/deny lists; empty lists mean "no restriction". When `event_type`
// is empty the caller is signalling that the type is not yet surfaced
// (e.g. a stored event whose JSON has not been re-parsed), and the type
// allow/deny predicates are skipped while sender predicates still apply.
[[nodiscard]] auto event_passes_filter(EventTypeFilter const& filter, std::string_view event_type,
                                       std::string_view sender) noexcept -> bool;

// event_passes_filter, plus the RoomEventFilter's contains_url against whether the
// event's content has a `url` key.
[[nodiscard]] auto event_passes_room_event_filter(EventTypeFilter const& filter, std::string_view event_type,
                                                  std::string_view sender, bool content_has_url) noexcept -> bool;

// True when a room id is allowed by the room filter's `rooms` / `not_rooms`
// constraint. The leave/invite/join classification is applied separately.
[[nodiscard]] auto room_passes_filter(RoomFilter const& filter, std::string_view room_id) noexcept -> bool;

} // namespace merovingian::sync
