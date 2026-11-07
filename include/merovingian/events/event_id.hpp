// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/EventHashResult.hpp"
#include "merovingian/events/EventIdResult.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::events
{

[[nodiscard]] auto event_id_is_valid(std::string_view event_id) noexcept -> bool;
// Whether a client or a remote server may name `event_id` in a receipt or read marker: a `$`
// followed by the characters of any supported room version's event IDs (the URL-safe alphabet of
// version 4 onward, and the `+` and `/` of version 3's standard base64), at most
// max_id_length_bytes (255) bytes in all (Appendices, "Event IDs"). It is a shape and size check
// only; whether the event exists is not asked.
[[nodiscard]] auto event_id_is_acceptable_in_receipt(std::string_view event_id) noexcept -> bool;
[[nodiscard]] auto make_content_hash(canonicaljson::Value const& event) -> EventHashResult;
[[nodiscard]] auto make_reference_hash(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> EventHashResult;
[[nodiscard]] auto make_reference_hash_event_id(canonicaljson::Value const& event,
                                                rooms::RoomVersionPolicy const& policy) -> EventIdResult;
// Spec: Matrix Server-Server API v1.19 — Room Version 4 § Event IDs
// URL: ../../docs/matrix-v1.19-spec/rooms/v4.md
//
// The event ID is "$" + the reference hash of the REDACTED event, and the
// redaction algorithm is room-version specific, so the caller must supply the
// event's own RoomVersionPolicy. There is no defaulted version: an ID computed
// under the wrong room version does not match the one other servers derive.
[[nodiscard]] auto make_content_hash_id(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> EventIdResult;

// Spec: Matrix Server-Server API v1.19 — Calculating the Content Hash for an Event
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#calculating-the-content-hash-for-an-event
//
// Returns true when the event's hashes.sha256 field matches the computed
// SHA-256 content hash. Returns false when the field is absent or incorrect.
// The event ID a sender would have computed for an event holding RawNumbers, hashed over those bytes. It labels a
// per-PDU error for the sender and nothing else: such an event is not stored or verified here (ADR-0398).
[[nodiscard]] auto make_noncanonical_event_id_label(canonicaljson::Value const& event,
                                                    rooms::RoomVersionPolicy const& policy) -> EventIdResult;

[[nodiscard]] auto verify_pdu_content_hash(canonicaljson::Value const& event) -> bool;

} // namespace merovingian::events
