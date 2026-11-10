// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/federation/EduDispositionResult.hpp"
#include "merovingian/federation/EduType.hpp"
#include "merovingian/federation/InboundEduEnvelope.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/PduIngestionResult.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Production sink: appends the PDU to the persistent store after running
// the spec's full receipt-order checks (ADR-0064 phases B1/B2): hash
// (redact on mismatch), auth against the PDU's own auth_events (reject),
// auth against the state before the PDU (reject), and auth against current
// state (soft-fail). See homeserver::ingest_pdu_event.
using PduSink = std::function<PduIngestionResult(InboundPduEnvelope const&)>;

// Production sink: routes accepted EDUs into the appropriate runtime
// surface (typing tracker, receipt store, presence dispatcher, to-device
// queue, device-list watcher). Returns the disposition so the inbound
// handler can audit.
using EduSink = std::function<EduDispositionResult(InboundEduEnvelope const&)>;

// Parses a federation PDU into the ingestion envelope and runs the v6+ auth
// rules. Returns std::nullopt when the JSON does not describe a well-formed
// event for the room version. The returned envelope's `signatures` are not
// re-verified here — the caller has already done that through
// authorize_federation_pdu.
// Why a received event is outside its room version's event format, empty when it is not: the canonical size limit,
// prev_events and auth_events as arrays within their caps, and no event_id from room version 3 on. One check for
// every path that takes events from another server, including those that hold them as parsed values (ADR-0399).
// The largest `depth` Canonical JSON can carry (2^53 - 1; rooms/v6.md on: "Must be less than the maximum value for an
// integer (2^53 - 1)"; before room version 6 the spec says 2^63 - 1, which no signed event can reach).
inline constexpr auto max_event_depth = std::int64_t{9007199254740991};

// Empty when `event` has a `depth` that is an integer from 0 to `max_event_depth`; otherwise why not. The spec makes
// `depth` required in every room version's event format, so a missing, negative, fractional or string depth is a
// malformed PDU, never a depth of 0. `pdu_format_violation` includes this; a path that does not call it (an invite's
// event) calls this one.
[[nodiscard]] auto pdu_depth_violation(canonicaljson::Value const& event) -> std::string;

// The room an event belongs to. A room v12 `m.room.create` event has no `room_id` (rooms/v12.md): its room is the
// create event's own reference-hash ID with the `$` sigil swapped for `!`. Any other event, or a create event that
// names its room, keeps the `room_id` it carries. One definition for every parser of a received PDU.
[[nodiscard]] auto room_id_for_received_event(std::string_view room_id, std::string_view event_type,
                                              std::string_view event_id) -> std::string;

[[nodiscard]] auto pdu_format_violation(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> std::string;

[[nodiscard]] auto parse_inbound_pdu_envelope(std::string_view pdu_json) -> std::optional<InboundPduEnvelope>;
// Overload that accepts a pre-resolved room version string, avoiding the
// hardcoded "12" default when the caller already knows the correct version
// (e.g. from a prior parse_federation_pdu call with a room_version_resolver).
[[nodiscard]] auto parse_inbound_pdu_envelope(std::string_view pdu_json, std::string_view room_version)
    -> std::optional<InboundPduEnvelope>;
// Rebuilds the envelope of a PDU that was retained for a retry (R03): the JSON
// as stored, the room version its room resolves to now, and the server it was
// received from (to backfill from). nullopt if the text is no longer a valid
// PDU. Signatures were verified before the PDU was retained and are not
// re-verified here, as for parse_inbound_pdu_envelope.
[[nodiscard]] auto rebuild_inbound_pdu_envelope(std::string_view pdu_json, std::string_view room_version,
                                                std::string_view origin) -> std::optional<InboundPduEnvelope>;

// Classifies an EDU type name against the set the inbound flow handles.
// Unknown types are dropped at the handler boundary rather than rejected
// since the federation spec allows servers to advertise new EDU types.
[[nodiscard]] auto classify_edu_type(std::string_view edu_type) noexcept -> EduType;

// Parses a federation EDU envelope. Validates the type name and that the
// content is a canonical JSON object.
[[nodiscard]] auto parse_inbound_edu_envelope(std::string_view edu_type, std::string_view origin,
                                              std::string_view content_json) -> std::optional<InboundEduEnvelope>;

// The digest main binds a worker-relayed EDU to (F-74, ADR-0395): the hash of the (edu_type, content)
// pair, with the type length-prefixed so no (type, content) split can collide with another. `content_json`
// is the canonical serialisation `extract_transaction_edus` produces, which is what a worker relays
// byte for byte. nullopt only if the hash fails.
[[nodiscard]] auto edu_relay_digest(std::string_view edu_type, std::string_view content_json)
    -> std::optional<std::string>;

// Validates an EDU content shape per type. The handler uses this as a
// gate before invoking the production sink so a malformed EDU never
// reaches the runtime state surface.
[[nodiscard]] auto edu_content_is_valid(EduType type, std::string_view content_json) -> bool;

} // namespace merovingian::federation
