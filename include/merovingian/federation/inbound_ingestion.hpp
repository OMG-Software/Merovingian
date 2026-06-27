// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/event.hpp"
#include "merovingian/events/state_resolution.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Per-PDU envelope passed to the injected ingestion sink. Carries the
// minimum surface the persistent store needs to append an event to the
// graph; consumers may also parse `json` directly for fields not surfaced
// here.
struct InboundPduEnvelope final
{
    std::string event_id{};
    std::string room_id{};
    std::string room_version{};
    std::string sender{};
    std::string event_type{};
    std::optional<std::string> state_key{};
    std::int64_t origin_server_ts{0};
    std::uint64_t depth{0U};
    std::vector<std::string> prev_event_ids{};
    std::vector<std::string> auth_event_ids{};
    std::vector<events::EventSignature> signatures{};
    std::string json{};
};

enum class PduIngestionStatus : std::uint8_t
{
    accepted,
    rejected_auth,
    rejected_state_conflict,
    rejected_invalid,
    internal_error,
};

// Context surfaced by the sink when an incoming PDU forks the room's
// resolved state. Carries the room version, the resolved state before
// the PDU, and the state map proposed by the PDU's prev_events ancestry.
// The federation core hands this to `state_conflict_resolver` to attempt
// a merge through state-resolution v2 rather than silently accepting the
// transaction with the conflict logged.
struct PduStateConflictContext final
{
    std::string room_version{};
    InboundPduEnvelope incoming_pdu{};
    // Two state groups: index 0 is the room's currently resolved state,
    // index 1 is the candidate state the incoming PDU's chain proposes.
    std::vector<events::StateGroup> state_groups{};
};

struct PduIngestionResult final
{
    PduIngestionStatus status{PduIngestionStatus::internal_error};
    std::string reason{};
    // Populated only when status == rejected_state_conflict and the sink
    // could build a resolution context. Empty otherwise, including for
    // accepted PDUs or non-conflict rejections.
    std::optional<PduStateConflictContext> state_conflict{};
};

// Production sink: appends the PDU to the persistent store after running
// final consistency checks. State-conflict cases return
// rejected_state_conflict and SHOULD populate `state_conflict` so the
// federation core can run state-resolution v2 to merge the forks before
// dropping the PDU on the floor.
using PduSink = std::function<PduIngestionResult(InboundPduEnvelope const&)>;

// Resolver invoked on rejected_state_conflict. Returns either accepted
// (the resolver merged the forks via state-res v2 and applied the result)
// or rejected_state_conflict (resolution failed; the PDU is dropped and
// the original conflict is audited).
using StateConflictResolver = std::function<PduIngestionResult(PduStateConflictContext const&)>;

// Runs Matrix state-resolution v2 against the two state groups in
// `context` and returns the merged state. On success the federation
// core calls the resolver's persistence path through `apply_resolved`;
// `apply_resolved` is invoked once with the resolved state so the
// caller (production: the runtime; tests: a fake) can commit the merge
// before the federation handler counts the PDU as accepted.
//
// Returns the resolution result so callers can audit. The returned
// PduIngestionResult mirrors what the federation handler will record:
// `accepted` when state-res succeeded and `apply_resolved` returned true,
// `rejected_state_conflict` otherwise.
using ResolvedStateApplier = std::function<bool(std::vector<events::StateEventReference> const&)>;

[[nodiscard]] auto apply_state_resolution_v2(PduStateConflictContext const& context,
                                             ResolvedStateApplier const& apply_resolved) -> PduIngestionResult;

enum class EduType : std::uint8_t
{
    unknown,
    typing,
    receipt,
    presence,
    direct_to_device,
    device_list_update,
};

struct InboundEduEnvelope final
{
    EduType type{EduType::unknown};
    std::string edu_type{};
    std::string content_json{};
    std::string origin{};
};

enum class EduDispositionStatus : std::uint8_t
{
    accepted,
    rejected_invalid,
    dropped_unknown_type,
};

struct EduDispositionResult final
{
    EduDispositionStatus status{EduDispositionStatus::dropped_unknown_type};
    std::string reason{};
};

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
[[nodiscard]] auto parse_inbound_pdu_envelope(std::string_view pdu_json) -> std::optional<InboundPduEnvelope>;
// Overload that accepts a pre-resolved room version string, avoiding the
// hardcoded "12" default when the caller already knows the correct version
// (e.g. from a prior parse_federation_pdu call with a room_version_resolver).
[[nodiscard]] auto parse_inbound_pdu_envelope(std::string_view pdu_json, std::string_view room_version)
    -> std::optional<InboundPduEnvelope>;

// Classifies an EDU type name against the set the inbound flow handles.
// Unknown types are dropped at the handler boundary rather than rejected
// since the federation spec allows servers to advertise new EDU types.
[[nodiscard]] auto classify_edu_type(std::string_view edu_type) noexcept -> EduType;

// Parses a federation EDU envelope. Validates the type name and that the
// content is a canonical JSON object.
[[nodiscard]] auto parse_inbound_edu_envelope(std::string_view edu_type, std::string_view origin,
                                              std::string_view content_json) -> std::optional<InboundEduEnvelope>;

// Validates an EDU content shape per type. The handler uses this as a
// gate before invoking the production sink so a malformed EDU never
// reaches the runtime state surface.
[[nodiscard]] auto edu_content_is_valid(EduType type, std::string_view content_json) -> bool;

} // namespace merovingian::federation
