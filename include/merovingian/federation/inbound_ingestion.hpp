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
    // ADR-0064 phase C: the server that sent this PDU over federation. Used to
    // fetch missing prev_events / auth_events and to request state from the
    // origin when our own copy of the DAG is incomplete. Not present in the
    // PDU JSON itself; set by the transaction handler before invoking pdu_sink.
    std::string origin{};
};

enum class PduIngestionStatus : std::uint8_t
{
    accepted,
    rejected_auth,
    // Legacy status from the pre-ADR-0064 state-conflict-resolver plumbing
    // (removed in phase B2 — see the ADR). No production sink produces this
    // any more; kept only so the worker IPC wire format
    // (worker_pool.cpp/worker_event_loop.cpp) stays a stable, exhaustive set.
    rejected_state_conflict,
    rejected_invalid,
    internal_error,
    // ADR-0064 phase B1: a prev_event this PDU depends on has no recorded
    // state group (an older, pre-Phase-A event, or a genuine gap in our
    // history of the room). The event is NOT stored — applying it would mean
    // either guessing its state-before or silently substituting current
    // state, both of which reintroduce delivery-order dependence. The spec
    // treats a delayed-but-legitimate PDU the same as one we simply have not
    // backfilled yet, so this is not a rejection: the transaction still
    // returns 200 and a later phase is expected to fetch the gap
    // (/get_missing_events, /state_ids) and retry.
    missing_prev_state,
    // ADR-0064 phase B2: the PDU passed auth against its own auth_events and
    // against the state before it, but fails auth against the room's
    // *current* (resolved) state. Spec: server-server-api.md "Soft failure".
    // The event IS stored, given an after-state group, and takes part in
    // state resolution as normal — it is never rejected — but it is not a
    // forward extremity and is not relayed to clients, except that a
    // soft-failed *state* event which resolution later admits into current
    // state is shown to clients in the state section as usual.
    soft_failed,
    // ADR-0065 (0.12.13 audit, finding H2): main is at its per-channel IPC
    // in-flight cap and explicitly rejected the pdu_ingest request. The
    // transaction handler must answer the remote with a retryable 5xx.
    main_overloaded,
};

struct PduIngestionResult final
{
    PduIngestionStatus status{PduIngestionStatus::internal_error};
    std::string reason{};
    // Set by production sinks that allocate a stream_ordering for the event.
    // Zero when the result is not accepted or the sink does not assign one.
    std::uint64_t accepted_stream_ordering{0U};
    // Set by production sinks that allocate a sync_stream_id for the event.
    // Zero when the result is not accepted or the sink does not assign one.
    std::uint64_t accepted_sync_stream_id{0U};
};

// Production sink: appends the PDU to the persistent store after running
// the spec's full receipt-order checks (ADR-0064 phases B1/B2): hash
// (redact on mismatch), auth against the PDU's own auth_events (reject),
// auth against the state before the PDU (reject), and auth against current
// state (soft-fail). See homeserver::ingest_pdu_event.
using PduSink = std::function<PduIngestionResult(InboundPduEnvelope const&)>;

enum class EduType : std::uint8_t
{
    unknown,
    typing,
    receipt,
    presence,
    direct_to_device,
    device_list_update,
    signing_key_update,
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
