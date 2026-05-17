// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/event.hpp"

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

struct PduIngestionResult final
{
    PduIngestionStatus status{PduIngestionStatus::internal_error};
    std::string reason{};
};

// Production sink: appends the PDU to the persistent store after running
// final consistency checks. State-conflict cases return
// rejected_state_conflict so the caller can log a structured warning and
// return 200 per the deferred state-resolution policy.
using PduSink = std::function<PduIngestionResult(InboundPduEnvelope const&)>;

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
