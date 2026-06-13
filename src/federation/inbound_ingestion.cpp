// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/inbound_ingestion.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("inbound_ingestion", event, std::move(fields)));
    }

    [[nodiscard]] auto find_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto extract_string(canonicaljson::Value const& value) -> std::optional<std::string>
    {
        auto const* text = std::get_if<std::string>(&value.storage());
        return text == nullptr ? std::nullopt : std::optional<std::string>{*text};
    }

    [[nodiscard]] auto extract_integer(canonicaljson::Value const& value) -> std::optional<std::int64_t>
    {
        auto const* number = std::get_if<std::int64_t>(&value.storage());
        return number == nullptr ? std::nullopt : std::optional<std::int64_t>{*number};
    }

    [[nodiscard]] auto extract_string_array(canonicaljson::Value const& value) -> std::vector<std::string>
    {
        auto out = std::vector<std::string>{};
        auto const* array = std::get_if<canonicaljson::Array>(&value.storage());
        if (array == nullptr)
        {
            return out;
        }
        for (auto const& entry : *array)
        {
            if (auto text = extract_string(entry); text.has_value())
            {
                out.push_back(std::move(*text));
            }
        }
        return out;
    }

} // namespace

auto parse_inbound_pdu_envelope(std::string_view pdu_json) -> std::optional<InboundPduEnvelope>
{
    return parse_inbound_pdu_envelope(pdu_json, "12");
}

auto parse_inbound_pdu_envelope(std::string_view pdu_json, std::string_view room_version)
    -> std::optional<InboundPduEnvelope>
{
    if (pdu_json.empty() || pdu_json.front() != '{')
    {
        log_diagnostic("pdu.parse.rejected", {
                                                 {"reason", "empty or non-object PDU", false}
        });
        return std::nullopt;
    }
    auto const parsed = canonicaljson::parse_lossless(pdu_json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        log_diagnostic("pdu.parse.rejected", {
                                                 {"reason", "PDU JSON parse failed", false}
        });
        return std::nullopt;
    }
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        log_diagnostic("pdu.parse.rejected", {
                                                 {"reason", "PDU root is not an object", false}
        });
        return std::nullopt;
    }
    auto envelope = events::parse_event_envelope(parsed.value);
    if (!envelope.error.empty())
    {
        log_diagnostic("pdu.parse.rejected", {
                                                 {"reason", "event envelope parse failed: " + envelope.error, false}
        });
        return std::nullopt;
    }

    // Use the caller-supplied room version (resolved from m.room.create state
    // when available) for event-ID computation so all versions use their own
    // redaction rules rather than hard-coding "12".
    auto const resolved_ver = room_version.empty() ? std::string_view{"12"} : room_version;
    auto const* room_version_policy = rooms::find_room_version_policy(resolved_ver);
    if (room_version_policy == nullptr)
    {
        log_diagnostic("pdu.parse.rejected", {
                                                 {"reason", "room version policy not found", false}
        });
        return std::nullopt;
    }
    auto const event_id_result = events::make_reference_hash_event_id(parsed.value, *room_version_policy);
    if (event_id_result.event_id.empty())
    {
        log_diagnostic("pdu.parse.rejected", {
                                                 {"reason", "event ID computation failed", false}
        });
        return std::nullopt;
    }

    auto out = InboundPduEnvelope{};
    out.event_id = event_id_result.event_id;
    // Spec: Room Version 12 (MSC4291) — the m.room.create event has no room_id
    // field. The room ID equals the create event's reference hash with '!' sigil:
    //   room_id = "!" + event_id.substr(1)   (swap '$' → '!')
    if (envelope.event.room_id.empty() && envelope.event.event_type == "m.room.create")
    {
        out.room_id = "!" + event_id_result.event_id.substr(1);
    }
    else
    {
        out.room_id = envelope.event.room_id;
    }
    out.room_version = std::string{resolved_ver};
    out.sender = envelope.event.sender;
    out.event_type = envelope.event.event_type;
    if (find_member(*root, "state_key") != nullptr)
    {
        out.state_key = envelope.event.state_key;
    }
    out.origin_server_ts = envelope.event.origin_server_ts;
    out.signatures = envelope.event.signatures;
    out.json = std::string{pdu_json};

    if (auto const* prev_value = find_member(*root, "prev_events"); prev_value != nullptr)
    {
        out.prev_event_ids = extract_string_array(*prev_value);
    }
    if (auto const* auth_value = find_member(*root, "auth_events"); auth_value != nullptr)
    {
        out.auth_event_ids = extract_string_array(*auth_value);
    }
    // Spec: Room Version 12 (MSC4291) — the m.room.create event MUST NOT appear
    // in the auth_events of any other event. In v12, the create event ID equals
    // the room_id with sigil swapped ('!' → '$'), so we can detect violations
    // without a store lookup. Only applies to v12 rooms (no ':' in room_id).
    if (out.event_type != "m.room.create" && !out.room_id.empty() &&
        out.room_id.find(':') == std::string::npos)
    {
        auto const create_event_id = "$" + out.room_id.substr(1U);
        for (auto const& auth_id : out.auth_event_ids)
        {
            if (auth_id == create_event_id)
            {
                log_diagnostic("pdu.parse.rejected",
                               {{"reason", "v12: m.room.create must not appear in auth_events", false}});
                return std::nullopt;
            }
        }
    }
    if (auto const* depth_value = find_member(*root, "depth"); depth_value != nullptr)
    {
        if (auto const depth = extract_integer(*depth_value); depth.has_value() && *depth >= 0)
        {
            out.depth = static_cast<std::uint64_t>(*depth);
        }
    }
    log_diagnostic("pdu.parse.accepted", {
                                             {"event_id",   out.event_id,   false},
                                             {"room_id",    out.room_id,    false},
                                             {"sender",     out.sender,     false},
                                             {"event_type", out.event_type, false}
    });
    return out;
}

auto classify_edu_type(std::string_view edu_type) noexcept -> EduType
{
    if (edu_type == "m.typing")
    {
        return EduType::typing;
    }
    if (edu_type == "m.receipt")
    {
        return EduType::receipt;
    }
    if (edu_type == "m.presence")
    {
        return EduType::presence;
    }
    if (edu_type == "m.direct_to_device")
    {
        return EduType::direct_to_device;
    }
    if (edu_type == "m.device_list_update")
    {
        return EduType::device_list_update;
    }
    return EduType::unknown;
}

auto edu_content_is_valid(EduType type, std::string_view content_json) -> bool
{
    if (content_json.empty())
    {
        return false;
    }
    auto const parsed = canonicaljson::parse_lossless(content_json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return false;
    }
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        return false;
    }

    switch (type)
    {
    case EduType::typing:
        // Spec: SS API v1.18 §m.typing — content: { room_id: string, user_id: string, typing: bool }.
        // Note: the CS API uses user_ids (array); the SS API uses user_id (singular) per-user.
        return find_member(*root, "room_id") != nullptr && find_member(*root, "user_id") != nullptr &&
               find_member(*root, "typing") != nullptr;
    case EduType::receipt:
        // receipt content: { <room_id>: { "m.read": { <user_id>: { ts } } } }.
        return !root->empty();
    case EduType::presence:
        // presence content: { push: [ { user_id, presence } ] }.
        return find_member(*root, "push") != nullptr;
    case EduType::direct_to_device:
        // to_device content: { sender, type, message_id, messages }.
        return find_member(*root, "sender") != nullptr && find_member(*root, "type") != nullptr &&
               find_member(*root, "messages") != nullptr;
    case EduType::device_list_update:
        // device_list_update content: { user_id, device_id, stream_id }.
        return find_member(*root, "user_id") != nullptr && find_member(*root, "device_id") != nullptr &&
               find_member(*root, "stream_id") != nullptr;
    case EduType::unknown:
        return false;
    }
    return false;
}

auto parse_inbound_edu_envelope(std::string_view edu_type, std::string_view origin, std::string_view content_json)
    -> std::optional<InboundEduEnvelope>
{
    if (edu_type.empty() || origin.empty())
    {
        return std::nullopt;
    }
    auto const type = classify_edu_type(edu_type);
    if (type == EduType::unknown)
    {
        return std::nullopt;
    }
    if (!edu_content_is_valid(type, content_json))
    {
        return std::nullopt;
    }
    auto out = InboundEduEnvelope{};
    out.type = type;
    out.edu_type = std::string{edu_type};
    out.content_json = std::string{content_json};
    out.origin = std::string{origin};
    return out;
}

auto apply_state_resolution_v2(PduStateConflictContext const& context, ResolvedStateApplier const& apply_resolved)
    -> PduIngestionResult
{
    if (context.room_version.empty())
    {
        return {PduIngestionStatus::rejected_state_conflict, "state-res v2: room version missing", {}};
    }
    auto const* policy = rooms::find_room_version_policy(context.room_version);
    if (policy == nullptr)
    {
        return {PduIngestionStatus::rejected_state_conflict, "state-res v2: unknown room version", {}};
    }
    if (context.state_groups.empty())
    {
        return {PduIngestionStatus::rejected_state_conflict, "state-res v2: no state groups", {}};
    }
    auto request = events::StateResolutionRequest{context.room_version, context.state_groups};
    auto const resolution = events::resolve_state_v2(request, *policy);
    if (!resolution.resolved)
    {
        return {PduIngestionStatus::rejected_state_conflict, "state-res v2 failed: " + resolution.reason, {}};
    }
    if (apply_resolved && !apply_resolved(resolution.resolved_state))
    {
        return {PduIngestionStatus::rejected_state_conflict, "state-res v2: applier rejected merged state", {}};
    }
    return {PduIngestionStatus::accepted,
            "state-res v2: merged " + std::to_string(resolution.resolved_state.size()) + " state events",
            {}};
}

} // namespace merovingian::federation
