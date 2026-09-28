// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_pool.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/crypto/master_key.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/ipc/channel.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"
#include "merovingian/net/thread_pool.hpp"
#include "merovingian/observability/logger.hpp"

#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    // Minimal JSON helpers for sign_request / pdu_ingest frames.
    // Serializers (json_str, json_str_array_literal) build wire JSON.  Parsers
    // below use canonicaljson::parse_json instead of substring scanning so
    // escaping, whitespace, and nested keys are handled correctly.

    auto json_str(std::string_view s) -> std::string
    {
        auto result = std::string{};
        result.reserve(s.size() + 2U);
        result += '"';
        for (auto const raw_ch : s)
        {
            auto const ch = static_cast<unsigned char>(raw_ch);
            switch (ch)
            {
            case '"':
                result += "\\\"";
                break;
            case '\\':
                result += "\\\\";
                break;
            case '\b':
                result += "\\b";
                break;
            case '\f':
                result += "\\f";
                break;
            case '\n':
                result += "\\n";
                break;
            case '\r':
                result += "\\r";
                break;
            case '\t':
                result += "\\t";
                break;
            default:
                if (ch < 0x20U)
                {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(ch));
                    result += buf;
                }
                else
                {
                    result += static_cast<char>(ch);
                }
                break;
            }
        }
        result += '"';
        return result;
    }

    // Typed JSON accessors used by the deserializers below.
    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
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

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto integer_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::int64_t const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::int64_t>(&value->storage());
    }

    [[nodiscard]] auto array_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Array const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Array>(&value->storage());
    }

    [[nodiscard]] auto string_array_from_json(canonicaljson::Array const* array) -> std::vector<std::string>
    {
        auto result = std::vector<std::string>{};
        if (array == nullptr)
        {
            return result;
        }
        for (auto const& entry : *array)
        {
            if (auto const* text = std::get_if<std::string>(&entry.storage()); text != nullptr)
            {
                result.push_back(*text);
            }
        }
        return result;
    } // Backward-compatible wrappers that parse with canonicaljson and use the
    // typed accessors above.  These replace the previous hand-rolled substring
    // scanners (issues #403 and #397) without requiring every call site to be
    // rewritten.  Functions that extract many fields parse once in their own
    // deserialize_* helpers for efficiency.
    [[nodiscard]] auto json_get_str(std::string_view json, std::string_view key) -> std::string
    {
        auto const parsed = canonicaljson::parse_json(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return {};
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return {};
        }
        auto const* value = string_member(*root, key);
        return value == nullptr ? std::string{} : *value;
    }

    auto deserialize_pdu_ingest(std::string_view json) -> federation::InboundPduEnvelope
    {
        auto env = federation::InboundPduEnvelope{};
        auto const parsed = canonicaljson::parse_json(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return env;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return env;
        }

        if (auto const* value = string_member(*root, "event_id"); value != nullptr)
        {
            env.event_id = *value;
        }
        if (auto const* value = string_member(*root, "room_id"); value != nullptr)
        {
            env.room_id = *value;
        }
        if (auto const* value = string_member(*root, "room_version"); value != nullptr)
        {
            env.room_version = *value;
        }
        if (auto const* value = string_member(*root, "sender"); value != nullptr)
        {
            env.sender = *value;
        }
        if (auto const* value = string_member(*root, "event_type"); value != nullptr)
        {
            env.event_type = *value;
        }
        if (auto const* value = integer_member(*root, "origin_server_ts"); value != nullptr)
        {
            env.origin_server_ts = *value;
        }
        if (auto const* value = integer_member(*root, "depth"); value != nullptr && *value >= 0)
        {
            env.depth = static_cast<std::uint64_t>(*value);
        }
        if (auto const* value = string_member(*root, "json"); value != nullptr)
        {
            env.json = *value;
        }
        if (auto const* value = string_member(*root, "origin"); value != nullptr)
        {
            env.origin = *value;
        }
        if (auto const* value = string_member(*root, "state_key"); value != nullptr)
        {
            env.state_key = *value;
        }

        env.auth_event_ids = string_array_from_json(array_member(*root, "auth_event_ids"));
        env.prev_event_ids = string_array_from_json(array_member(*root, "prev_event_ids"));

        if (auto const* signatures = array_member(*root, "signatures"); signatures != nullptr)
        {
            for (auto const& entry : *signatures)
            {
                auto const* sig_obj = std::get_if<canonicaljson::Object>(&entry.storage());
                if (sig_obj == nullptr)
                {
                    continue;
                }
                auto sig = events::EventSignature{};
                if (auto const* sn = string_member(*sig_obj, "sn"); sn != nullptr)
                {
                    sig.server_name = *sn;
                }
                if (auto const* ki = string_member(*sig_obj, "ki"); ki != nullptr)
                {
                    sig.key_id = *ki;
                }
                if (auto const* s = string_member(*sig_obj, "sig"); s != nullptr)
                {
                    sig.signature = *s;
                }
                if (!sig.server_name.empty())
                {
                    env.signatures.push_back(std::move(sig));
                }
            }
        }

        return env;
    }

    auto serialize_pdu_ingest_result(federation::PduIngestionResult const& result) -> std::string
    {
        auto status_str = std::string_view{};
        switch (result.status)
        {
        case federation::PduIngestionStatus::accepted:
            status_str = "accepted";
            break;
        case federation::PduIngestionStatus::rejected_auth:
            status_str = "rejected_auth";
            break;
        case federation::PduIngestionStatus::rejected_state_conflict:
            status_str = "rejected_state_conflict";
            break;
        case federation::PduIngestionStatus::rejected_invalid:
            status_str = "rejected_invalid";
            break;
        case federation::PduIngestionStatus::internal_error:
            status_str = "internal_error";
            break;
        case federation::PduIngestionStatus::missing_prev_state:
            status_str = "missing_prev_state";
            break;
        case federation::PduIngestionStatus::soft_failed:
            status_str = "soft_failed";
            break;
        case federation::PduIngestionStatus::main_overloaded:
            status_str = "main_overloaded";
            break;
        }
        auto body = std::string{R"({"type":"pdu_ingest_result","status":)"};
        body += json_str(status_str);
        body += R"(,"reason":)";
        body += json_str(result.reason);
        body += R"(,"stream_ordering":)";
        body += std::to_string(result.accepted_stream_ordering);
        body += '}';
        return body;
    }

    // membership_ingest reuses pdu_ingest's envelope wire shape (see
    // append_envelope_fields in worker_event_loop.cpp) plus one extra
    // "endpoint" field, so the existing envelope parser handles everything
    // except that field.
    [[nodiscard]] auto federation_endpoint_from_string(std::string_view value) noexcept
        -> federation::FederationEndpoint
    {
        if (value == "send_leave")
        {
            return federation::FederationEndpoint::send_leave;
        }
        if (value == "send_knock")
        {
            return federation::FederationEndpoint::send_knock;
        }
        return federation::FederationEndpoint::send_join;
    }

    auto json_str_array_literal(std::vector<std::string> const& values) -> std::string
    {
        auto body = std::string{"["};
        auto first = true;
        for (auto const& value : values)
        {
            if (!first)
            {
                body += ',';
            }
            first = false;
            body += json_str(value);
        }
        body += ']';
        return body;
    }

    auto serialize_membership_ingest_result(federation::MembershipAcceptResult const& result) -> std::string
    {
        auto body = std::string{R"({"type":"membership_ingest_result","accepted":)"};
        body += result.accepted ? "true" : "false";
        body += R"(,"status":)";
        body += std::to_string(result.status);
        body += R"(,"reason":)";
        body += json_str(result.reason);
        body += R"(,"room_version":)";
        body += json_str(result.room_version);
        body += R"(,"signed_event_json":)";
        body += json_str(result.signed_event_json);
        body += R"(,"auth_chain_json":)";
        body += json_str_array_literal(result.auth_chain_json);
        body += R"(,"state_json":)";
        body += json_str_array_literal(result.state_json);
        body += R"(,"knock_room_state_json":)";
        body += json_str_array_literal(result.knock_room_state_json);
        body += '}';
        return body;
    }

    auto serialize_sign_response(crypto::SignatureResult const& result) -> std::string
    {
        auto signature_b64 = std::string{};
        if (!result.signature.bytes.empty())
        {
            signature_b64 = events::matrix_base64_from_bytes(result.signature.bytes);
        }
        auto body = std::string{R"({"type":"sign_response","signature":)"};
        body += json_str(signature_b64);
        body += R"(,"error":)";
        body += json_str(result.error);
        body += '}';
        return body;
    }

    // RAII release of a per-channel in-flight slot. Acquired on the IPC
    // dispatch thread before a request is queued; released when the handler
    // lambda finishes, even if it throws (ThreadPool swallows exceptions, so a
    // manual release at the bottom of the lambda would leak on the error path).
    struct InFlightGuard final
    {
        ipc::IpcChannel& channel;
        explicit InFlightGuard(ipc::IpcChannel& ch) noexcept
            : channel{ch}
        {
        }
        ~InFlightGuard() noexcept
        {
            channel.release_in_flight();
        }
        InFlightGuard(InFlightGuard const&) = delete;
        auto operator=(InFlightGuard const&) -> InFlightGuard& = delete;
        InFlightGuard(InFlightGuard&&) = delete;
        auto operator=(InFlightGuard&&) -> InFlightGuard& = delete;
    };

    // Returns the wire response main sends when a channel is already at its
    // per-channel in-flight cap. The shape is type-specific so the worker can
    // map the overload to a retryable 5xx toward the remote.
    [[nodiscard]] auto overload_response_for(std::string_view type) -> std::string
    {
        if (type == "pdu_ingest")
        {
            return R"({"type":"pdu_ingest_result","status":"main_overloaded","reason":"main at per-channel in-flight cap","stream_ordering":0})";
        }
        if (type == "membership_ingest")
        {
            return R"({"type":"membership_ingest_result","accepted":false,"status":503,"reason":"main at per-channel in-flight cap","room_version":"","signed_event_json":"","auth_chain_json":[],"state_json":[],"knock_room_state_json":[]})";
        }
        if (type == "invite_ingest")
        {
            return R"({"type":"invite_ingest_result","accepted":false,"status":503,"reason":"main at per-channel in-flight cap","signed_event_json":"","invite_room_state_json":[]})";
        }
        if (type == "edu_ingest")
        {
            return R"({"type":"edu_ingest_result","status":"rejected_invalid","reason":"main at per-channel in-flight cap"})";
        }
        if (type == "sign_request")
        {
            return R"({"type":"sign_response","signature":"","error":"main at per-channel in-flight cap"})";
        }
        return R"({"type":"error","status":503,"reason":"main at per-channel in-flight cap"})";
    }

    // Acquires a per-channel in-flight slot, submits the handler to the pool,
    // and releases the slot if the pool refuses the work. Returns false when
    // the channel is at its cap (caller must send overload_response_for).
    // clang-format off
    auto submit_limited(net::ThreadPool& pool,
                        std::shared_ptr<ipc::IpcChannel> const& ch, // SHARED_PTR: reviewed — ref-counted channel snapshot from the IPC dispatch thread, must outlive submitted handler across restarts
                        std::function<void()> work) -> bool
    // clang-format on
    {
        if (!ch->try_acquire_in_flight())
        {
            return false;
        }
        if (!pool.submit(std::move(work)))
        {
            ch->release_in_flight();
            return false;
        }
        return true;
    }

    // FNV-1a 32-bit hash. Fast, dependency-free, and distributes room IDs
    // uniformly across shards.
    [[nodiscard]] auto fnv1a_32(std::string_view data) noexcept -> std::uint32_t
    {
        constexpr std::uint32_t prime = 16777619U;
        constexpr std::uint32_t offset_basis = 2166136261U;
        auto hash = offset_basis;
        for (auto const byte : data)
        {
            hash ^= static_cast<std::uint32_t>(static_cast<unsigned char>(byte));
            hash *= prime;
        }
        return hash;
    }

    // Deserializes an "edu_ingest" wire frame into an InboundEduEnvelope,
    // reusing federation::parse_inbound_edu_envelope so an unknown/malformed
    // edu_type or non-object content_json is rejected the same way it would
    // be if this EDU had been processed directly by main instead of relayed
    // from a worker.
    [[nodiscard]] auto deserialize_edu_ingest(std::string_view json) -> std::optional<federation::InboundEduEnvelope>
    {
        auto const parsed = canonicaljson::parse_json(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return std::nullopt;
        }
        auto const edu_type = string_member(*root, "edu_type");
        auto const origin = string_member(*root, "origin");
        auto const content_json = string_member(*root, "content_json");
        return federation::parse_inbound_edu_envelope(edu_type == nullptr ? std::string{} : *edu_type,
                                                      origin == nullptr ? std::string{} : *origin,
                                                      content_json == nullptr ? std::string{} : *content_json);
    }

    auto serialize_edu_ingest_result(federation::EduDispositionResult const& result) -> std::string
    {
        auto status_str = std::string_view{};
        switch (result.status)
        {
        case federation::EduDispositionStatus::accepted:
            status_str = "accepted";
            break;
        case federation::EduDispositionStatus::rejected_invalid:
            status_str = "rejected_invalid";
            break;
        case federation::EduDispositionStatus::dropped_unknown_type:
            status_str = "dropped_unknown_type";
            break;
        }
        auto body = std::string{R"({"type":"edu_ingest_result","status":)"};
        body += json_str(status_str);
        body += R"(,"reason":)";
        body += json_str(result.reason);
        body += '}';
        return body;
    }

    // Deserializes an "invite_ingest" wire frame into an InviteRequest.
    // invite_room_state_json reuses json_str_array, the same array parser
    // deserialize_pdu_ingest uses for auth_event_ids/prev_event_ids above.
    [[nodiscard]] auto deserialize_invite_ingest(std::string_view json) -> federation::InviteRequest
    {
        auto request = federation::InviteRequest{};
        auto const parsed = canonicaljson::parse_json(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return request;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return request;
        }
        if (auto const* value = string_member(*root, "room_id"); value != nullptr)
        {
            request.room_id = *value;
        }
        if (auto const* value = string_member(*root, "event_id"); value != nullptr)
        {
            request.event_id = *value;
        }
        if (auto const* value = string_member(*root, "room_version"); value != nullptr)
        {
            request.room_version = *value;
        }
        if (auto const* value = string_member(*root, "invite_event_json"); value != nullptr)
        {
            request.invite_event_json = *value;
        }
        if (auto const* value = string_member(*root, "origin"); value != nullptr)
        {
            request.origin = *value;
        }
        request.invite_room_state_json = string_array_from_json(array_member(*root, "invite_room_state_json"));
        return request;
    }

    auto serialize_invite_ingest_result(federation::InviteAcceptResult const& result) -> std::string
    {
        auto body = std::string{R"({"type":"invite_ingest_result","accepted":)"};
        body += result.accepted ? "true" : "false";
        body += R"(,"status":)";
        body += std::to_string(result.status);
        body += R"(,"reason":)";
        body += json_str(result.reason);
        body += R"(,"signed_event_json":)";
        body += json_str(result.signed_event_json);
        body += '}';
        return body;
    }

    auto serialize_otk_claim_ingest_result(std::string_view response_body) -> std::string
    {
        auto body = std::string{R"({"type":"otk_claim_ingest_result","response_body":)"};
        body += json_str(response_body);
        body += '}';
        return body;
    }

    auto serialize_user_devices_ingest_result(std::string_view response_body) -> std::string
    {
        auto body = std::string{R"({"type":"user_devices_ingest_result","response_body":)"};
        body += json_str(response_body);
        body += '}';
        return body;
    }

    auto serialize_device_keys_query_ingest_result(std::string_view response_body) -> std::string
    {
        auto body = std::string{R"({"type":"device_keys_query_ingest_result","response_body":)"};
        body += json_str(response_body);
        body += '}';
        return body;
    }

    auto serialize_profile_query_ingest_result(federation::FederationProfile const& profile) -> std::string
    {
        auto body = std::string{R"({"type":"profile_query_ingest_result","found":)"};
        body += profile.found ? "true" : "false";
        body += R"(,"displayname":)";
        body += json_str(profile.displayname);
        body += R"(,"avatar_url":)";
        body += json_str(profile.avatar_url);
        body += '}';
        return body;
    }

    auto serialize_event_query_ingest_result(std::string_view response_body) -> std::string
    {
        auto body = std::string{R"({"type":"event_query_ingest_result","response_body":)"};
        body += json_str(response_body);
        body += '}';
        return body;
    }

    // ADR-0071 (0.12.13, decision D2): main does not trust a worker's claim
    // that a relayed PDU was signed by its sender's server. A compromised
    // worker could otherwise inject events impersonating any sender the room's
    // state authorises. Everything below runs before the relay handlers take
    // runtime.mutex, because resolving a key may go to the network.

    // The room version main itself records for the room; the worker's claim is
    // used only for a room main does not hold (an invite to a remote room),
    // and "12" when neither is known, matching inbound_request.cpp.
    [[nodiscard]] auto relayed_room_version(HomeserverRuntime& runtime, std::string_view room_id,
                                            std::string_view claimed) -> std::string
    {
        auto version = std::string{};
        if (runtime.federation.room_version_resolver)
        {
            auto guard = std::unique_lock{runtime.mutex};
            version = runtime.federation.room_version_resolver(room_id);
        }
        if (version.empty())
        {
            version = std::string{claimed};
        }
        return version.empty() ? std::string{"12"} : version;
    }

    [[nodiscard]] auto server_name_of(std::string_view user_id) noexcept -> std::string_view
    {
        auto const colon = user_id.find(':');
        return colon == std::string_view::npos ? std::string_view{} : user_id.substr(colon + 1U);
    }

    // Verifies the signature of the server the event's sender belongs to
    // (server-server-api.md, "Validating hashes and signatures on received
    // events"), with a key main resolves through its own remote_key_resolver.
    // The same check the worker ran (federation::authorize_federation_pdu), but
    // never on the worker's word.
    struct RelayedSignature final
    {
        // The event ID the signed event hashes to; empty when refused.
        std::string event_id{};
        std::string refusal{};
    };

    [[nodiscard]] auto verify_relayed_event_signature(HomeserverRuntime& runtime, std::string_view event_json,
                                                      std::string const& room_version) -> RelayedSignature
    {
        auto pdu = federation::parse_federation_pdu(event_json, [&room_version](std::string_view) {
            return room_version;
        });
        if (pdu.event_id.empty())
        {
            return {{}, "relayed event is not a valid PDU"};
        }
        pdu.room_version = room_version;
        auto const sender_server = server_name_of(pdu.sender);
        auto const signature = std::ranges::find_if(pdu.signatures, [sender_server](auto const& sig) {
            return sig.server_name == sender_server;
        });
        if (sender_server.empty() || signature == pdu.signatures.end())
        {
            return {{}, "relayed event has no signature from its sender's server"};
        }
        if (!runtime.federation.remote_key_resolver)
        {
            return {{}, "remote key resolver not wired"};
        }
        auto const remote = [&]() {
            auto const unlocked = RuntimeLockRelease{};
            std::ignore = unlocked;
            return runtime.federation.remote_key_resolver(sender_server, signature->key_id);
        }();
        auto const key = remote.has_value() ? std::optional<federation::FederationKeyRecord>{remote->signing_key}
                                            : std::optional<federation::FederationKeyRecord>{};
        auto const decision = federation::authorize_federation_pdu(pdu, sender_server, key);
        if (!decision.accepted)
        {
            return {{}, "relayed event failed signature verification: " + decision.reason};
        }
        return {pdu.event_id, {}};
    }

    struct RelayedEnvelope final
    {
        // Set only when the frame passed; otherwise `refusal` says why.
        std::optional<federation::InboundPduEnvelope> envelope{};
        std::string refusal{};
    };

    // Rebuilds the envelope from the verified event JSON rather than taking
    // the worker's separately framed fields, and refuses a frame that
    // disagrees with the event it carries. Only the transport origin (used to
    // choose where to backfill from; anything fetched there is verified
    // again) is taken from the frame.
    [[nodiscard]] auto reverify_relayed_envelope(HomeserverRuntime& runtime,
                                                 federation::InboundPduEnvelope const& frame) -> RelayedEnvelope
    {
        auto const room_version = relayed_room_version(runtime, frame.room_id, frame.room_version);
        auto const signature = verify_relayed_event_signature(runtime, frame.json, room_version);
        if (!signature.refusal.empty())
        {
            return {std::nullopt, signature.refusal};
        }
        auto envelope = federation::parse_inbound_pdu_envelope(frame.json, room_version);
        if (!envelope.has_value())
        {
            return {std::nullopt, "relayed event is not a valid PDU envelope"};
        }
        if (envelope->event_id != frame.event_id || envelope->event_id != signature.event_id ||
            envelope->room_id != frame.room_id)
        {
            return {std::nullopt, "relayed frame does not match the signed event it carries"};
        }
        envelope->origin = frame.origin;
        envelope->room_version = room_version;
        return {std::move(envelope), {}};
    }

    auto log_relay_refused(std::string_view type, std::string_view event_id, std::string_view reason) -> void
    {
        LOG_WARNING("Refused a PDU relayed by a federation worker; type=" + std::string{type} +
                    " event_id=" + std::string{event_id} + " reason=" + std::string{reason});
    }

} // namespace

auto federation_worker_shard_for(std::string_view room_id, std::uint32_t shards) noexcept -> std::size_t
{
    if (shards == 0U)
    {
        return 0U;
    }
    if (room_id.empty())
    {
        return 0U;
    }
    return static_cast<std::size_t>(fnv1a_32(room_id) % shards);
}

auto handle_pdu_ingest_request(HomeserverRuntime& runtime, std::string_view request_json)
    -> federation::PduIngestionResult
{
    // TRUST BOUNDARY (ADR-0071): the frame comes from the worker, the process
    // most exposed to hostile input. Main re-verifies the event's signature
    // with its own key resolver and rebuilds the envelope from the verified
    // event before pdu_sink sees it.
    auto const frame = deserialize_pdu_ingest(request_json);
    if (!runtime.federation.pdu_sink)
    {
        return {federation::PduIngestionStatus::internal_error, "pdu_sink not wired"};
    }
    auto const relayed = reverify_relayed_envelope(runtime, frame);
    if (!relayed.envelope.has_value())
    {
        log_relay_refused("pdu_ingest", frame.event_id, relayed.refusal);
        return {federation::PduIngestionStatus::rejected_invalid, relayed.refusal};
    }
    // The default sink reserves stream_ordering internally and returns it in
    // accepted_stream_ordering. It also publishes the sync notification, so the
    // worker path only forwards the result back to the shard that owns this room.
    return runtime.federation.pdu_sink(*relayed.envelope);
}

auto handle_membership_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // send_join/send_leave/send_knock accepted by a worker must be persisted
    // through main's own store, not the worker's — see docs/architecture.md,
    // "Federation worker room staleness", "Shard routing must key on the same
    // room ID string...". The default membership_acceptor (wired via
    // wire_federation_callbacks, same as pdu_sink's default) already calls
    // sync_notifier->publish itself on success, so unlike pdu_ingest this does
    // not need to publish separately.
    auto const endpoint = federation_endpoint_from_string(json_get_str(request_json, "endpoint"));
    auto const frame = deserialize_pdu_ingest(request_json);
    auto result = federation::MembershipAcceptResult{};
    if (!runtime.federation.membership_acceptor)
    {
        result.status = 501U;
        result.reason = "membership_acceptor not wired";
        return serialize_membership_ingest_result(result);
    }
    // TRUST BOUNDARY (ADR-0071): verified before the runtime lock is taken,
    // because resolving the sender's key may go to the network.
    auto const relayed = reverify_relayed_envelope(runtime, frame);
    if (!relayed.envelope.has_value())
    {
        log_relay_refused("membership_ingest", frame.event_id, relayed.refusal);
        result.status = 403U;
        result.reason = relayed.refusal;
        return serialize_membership_ingest_result(result);
    }
    {
        auto guard = std::unique_lock{runtime.mutex};
        result = runtime.federation.membership_acceptor(endpoint, relayed.envelope->room_id, {}, *relayed.envelope);
    }
    return serialize_membership_ingest_result(result);
}

auto handle_edu_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // EDUs (typing, receipts, presence, m.direct_to_device, device list
    // updates) accepted by a worker must reach main's own edu_sink the same
    // way pdu_ingest/membership_ingest already relay PDUs and membership
    // acceptances — see docs/architecture.md, "Federation worker EDU relay".
    // m.direct_to_device in particular carries E2EE megolm room-key shares:
    // a worker that dropped this EDU instead of relaying it would leave the
    // recipient's device without the key it needs to decrypt the
    // corresponding room event, with no error surfaced anywhere — the
    // transaction is still ack'd 200 to the sending server either way.
    auto const envelope = deserialize_edu_ingest(request_json);
    if (!envelope.has_value())
    {
        return serialize_edu_ingest_result(
            {federation::EduDispositionStatus::rejected_invalid, "edu_ingest envelope failed to parse"});
    }
    auto result = federation::EduDispositionResult{};
    {
        auto guard = std::unique_lock{runtime.mutex};
        if (runtime.federation.edu_sink)
        {
            result = runtime.federation.edu_sink(*envelope);
        }
        else
        {
            result.status = federation::EduDispositionStatus::rejected_invalid;
            result.reason = "edu_sink not wired";
        }
    }
    return serialize_edu_ingest_result(result);
}

auto handle_invite_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // A federated invite accepted by a worker must be persisted through
    // main's own store, not the worker's — see docs/architecture.md,
    // "Federation worker invite relay", the same class of gap
    // handle_membership_ingest_request closes for send_join/send_leave/
    // send_knock. The default invite_handler (wired via
    // wire_federation_callbacks, same as membership_acceptor's default)
    // already calls sync_notifier->publish itself on success, so this does
    // not need to publish separately either.
    auto const request = deserialize_invite_ingest(request_json);
    auto result = federation::InviteAcceptResult{};
    if (!runtime.federation.invite_handler)
    {
        result.status = 501U;
        result.reason = "invite_handler not wired";
        return serialize_invite_ingest_result(result);
    }
    // TRUST BOUNDARY (ADR-0071): verified before the runtime lock is taken.
    // invite_handler reads the event itself from invite_event_json but files
    // it under the frame's event_id, so that must be the ID the signed event
    // hashes to.
    auto const room_version = relayed_room_version(runtime, request.room_id, request.room_version);
    auto const signature = verify_relayed_event_signature(runtime, request.invite_event_json, room_version);
    auto const refusal = !signature.refusal.empty() ? signature.refusal
                         : signature.event_id != request.event_id
                             ? std::string{"relayed frame does not match the signed event it carries"}
                             : std::string{};
    if (!refusal.empty())
    {
        log_relay_refused("invite_ingest", request.event_id, refusal);
        result.status = 403U;
        result.reason = refusal;
        return serialize_invite_ingest_result(result);
    }
    {
        auto guard = std::unique_lock{runtime.mutex};
        result = runtime.federation.invite_handler(request);
    }
    return serialize_invite_ingest_result(result);
}

auto handle_otk_claim_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // A one-time-key claim accepted by a worker must be decided against
    // main's own store, not a worker's — see docs/architecture.md,
    // "Federation worker one-time-key claim relay". Unlike pdu_ingest/
    // membership_ingest/edu_ingest/invite_ingest above, this isn't about a
    // write becoming invisible to main: database::claim_one_time_key issues
    // a real DELETE against the shared database either way. The problem is
    // that the claim *decision* — whether the key is still available — is
    // made against a per-process in-memory PersistentStore::one_time_keys
    // snapshot that is never invalidated by another process's write. Two
    // processes can each believe the same key is still available and both
    // return it to their caller, reusing an Olm one-time prekey — exactly
    // the property a one-time key exists to prevent. Routing every claim
    // through main's own single copy removes the split-brain entirely.
    auto const request_body = json_get_str(request_json, "request_body");
    auto response_body = std::string{};
    {
        auto guard = std::unique_lock{runtime.mutex};
        if (runtime.federation.one_time_keys_claim_provider)
        {
            response_body = runtime.federation.one_time_keys_claim_provider(request_body);
        }
    }
    return serialize_otk_claim_ingest_result(response_body);
}

auto handle_user_devices_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // A federated device-list query decided by a worker must read main's own
    // store, not a worker's — see docs/architecture.md, "Federation worker
    // user/device/profile/event query relay". Unlike pdu_ingest/membership_ingest/
    // edu_ingest/invite_ingest above, there is no write to make visible here;
    // the bug is that PersistentStore::device_keys is a per-process snapshot
    // hydrated once at worker startup, so a device whose keys were uploaded
    // through main afterward is invisible to a worker's copy, and this
    // non-room-scoped route always lands on shard 0 with no mechanism (unlike
    // room_sync) to ever refresh it.
    auto const user_id = json_get_str(request_json, "user_id");
    auto response_body = std::string{};
    {
        auto guard = std::unique_lock{runtime.mutex};
        if (runtime.federation.user_devices_provider)
        {
            response_body = runtime.federation.user_devices_provider(user_id);
        }
    }
    return serialize_user_devices_ingest_result(response_body);
}

auto handle_device_keys_query_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // Same stale-snapshot failure mode as handle_user_devices_ingest_request
    // above, for POST /_matrix/federation/v1/user/keys/query instead of
    // GET /user/devices/{userId}. See docs/architecture.md, "Federation
    // worker user/device/profile/event query relay".
    auto const request_body = json_get_str(request_json, "request_body");
    auto response_body = std::string{};
    {
        auto guard = std::unique_lock{runtime.mutex};
        if (runtime.federation.device_keys_query_provider)
        {
            response_body = runtime.federation.device_keys_query_provider(request_body);
        }
    }
    return serialize_device_keys_query_ingest_result(response_body);
}

auto handle_profile_query_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // Same stale-snapshot failure mode as handle_user_devices_ingest_request
    // above, for GET /_matrix/federation/v1/query/profile: PersistentStore::
    // profiles is likewise a worker-startup snapshot never refreshed by a
    // later client-server profile update on main. See docs/architecture.md,
    // "Federation worker user/device/profile/event query relay".
    auto const user_id = json_get_str(request_json, "user_id");
    auto profile = federation::FederationProfile{};
    {
        auto guard = std::unique_lock{runtime.mutex};
        if (runtime.federation.profile_query_provider)
        {
            profile = runtime.federation.profile_query_provider(user_id);
        }
    }
    return serialize_profile_query_ingest_result(profile);
}

auto handle_event_query_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // GET /_matrix/federation/v1/event/{eventId} carries no room ID, so it
    // cannot be routed to the shard that actually owns the event's room the
    // way state/state_ids/backfill/get_missing_events are — it always lands
    // on shard 0 regardless of ownership. Relaying through main (which
    // receives every event via pdu_sink on every shard's behalf) answers
    // correctly regardless of which shard the request happened to land on,
    // sidestepping the routing-alignment problem rather than trying to fix
    // shard selection for an ID space with no room ID to key off. See
    // docs/architecture.md, "Federation worker user/device/profile/event query
    // relay".
    auto const event_id = json_get_str(request_json, "event_id");
    auto response_body = std::string{};
    {
        auto guard = std::unique_lock{runtime.mutex};
        if (runtime.federation.event_query_provider)
        {
            response_body = runtime.federation.event_query_provider(event_id);
        }
    }
    return serialize_event_query_ingest_result(response_body);
}

namespace
{

    // Reads federation.worker.database_uri_file, ADR-0062 part 2's separate,
    // least-privilege PostgreSQL connection URI for the worker. Mirrors
    // runtime.cpp's read_database_uri_file (first line of the file, trimmed
    // of its trailing newline by std::getline), but returns the bytes in a
    // core::SecretBuffer and wipes the transient std::string copy, since
    // unlike main's own database.uri_file this value is about to cross a
    // process boundary. Returns nullopt on an empty path, a file that cannot
    // be opened, or an empty first line -- the caller treats all three as
    // "no URI available" and decides what that means from the surrounding
    // config (required vs. an explicit shared-credentials opt-out).
    [[nodiscard]] auto read_worker_database_uri_file(std::string const& path) -> std::optional<core::SecretBuffer>
    {
        if (path.empty())
        {
            return std::nullopt;
        }
        auto input = std::ifstream{path};
        if (!input.is_open())
        {
            return std::nullopt;
        }
        auto value = std::string{};
        std::getline(input, value);
        if (value.empty())
        {
            return std::nullopt;
        }
        auto secret = core::SecretBuffer{
            std::span<std::uint8_t const>{reinterpret_cast<std::uint8_t const*>(value.data()), value.size()}
        };
        core::secure_zero(std::as_writable_bytes(std::span{value}));
        return secret;
    }

} // namespace

WorkerPool::WorkerPool(config::FederationWorkerConfig const& cfg, HomeserverRuntime& runtime, std::string worker_path,
                       std::string config_path)
    : cfg_{cfg}
    , runtime_{runtime}
    , handler_pool_{cfg_.relay_threads}
    , worker_path_{std::move(worker_path)}
    , config_path_{std::move(config_path)}
{
    // Both sides of the worker IPC channel must agree on max_frame_bytes (see
    // ipc::frame_bytes_for_response_cap); this side derives it from the same
    // config the worker itself parses from --config at spawn time.
    auto const join_response_max_size =
        config::parse_size_limit(runtime_.config.security().federation.join_response_max_size);
    auto const max_frame_bytes =
        ipc::frame_bytes_for_response_cap(join_response_max_size.valid ? join_response_max_size.bytes : 0U);

    // Derive the worker IPC auth key ONCE, here, from the operator master-key
    // file — instead of letting each WorkerSupervisor independently open that
    // file on every spawn and every restart. Neither the worker nor any
    // restart of it ever reads the master key file itself (0.12.13 audit,
    // finding N1): each supervisor below receives only these already-derived
    // bytes, over a pipe inherited at spawn time. See ADR-0062.
    auto const master_material = crypto::load_master_key_material(runtime_.config.security().secrets.master_key_file);
    if (!master_material.has_value())
    {
        throw std::runtime_error{"ipc: master key file '" + runtime_.config.security().secrets.master_key_file +
                                 "' is unavailable; cannot authenticate worker IPC channel"};
    }
    auto const derived_auth_key = crypto::derive_ipc_auth_key(master_material->bytes());
    if (!derived_auth_key.has_value())
    {
        throw std::runtime_error{"ipc: failed to derive worker IPC auth key from master key file"};
    }

    // ADR-0062 part 2 (finding N1): derive the worker's separate database
    // connection URI ONCE, here, the same way the auth key above is derived
    // once rather than per-supervisor. SQLite offers no role to separate --
    // the worker keeps opening the same file there, so this section is
    // skipped entirely and every supervisor below gets an empty
    // worker_database_uri_material (no --db-uri-fd is ever passed).
    auto worker_database_uri = std::optional<core::SecretBuffer>{};
    if (runtime_.config.database().backend == config::DatabaseBackend::postgresql)
    {
        worker_database_uri = read_worker_database_uri_file(cfg_.database_uri_file);
        if (worker_database_uri.has_value())
        {
            LOG_INFO("Federation worker: using a separate least-privilege database login "
                     "(federation.worker.database_uri_file configured)");
        }
        else if (cfg_.allow_shared_database_credentials)
        {
            LOG_CRITICAL("Federation worker: federation.worker.database_uri_file is not set or unreadable; the worker "
                         "will share main's PostgreSQL login credentials, including read access to "
                         "server_signing_keys.secret_key (federation.worker.allow_shared_database_credentials=true). "
                         "See ADR-0062 part 2.");
        }
        else
        {
            // config::validate() already rejects this combination before the
            // server can start; this is the fail-closed backstop for any
            // caller that constructs a WorkerPool without going through that
            // validation path (e.g. an embedder or a future admin API).
            throw std::runtime_error{
                "federation.worker.database_uri_file is required when database.backend=postgresql and "
                "security.federation.enabled=true, unless federation.worker.allow_shared_database_credentials=true"};
        }
    }

    auto const count = cfg_.shards > 0U ? cfg_.shards : 1U;
    workers_.reserve(count);
    for (auto i = std::uint32_t{0U}; i < count; ++i)
    {
        // Each supervisor gets its own SecretBuffer copy of the same derived
        // bytes: core::SecretBuffer is move-only and mlocks its own page, so
        // one instance cannot be shared by reference across N supervisors
        // that each outlive this constructor.
        auto key_material = core::SecretBuffer{
            std::span<std::uint8_t const>{derived_auth_key->bytes.data(), derived_auth_key->bytes.size()}
        };
        auto db_uri_material =
            worker_database_uri.has_value() ? core::SecretBuffer{worker_database_uri->bytes()} : core::SecretBuffer{};
        auto supervisor =
            std::make_unique<WorkerSupervisor>(worker_path_, config_path_, cfg_.request_timeout_seconds, i,
                                               std::move(key_material), max_frame_bytes, std::move(db_uri_material));
        supervisor->set_max_in_flight(cfg_.ipc_max_in_flight_requests);

        // Per-worker request handler: the IPC dispatch thread only classifies
        // the frame and enqueues the real work on handler_pool_. Each task
        // holds its own ref-counted channel snapshot and sends the response
        // from the pool, so a slow handler can never stall later queued frames.
        supervisor->set_request_handler([this, ptr = supervisor.get()](std::uint64_t id, std::string json) {
            auto const type = json_get_str(json, "type");
            // Keep a ref-counted handle to the channel that received this
            // request. The submitted task may outlive a concurrent worker
            // restart, so it must hold its own reference rather than
            // dereferencing the supervisor pointer.
            auto const ch = ptr->channel_snapshot();
            if (type == "pdu_ingest")
            {
                auto const room_id = json_get_str(json, "room_id");
                if (!submit_limited(handler_pool_, ch, [this, ch, id, room_id, json = std::move(json)]() mutable {
                        auto const guard = InFlightGuard{*ch};
                        auto const result = handle_pdu_ingest_request(runtime_, json);
                        if (result.status == federation::PduIngestionStatus::accepted)
                        {
                            // Push the just-committed event back down to whichever
                            // shard owns this room — in practice the same worker that
                            // made this exact pdu_ingest call, since shard_for() is a
                            // pure function of room_id. Without this, a message
                            // relayed from a worker is only ever visible in main's own
                            // store: pdu_sink deliberately does not write to the
                            // worker's own PersistentStore ("does NOT write events",
                            // see worker_event_loop.cpp), and nothing else refreshes a
                            // worker's room snapshot for ordinary (non-membership)
                            // traffic. A later backfill/event/state query for this
                            // room landing back on that shard would otherwise omit
                            // this event. See docs/architecture.md, "Federation
                            // worker room staleness".
                            notify_room_changed(room_id);
                        }
                        ch->send_response(id, serialize_pdu_ingest_result(result));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else if (type == "membership_ingest")
            {
                if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                        auto const guard = InFlightGuard{*ch};
                        ch->send_response(id, handle_membership_ingest_request(runtime_, json));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else if (type == "edu_ingest")
            {
                if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                        auto const guard = InFlightGuard{*ch};
                        ch->send_response(id, handle_edu_ingest_request(runtime_, json));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else if (type == "invite_ingest")
            {
                if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                        auto const guard = InFlightGuard{*ch};
                        ch->send_response(id, handle_invite_ingest_request(runtime_, json));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else if (type == "otk_claim_ingest")
            {
                if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                        auto const guard = InFlightGuard{*ch};
                        ch->send_response(id, handle_otk_claim_ingest_request(runtime_, json));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else if (type == "user_devices_ingest")
            {
                if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                        auto const guard = InFlightGuard{*ch};
                        ch->send_response(id, handle_user_devices_ingest_request(runtime_, json));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else if (type == "device_keys_query_ingest")
            {
                if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                        auto const guard = InFlightGuard{*ch};
                        ch->send_response(id, handle_device_keys_query_ingest_request(runtime_, json));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else if (type == "profile_query_ingest")
            {
                if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                        auto const guard = InFlightGuard{*ch};
                        ch->send_response(id, handle_profile_query_ingest_request(runtime_, json));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else if (type == "event_query_ingest")
            {
                if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                        auto const guard = InFlightGuard{*ch};
                        ch->send_response(id, handle_event_query_ingest_request(runtime_, json));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else if (type == "sign_request")
            {
                auto const key_id = json_get_str(json, "key_id");
                auto const canonical = json_get_str(json, "canonical_json");
                if (!submit_limited(handler_pool_, ch, [this, ch, id, key_id, canonical]() {
                        auto const flight_guard = InFlightGuard{*ch};
                        auto result = crypto::SignatureResult{};
                        {
                            auto lock = std::unique_lock{runtime_.mutex};
                            if (runtime_.crypto_provider != nullptr)
                            {
                                result =
                                    runtime_.crypto_provider->sign(crypto::Ed25519SecretKeyHandle{key_id}, canonical);
                            }
                            else
                            {
                                result.error = "crypto provider not available";
                            }
                        }
                        ch->send_response(id, serialize_sign_response(result));
                    }))
                {
                    ch->send_response(id, overload_response_for(type));
                }
            }
            else
            {
                LOG_WARNING("WorkerPool shard " + std::to_string(ptr == nullptr ? 0U : ptr->shard_index()) +
                            ": unexpected IPC request type: " + type);
            }
        });

        supervisor->start();
        workers_.push_back(std::move(supervisor));
    }
}

WorkerPool::~WorkerPool()
{
    stop();
}

auto WorkerPool::handle(LocalHttpRequest const& request, std::string_view room_id) -> LocalHttpResponse
{
    auto const index = shard_for(room_id);
    if (index >= workers_.size())
    {
        return {503U, R"({"errcode":"M_UNAVAILABLE","error":"Federation worker shard unavailable"})"};
    }

    auto& worker = *workers_[index];
    // Check supervisor health first (covers waitpid failure / stopped monitor),
    // then grab a ref-counted channel snapshot so the pointer stays alive across
    // a concurrent restart that might reset channel_ before send_request().
    auto const ch = worker.channel_snapshot();
    if (!worker.healthy() || !ch || !ch->healthy())
    {
        return {503U, R"({"errcode":"M_UNAVAILABLE","error":"Federation worker shard unavailable"})"};
    }

    // Inbound federation requests can trigger outbound HTTP calls inside the
    // worker. The IPC timeout must cover the longest remote timeout the worker
    // may wait for, plus a small margin, or main will declare an IPC timeout
    // before the worker's own remote call has had a chance to complete (issue
    // #326).
    auto const remote_timeout = config::parse_duration_seconds(runtime_.config.security().federation.remote_timeout);
    auto const remote_seconds = remote_timeout.valid ? remote_timeout.seconds : cfg_.request_timeout_seconds;
    auto const ipc_timeout_seconds = std::max(cfg_.request_timeout_seconds, remote_seconds) + 10U;
    auto const timeout = std::chrono::seconds{ipc_timeout_seconds};
    auto const reply = ch->send_request(ipc::serialize_fed_request(request), timeout);
    if (!reply.has_value())
    {
        LOG_WARNING("WorkerPool: shard " + std::to_string(index) + " request timed out or failed for " +
                    request.target);
        return {503U, R"({"errcode":"M_UNAVAILABLE","error":"Federation worker shard unavailable"})"};
    }

    auto response = ipc::deserialize_fed_response(*reply);
    // Diagnostic visibility into what the worker actually answered: main's own
    // logging is reliable (this call site), but handle_inbound_federation_request
    // — which runs entirely inside the worker process — has been observed to
    // leave no trace of its own request.received/transaction.accepted log lines
    // even for transactions that plainly succeeded (event_state.persisted fires
    // from the relayed pdu_ingest handler on main's side). Logging the shape of
    // the raw reply here, from a call site proven to reach the journal, lets us
    // tell whether the worker's response body actually came from that function
    // without guessing at where its own logging goes missing.
    LOG_DEBUG("WorkerPool: shard " + std::to_string(index) + " replied for " + request.target +
              " status=" + std::to_string(response.status) + " body_bytes=" + std::to_string(response.body.size()) +
              " body_prefix=" + response.body.substr(0U, 96U));
    return response;
}

auto WorkerPool::notify_room_changed(std::string_view room_id) -> void
{
    auto const index = shard_for(room_id);
    if (index >= workers_.size())
    {
        return;
    }
    auto const ch = workers_[index]->channel_snapshot();
    if (!ch || !ch->healthy())
    {
        return;
    }
    ch->send_notification(ipc::serialize_room_sync_notification(room_id));
}

auto WorkerPool::healthy() const noexcept -> bool
{
    for (auto const& worker : workers_)
    {
        if (!worker || !worker->healthy())
        {
            return false;
        }
    }
    return !workers_.empty();
}

auto WorkerPool::stop() noexcept -> void
{
    // Stop the handler pool first: any in-flight main-side IPC handler holds a
    // channel snapshot and may call back into the pool (notify_room_changed) or
    // send a response on a channel we are about to close. Draining the pool
    // before stopping workers prevents those callbacks from racing shutdown
    // and keeps TSan-instrumented teardown paths from deadlocking around a
    // channel whose dispatch thread has already been joined.
    handler_pool_.request_stop();

    for (auto& worker : workers_)
    {
        if (worker)
        {
            worker->stop();
        }
    }
    workers_.clear();
}

auto WorkerPool::shard_for(std::string_view room_id) const noexcept -> std::size_t
{
    return federation_worker_shard_for(room_id, cfg_.shards);
}

auto WorkerPool::send_outbound_request(http::OutboundRequest const& request, std::string_view room_id)
    -> http::OutboundResult
{
    auto const index = shard_for(room_id);
    if (index >= workers_.size())
    {
        return {false, {}, http::OutboundError::network_error, "federation worker shard unavailable"};
    }

    auto& worker = *workers_[index];
    auto const ch = worker.channel_snapshot();
    if (!worker.healthy() || !ch || !ch->healthy())
    {
        return {false, {}, http::OutboundError::network_error, "federation worker shard unavailable"};
    }

    // Give the IPC channel a 10 s buffer beyond the HTTP total timeout so the
    // worker always has time to return a response before we declare a timeout.
    auto const ipc_timeout = std::chrono::seconds{static_cast<long>(request.total_timeout_seconds) + 10};
    auto const reply = ch->send_request(ipc::serialize_outbound_http_request(request), ipc_timeout);
    if (!reply.has_value())
    {
        LOG_WARNING("WorkerPool: shard " + std::to_string(index) + " outbound HTTP IPC timed out for " + request.url);
        return {false, {}, http::OutboundError::timeout, "IPC timeout waiting for outbound HTTP result"};
    }

    return ipc::deserialize_outbound_http_response(*reply);
}

} // namespace merovingian::homeserver
