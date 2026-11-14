// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/WorkerPool.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/crypto/IpcAuthKey.hpp"
#include "merovingian/crypto/MasterKey.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/SnapshotReaderPool.hpp"
#include "merovingian/federation/EduDispositionResult.hpp"
#include "merovingian/federation/EduDispositionStatus.hpp"
#include "merovingian/federation/FederationDirectory.hpp"
#include "merovingian/federation/FederationEndpoint.hpp"
#include "merovingian/federation/FederationProfile.hpp"
#include "merovingian/federation/InboundEduEnvelope.hpp"
#include "merovingian/federation/InboundIngestion.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/InboundRequest.hpp"
#include "merovingian/federation/InviteAcceptResult.hpp"
#include "merovingian/federation/InviteRequest.hpp"
#include "merovingian/federation/InviteRoomState.hpp"
#include "merovingian/federation/MembershipAcceptResult.hpp"
#include "merovingian/federation/PduIngestionResult.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/federation/ServerAcl.hpp"
#include "merovingian/federation/ServerAclBudget.hpp"
#include "merovingian/federation/Transactions.hpp"
#include "merovingian/federation/WorkerRelayBinding.hpp"
#include "merovingian/federation/WorkerRelayKind.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RuntimeLockRelease.hpp"
#include "merovingian/homeserver/WorkerIpcLimits.hpp"
#include "merovingian/homeserver/WorkerSnapshotService.hpp"
#include "merovingian/homeserver/WorkerSnapshotSources.hpp"
#include "merovingian/ipc/FederationIpcFrames.hpp"
#include "merovingian/ipc/IpcChannel.hpp"
#include "merovingian/net/ThreadPool.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <initializer_list>
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

    // Minimal JSON helpers for pdu_ingest frames.
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
        if (auto const* value = integer_member(*root, "omit_members"); value != nullptr)
        {
            env.omit_members = *value == 1;
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
        case federation::PduIngestionStatus::deferred:
            status_str = "deferred";
            break;
        case federation::PduIngestionStatus::already_stored:
            status_str = "already_stored";
            break;
        case federation::PduIngestionStatus::rejected_acl:
            status_str = "rejected_acl";
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
    // append_envelope_fields in WorkerEventLoop.cpp) plus one extra
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
        body += R"(,"members_omitted":)";
        body += result.members_omitted ? "true" : "false";
        body += R"(,"servers_in_room":)";
        body += json_str_array_literal(result.servers_in_room);
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
        if (type == "membership_template_ingest")
        {
            return R"({"type":"membership_template_ingest_result","found":true,"reason":"{\"errcode\":\"M_UNKNOWN\",\"error\":\"main at per-channel in-flight cap\"}","error_status":503})";
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
        body += R"(,"fields_json":)";
        body += json_str(profile.fields_json);
        body += '}';
        return body;
    }

    auto serialize_directory_query_ingest_result(federation::FederationDirectory const& directory) -> std::string
    {
        auto body = std::string{R"({"type":"directory_query_ingest_result","found":)"};
        body += directory.found ? "true" : "false";
        body += R"(,"room_id":)";
        body += json_str(directory.room_id);
        body += R"(,"servers":)";
        body += json_str_array_literal(directory.servers);
        body += '}';
        return body;
    }

    auto serialize_event_query_ingest_result(federation::RoomReadResult const& result) -> std::string
    {
        auto body = std::string{R"({"type":"event_query_ingest_result","status":)"};
        body += json_str(federation::room_read_status_name(result.status));
        body += R"(,"response_body":)";
        body += json_str(result.body);
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
    // and "12" when neither is known, matching InboundRequest.cpp.
    [[nodiscard]] auto relayed_room_version(HomeserverRuntime& runtime, std::string_view room_id,
                                            std::string_view claimed) -> std::string
    {
        auto version = std::string{};
        if (runtime.federation.room_version_resolver)
        {
            // A relayed PDU queues here behind whatever holds runtime.mutex (a
            // join, a send, a sync). Complement run 9 (A6) lost a race by tens of
            // milliseconds with no log line to say where, so the wait is logged.
            auto const waiting_since = std::chrono::steady_clock::now();
            auto guard = RuntimeLock{runtime.mutex};
            auto const waited =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - waiting_since);
            observability::log_diagnostic("worker_pool", "relay.runtime_lock_acquired",
                                          {
                                              {"wait_ms", std::to_string(waited.count()), false}
            });
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
        bool locally_denied{false};
        bool policy_refused{false};
        // The verified event's sender; empty when refused.
        std::string sender{};
    };

    // `authorised_here` is this server's name when the relay is a send_join
    // the membership acceptor may co-sign as a restricted join's authorising
    // server (R04, ADR-0185): such an event cannot carry our signature yet, and
    // the acceptor checks the allow conditions before it adds one. Empty for
    // every other relay, which must already carry every signature it needs.
    [[nodiscard]] auto verify_relayed_event_signature(HomeserverRuntime& runtime, std::string_view event_json,
                                                      std::string const& room_version,
                                                      std::string_view authorised_here = {}) -> RelayedSignature
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
        if (sender_server.empty() || federation::signature_key_ids_for_server(pdu.signatures, sender_server).empty())
        {
            return {{}, "relayed event has no signature from its sender's server"};
        }
        // ADR-0390: the operator's policy for the server that wrote it, before any of its keys is looked up.
        if (auto const policy_refusal = federation::operator_policy_refusal(runtime.federation, sender_server);
            !policy_refusal.empty())
        {
            return {{}, "server is denied by operator policy", false, true};
        }
        // No trustworthy client address travels in these relay frames. All
        // main relay misses share the bounded unknown-source bucket; never let
        // a worker choose a source to evade main's quota. Each lookup may go to
        // the network, so runtime.mutex is released around it.
        auto const resolve = [&runtime](std::string_view server_name, std::string_view key_id) {
            auto const unlocked = RuntimeLockRelease{};
            return federation::resolve_verification_key(runtime.federation, {}, server_name, key_id);
        };
        // R05: every key ID listed for the sender's server, not only the first.
        auto const decision = federation::authorize_federation_pdu_sender(pdu, std::nullopt, resolve);
        if (decision.status == 503U)
        {
            return {{}, "main key-resolution admission overloaded", true};
        }
        if (!decision.accepted)
        {
            return {{}, "relayed event failed signature verification: " + decision.reason};
        }

        // EVT-1: the sender's signature says nothing about a restricted join's
        // authorising server. events::authorize_event_against_auth_events only
        // sees that its signature is present, so verify it here, with a key main
        // resolves itself, before pdu_sink or the membership acceptor runs.
        auto const* policy = rooms::find_room_version_policy(room_version);
        auto const parsed = canonicaljson::parse_lossless(event_json);
        if (policy == nullptr || parsed.error != canonicaljson::ParseError::none)
        {
            return {{}, "relayed event could not be checked for an authorising server"};
        }
        if (!authorised_here.empty())
        {
            if (auto const authorising_key = federation::join_authorising_signature_key(parsed.value);
                authorising_key.has_value() && authorising_key->server_name == authorised_here)
            {
                return {pdu.event_id, {}, false, false, pdu.sender};
            }
        }
        auto const authorising = federation::verify_join_authorising_server_signature(parsed.value, *policy, resolve);
        if (authorising.status == 503U)
        {
            return {{}, "main key-resolution admission overloaded", true};
        }
        if (!authorising.accepted)
        {
            return {{}, "relayed event failed authorising-server verification: " + authorising.reason};
        }
        return {pdu.event_id, {}, false, false, pdu.sender};
    }

    struct RelayedEnvelope final
    {
        // Set only when the frame passed; otherwise `refusal` says why.
        std::optional<federation::InboundPduEnvelope> envelope{};
        std::string refusal{};
        bool locally_denied{false};
        bool policy_refused{false};
    };

    // Rebuilds the envelope from the verified event JSON rather than taking
    // the worker's separately framed fields, and refuses a frame that
    // disagrees with the event it carries. Only the transport origin (used to
    // choose where to backfill from; anything fetched there is verified
    // again) is taken from the frame.
    [[nodiscard]] auto reverify_relayed_envelope(HomeserverRuntime& runtime,
                                                 federation::InboundPduEnvelope const& frame,
                                                 std::string_view authorised_here = {}) -> RelayedEnvelope
    {
        auto const room_version = relayed_room_version(runtime, frame.room_id, frame.room_version);
        auto const signature = verify_relayed_event_signature(runtime, frame.json, room_version, authorised_here);
        if (!signature.refusal.empty())
        {
            return {std::nullopt, signature.refusal, signature.locally_denied, signature.policy_refused};
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

    // F-21 and F-24 (ADR-0358, ADR-0359): main, not a worker, decides what an admin's policy rule and a room's
    // m.room.server_acl allow. A worker's store is a snapshot (PostgreSQL workers hold no policy rules at all, and
    // only the shard that owns a room is told when it changes), and a worker is the process most exposed to hostile
    // input, so a decision it made is not relied on: everything a worker relays is judged again here, against
    // main's own store, for the transport origin (`origin`, the worker's own claim, which the proxy has already
    // authenticated and judged) and, once the event is verified, for the server its sender belongs to.

    // The reason a verified origin is refused by the admin's federation policy rule (deny, or quarantine), or empty
    // when it is allowed. The policy server is not asked: that is made once per request by the proxy.
    [[nodiscard]] auto relay_origin_policy_refusal(HomeserverRuntime& runtime, std::string_view origin) -> std::string
    {
        if (origin.empty())
        {
            return {};
        }
        auto const decision = evaluate_inbound_federation_policy(runtime, origin, false);
        if (decision.allowed)
        {
            return {};
        }
        return decision.reason.public_summary.empty() ? decision.reason.code : decision.reason.public_summary;
    }

    // The reason `room_id`'s own m.room.server_acl, read under runtime.mutex from main's store, denies any of
    // `servers`, or empty when none is denied. Spec: server-server-api.md "Server Access Control Lists (ACLs)".
    [[nodiscard]] auto relay_room_acl_refusal(HomeserverRuntime& runtime, std::string_view room_id,
                                              std::initializer_list<std::string_view> servers) -> std::string
    {
        if (room_id.empty())
        {
            return {};
        }
        auto const guard = RuntimeLock{runtime.mutex};
        // One budget for the checks of the whole relayed frame (ADR-0653).
        auto budget = federation::ServerAclBudget{};
        for (auto const server : servers)
        {
            if (!server.empty() &&
                !federation::room_server_acl_allows(runtime.database.persistent_store, room_id, server, budget))
            {
                return "server is denied by room ACL";
            }
        }
        return {};
    }

    // Both checks that need only the frame: the policy rule for the transport origin, then the room ACL for it.
    [[nodiscard]] auto relay_origin_refusal(HomeserverRuntime& runtime, std::string_view origin,
                                            std::string_view room_id) -> std::string
    {
        if (auto policy = relay_origin_policy_refusal(runtime, origin); !policy.empty())
        {
            return policy;
        }
        return relay_room_acl_refusal(runtime, room_id, {origin});
    }

    // GHSA-3p5v-vrg8-f545 (ADR-0595): whether a claim or query relay is one the request it names as its parent could
    // cause. `digest` is computed by the caller before it takes runtime.mutex, from the argument the frame carries;
    // call this after the lock is held, as the EDU admission is, so a parent that finished during the wait cannot
    // authorise anything. Each digest is admitted once.
    [[nodiscard]] auto worker_relay_admitted(ipc::IpcChannel& receiving_channel, std::string_view request_json,
                                             std::optional<std::string> const& digest, std::string_view frame_type)
        -> bool
    {
        auto const parent_request_id = ipc::ipc_json_get_u64(request_json, "parent_request_id");
        if (digest.has_value() && receiving_channel.consume_pending_relay(parent_request_id, *digest))
        {
            return true;
        }
        LOG_WARNING(std::string{frame_type} +
                    " refused: no live verified parent request on this channel carries it, or it was already relayed");
        return false;
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
    // F-21, F-24: the origin's policy rule and the room's ACL, in main's own store, before a key is looked up.
    if (auto const refusal = relay_origin_refusal(runtime, frame.origin, frame.room_id); !refusal.empty())
    {
        log_relay_refused("pdu_ingest", frame.event_id, refusal);
        return {federation::PduIngestionStatus::rejected_acl, refusal};
    }
    // ADR-0285: an event main already stores was handled when it first arrived. Answered before
    // the signature is re-verified (no key lookup) and without touching pdu_sink, so a re-sent PDU
    // has no side effect here. The frame's claim cannot do harm: "stored" only ever suppresses work,
    // and the worker is told nothing it could not learn from the answer to a re-send.
    if (!frame.event_id.empty() && pdu_event_already_stored(runtime, frame.room_id, frame.event_id))
    {
        return {federation::PduIngestionStatus::already_stored, "event already stored"};
    }
    auto const relayed = reverify_relayed_envelope(runtime, frame);
    if (!relayed.envelope.has_value())
    {
        log_relay_refused("pdu_ingest", frame.event_id, relayed.refusal);
        return {relayed.policy_refused   ? federation::PduIngestionStatus::rejected_acl
                : relayed.locally_denied ? federation::PduIngestionStatus::main_overloaded
                                         : federation::PduIngestionStatus::rejected_invalid,
                relayed.refusal};
    }
    // F-24: the server the verified event's sender belongs to is judged too, so a denied server cannot relay
    // its events through an allowed peer (and the worker's reading of the ACL cannot be what lets them in).
    if (auto const refusal =
            relay_room_acl_refusal(runtime, relayed.envelope->room_id, {server_name_of(relayed.envelope->sender)});
        !refusal.empty())
    {
        log_relay_refused("pdu_ingest", frame.event_id, refusal);
        return {federation::PduIngestionStatus::rejected_acl, refusal};
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
    // F-21, F-24: spec "Server Access Control Lists (ACLs)" lists send_join, send_leave and send_knock among the
    // endpoints an ACL protects; the origin's policy rule applies as to any request. Main's store decides.
    if (auto const refusal = relay_origin_refusal(runtime, frame.origin, frame.room_id); !refusal.empty())
    {
        log_relay_refused("membership_ingest", frame.event_id, refusal);
        result.status = 403U;
        result.reason = refusal;
        return serialize_membership_ingest_result(result);
    }
    // TRUST BOUNDARY (ADR-0071): verified before the runtime lock is taken,
    // because resolving the sender's key may go to the network. A send_join
    // naming one of our users as its authorising user is co-signed by the
    // acceptor after it checks the allow conditions (R04, ADR-0185), so only
    // that one signature is left to it.
    auto const our_server = endpoint == federation::FederationEndpoint::send_join
                                ? std::string{runtime.config.server().server_name}
                                : std::string{};
    auto const relayed = reverify_relayed_envelope(runtime, frame, our_server);
    if (!relayed.envelope.has_value())
    {
        log_relay_refused("membership_ingest", frame.event_id, relayed.refusal);
        result.status = relayed.locally_denied ? 503U : 403U;
        result.reason = relayed.refusal;
        return serialize_membership_ingest_result(result);
    }
    if (auto const refusal =
            relay_room_acl_refusal(runtime, relayed.envelope->room_id, {server_name_of(relayed.envelope->sender)});
        !refusal.empty())
    {
        log_relay_refused("membership_ingest", frame.event_id, refusal);
        result.status = 403U;
        result.reason = refusal;
        return serialize_membership_ingest_result(result);
    }
    // The worker's own copy of the request's omit_members is a hint about what the joining server
    // accepts, not a fact about the event: the verified envelope takes only that from the frame.
    auto envelope = *relayed.envelope;
    envelope.omit_members = frame.omit_members;
    {
        auto guard = RuntimeLock{runtime.mutex};
        result = runtime.federation.membership_acceptor(endpoint, envelope.room_id, {}, envelope);
    }
    return serialize_membership_ingest_result(result);
}

auto verified_send_edu_digests(LocalHttpRequest const& request, std::uint32_t max_edus) -> std::vector<std::string>
{
    auto digests = std::vector<std::string>{};
    if (!request.sig_verified || request.verified_origin.empty())
    {
        return digests;
    }
    auto const route = federation::match_federation_route(request.method, request.target);
    if (!route.matched || route.route.endpoint != federation::FederationEndpoint::transaction)
    {
        return digests;
    }
    auto const edus = federation::extract_transaction_edus(request.body);
    if (edus.size() > max_edus)
    {
        return digests;
    }
    digests.reserve(edus.size());
    for (auto const& [edu_type, content_json] : edus)
    {
        auto digest = federation::edu_relay_digest(edu_type, content_json);
        if (!digest.has_value())
        {
            return {};
        }
        digests.push_back(std::move(*digest));
    }
    return digests;
}

auto handle_edu_ingest_request(HomeserverRuntime& runtime, std::string_view request_json,
                               ipc::IpcChannel& receiving_channel) -> std::string
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
    // F-74 (ADR-0395): hash before taking the runtime lock; the digest is of the bytes the worker relayed.
    auto const digest = federation::edu_relay_digest(envelope->edu_type, envelope->content_json);
    auto result = federation::EduDispositionResult{};
    {
        auto guard = RuntimeLock{runtime.mutex};
        // Check after any runtime-lock wait. A channel-local parent ID is only a
        // routing reference: it must still name a live main-verified origin on
        // the exact channel that delivered this relay, and the EDU must be one the
        // verified body carried and no earlier relay used (consume_pending_edu marks
        // it used under the pending lock). The pending mutex is released before
        // invoking the real sink (including persistence).
        auto const parent_request_id = ipc::ipc_json_get_u64(request_json, "parent_request_id");
        if (!digest.has_value() || !receiving_channel.consume_pending_edu(parent_request_id, envelope->origin, *digest))
        {
            LOG_WARNING("edu_ingest refused: no matching live verified parent, or the EDU is not in its body "
                        "(or was already relayed); origin=" +
                        envelope->origin + " edu_type=" + envelope->edu_type);
            return serialize_edu_ingest_result({federation::EduDispositionStatus::rejected_invalid,
                                                "edu_ingest has no matching live verified parent"});
        }
        // F-21: the origin is the one main authenticated for this request (checked just above), so the admin's
        // policy rule is applied to it here: a rule added while the request was in flight still holds.
        if (auto const refusal = relay_origin_policy_refusal(runtime, envelope->origin); !refusal.empty())
        {
            result.status = federation::EduDispositionStatus::rejected_invalid;
            result.reason = refusal;
        }
        else if (runtime.federation.edu_sink)
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
    // F-14: an honest worker names the X-Matrix-verified origin. A blank one would skip the origin checks below and the
    // invite handler's sender-equals-origin guard, so it is refused rather than guessed from the sender.
    if (request.origin.empty())
    {
        log_relay_refused("invite_ingest", request.event_id, "relayed frame names no origin");
        result.status = 403U;
        result.reason = "relayed frame names no origin";
        return serialize_invite_ingest_result(result);
    }
    // F-21, F-24: the origin's policy rule and the room's ACL (the invite endpoint is one an ACL protects).
    if (auto const refusal = relay_origin_refusal(runtime, request.origin, request.room_id); !refusal.empty())
    {
        log_relay_refused("invite_ingest", request.event_id, refusal);
        result.status = 403U;
        result.reason = refusal;
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
        result.status = signature.locally_denied ? 503U : 403U;
        result.reason = refusal;
        return serialize_invite_ingest_result(result);
    }
    // F-14: the server the verified invite's sender belongs to is judged by the room's ACL too, as pdu_ingest and
    // membership_ingest do, so the worker's reading of the ACL (or its choice of origin) cannot let a denied server in.
    if (auto const acl_refusal = relay_room_acl_refusal(runtime, request.room_id, {server_name_of(signature.sender)});
        !acl_refusal.empty())
    {
        log_relay_refused("invite_ingest", request.event_id, acl_refusal);
        result.status = 403U;
        result.reason = acl_refusal;
        return serialize_invite_ingest_result(result);
    }
    // The stripped state travels in the same frame, so a compromised worker cannot hand main an
    // invite_room_state the worker did not check: the same validation (a create event, every
    // entry a signed PDU of this room) runs here with main's own key resolution.
    auto const state_decision = federation::validate_invite_room_state(
        request.room_id, room_version, request.invite_room_state_json, std::nullopt,
        [&runtime](std::string_view server_name, std::string_view key_id) {
            auto const unlocked = RuntimeLockRelease{};
            return federation::resolve_verification_key(runtime.federation, {}, server_name, key_id);
        });
    if (!state_decision.accepted)
    {
        log_relay_refused("invite_ingest", request.event_id, state_decision.reason);
        result.status = state_decision.status == 503U ? 503U : 400U;
        result.reason = state_decision.reason;
        return serialize_invite_ingest_result(result);
    }
    {
        auto guard = RuntimeLock{runtime.mutex};
        result = runtime.federation.invite_handler(request);
    }
    return serialize_invite_ingest_result(result);
}

auto handle_otk_claim_ingest_request(HomeserverRuntime& runtime, std::string_view request_json,
                                     ipc::IpcChannel& receiving_channel) -> std::string
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
    //
    // GHSA-3p5v-vrg8-f545 (ADR-0595): the claim deletes the keys it returns, and the worker's database role cannot
    // touch one_time_keys, so this relay is the only way the worker could. It is admitted only for the body of a
    // claim request main verified and forwarded on this channel, once.
    auto const request_body = json_get_str(request_json, "request_body");
    auto const digest = federation::worker_relay_digest(federation::WorkerRelayKind::otk_claim, request_body);
    auto response_body = std::string{};
    {
        auto guard = RuntimeLock{runtime.mutex};
        if (!worker_relay_admitted(receiving_channel, request_json, digest, "otk_claim_ingest"))
        {
            return serialize_otk_claim_ingest_result({});
        }
        if (runtime.federation.one_time_keys_claim_provider)
        {
            response_body = runtime.federation.one_time_keys_claim_provider(request_body);
        }
    }
    return serialize_otk_claim_ingest_result(response_body);
}

auto handle_user_devices_ingest_request(HomeserverRuntime& runtime, std::string_view request_json,
                                        ipc::IpcChannel& receiving_channel) -> std::string
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
    // The worker's role cannot read devices or device_keys, so the relay is bound to the user the verified request
    // named (GHSA-3p5v-vrg8-f545, ADR-0595).
    auto const user_id = json_get_str(request_json, "user_id");
    auto const digest = federation::worker_relay_digest(federation::WorkerRelayKind::user_devices, user_id);
    auto response_body = std::string{};
    {
        auto guard = RuntimeLock{runtime.mutex};
        if (!worker_relay_admitted(receiving_channel, request_json, digest, "user_devices_ingest"))
        {
            return serialize_user_devices_ingest_result({});
        }
        if (runtime.federation.user_devices_provider)
        {
            response_body = runtime.federation.user_devices_provider(user_id);
        }
    }
    return serialize_user_devices_ingest_result(response_body);
}

auto handle_device_keys_query_ingest_request(HomeserverRuntime& runtime, std::string_view request_json,
                                             ipc::IpcChannel& receiving_channel) -> std::string
{
    // Same stale-snapshot failure mode as handle_user_devices_ingest_request
    // above, for POST /_matrix/federation/v1/user/keys/query instead of
    // GET /user/devices/{userId}. See docs/architecture.md, "Federation
    // worker user/device/profile/event query relay".
    // Bound to the body of the verified query (GHSA-3p5v-vrg8-f545, ADR-0595).
    auto const request_body = json_get_str(request_json, "request_body");
    auto const digest = federation::worker_relay_digest(federation::WorkerRelayKind::device_keys_query, request_body);
    auto response_body = std::string{};
    {
        auto guard = RuntimeLock{runtime.mutex};
        if (!worker_relay_admitted(receiving_channel, request_json, digest, "device_keys_query_ingest"))
        {
            return serialize_device_keys_query_ingest_result({});
        }
        if (runtime.federation.device_keys_query_provider)
        {
            response_body = runtime.federation.device_keys_query_provider(request_body);
        }
    }
    return serialize_device_keys_query_ingest_result(response_body);
}

auto handle_profile_query_ingest_request(HomeserverRuntime& runtime, std::string_view request_json,
                                         ipc::IpcChannel& receiving_channel) -> std::string
{
    // Same stale-snapshot failure mode as handle_user_devices_ingest_request
    // above, for GET /_matrix/federation/v1/query/profile: PersistentStore::
    // profiles is likewise a worker-startup snapshot never refreshed by a
    // later client-server profile update on main. See docs/architecture.md,
    // "Federation worker user/device/profile/event query relay".
    // The worker's role cannot read profiles, so the relay is bound to the user_id of the verified query
    // (GHSA-3p5v-vrg8-f545, ADR-0595).
    auto const user_id = json_get_str(request_json, "user_id");
    auto const digest = federation::worker_relay_digest(federation::WorkerRelayKind::profile_query, user_id);
    auto profile = federation::FederationProfile{};
    {
        auto guard = RuntimeLock{runtime.mutex};
        if (!worker_relay_admitted(receiving_channel, request_json, digest, "profile_query_ingest"))
        {
            return serialize_profile_query_ingest_result({});
        }
        if (runtime.federation.profile_query_provider)
        {
            profile = runtime.federation.profile_query_provider(user_id);
        }
    }
    return serialize_profile_query_ingest_result(profile);
}

auto handle_directory_query_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // GET /_matrix/federation/v1/query/directory is not room-scoped, so the worker's per-room
    // `room_sync` reloads never refresh its alias table: an alias created through main after the
    // worker started would be a 404 for every remote server. The alias is read from main's own store.
    auto const room_alias = json_get_str(request_json, "room_alias");
    auto directory = federation::FederationDirectory{};
    {
        auto guard = RuntimeLock{runtime.mutex};
        if (runtime.federation.directory_query_provider && !room_alias.empty())
        {
            directory = runtime.federation.directory_query_provider(room_alias);
        }
    }
    return serialize_directory_query_ingest_result(directory);
}

auto handle_public_rooms_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // The frame comes from the worker (ADR-0071: untrusted input), so it is read with the checks the worker
    // applied to the remote server's request. The provider takes runtime.mutex itself and makes no network
    // call. No origin crosses: the directory is the same for every server.
    auto const request = ipc::deserialize_public_rooms_ingest(request_json);
    if (!request.has_value() || !runtime.federation.public_rooms_provider)
    {
        return ipc::serialize_public_rooms_ingest_result(std::nullopt);
    }
    return ipc::serialize_public_rooms_ingest_result(runtime.federation.public_rooms_provider(*request));
}

auto handle_membership_template_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string
{
    // The frame comes from the worker (ADR-0071: untrusted input). A template
    // carries no secret, only event IDs of the room's current state. The
    // worker checked the user against the X-Matrix origin, which main cannot
    // see, so main checks what it can: a well-formed frame naming a federated
    // user ID of ANOTHER server (make_join is how a remote server joins; a
    // local user joins through the client API). The provider takes
    // runtime.mutex itself and makes no network call.
    auto const request = ipc::deserialize_membership_template_ingest(request_json);
    if (!request.has_value() || !runtime.federation.membership_template_provider ||
        !auth::user_id_is_valid_federated(request->user_id) ||
        auth::user_id_server_name(request->user_id) == runtime.config.server().server_name)
    {
        return ipc::serialize_membership_template_ingest_result(std::nullopt);
    }
    return ipc::serialize_membership_template_ingest_result(runtime.federation.membership_template_provider(
        federation::FederationEndpoint::make_join, request->room_id, request->user_id, request->supported_versions));
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
    //
    // FED-2: the worker forwards the X-Matrix-verified origin with the event ID,
    // and the provider (run here against main's own store) resolves the event's
    // room and answers forbidden unless that origin may read it. A frame with no
    // origin therefore reads as forbidden, never as an unrestricted read.
    auto const event_id = json_get_str(request_json, "event_id");
    auto const origin = json_get_str(request_json, "origin");
    auto result = federation::RoomReadResult{};
    {
        auto guard = RuntimeLock{runtime.mutex};
        if (runtime.federation.event_query_provider)
        {
            result = runtime.federation.event_query_provider(event_id, origin);
        }
    }
    return serialize_event_query_ingest_result(result);
}

auto refuse_forbidden_worker_request(ipc::IpcChannel& channel, std::uint64_t request_id, std::string_view type) -> bool
{
    // sign_request used to be answered by signing whatever the worker sent with
    // any held key (a signing oracle, audit CRY-1). No legitimate worker sends
    // it any more, so a sign_request is always a sign of a compromised or badly
    // confused worker. It is answered with an explicit error so the sender's
    // send_request returns at once, and it is deliberately not forwarded to any
    // handler: no runtime.mutex, no crypto provider, no pool slot.
    // The channel stays up, matching how every other unexpected frame type is
    // handled (logged and dropped, never a teardown): the supervisor already
    // restarts a worker that dies, and tearing the channel down would only hand
    // a compromised worker a way to churn restarts. The payload and key id are
    // attacker-controlled and are never logged.
    if (type != "sign_request")
    {
        return false;
    }
    LOG_ERROR("WorkerPool: refused a sign_request frame from a federation worker; workers never sign (ADR-0078)");
    channel.send_response(
        request_id,
        R"({"type":"error","status":403,"reason":"sign_request is not permitted: federation workers never sign"})");
    return true;
}

namespace
{

    // Where the workers' store comes from (ADR-0733): main's database, read through connections of their own that
    // touch no row of main's live store and never runtime.mutex, each read's transaction closed before it returns.
    // The readers are opened here, one per shard, while WorkerPool is built and so before main enters a sandbox that
    // forbids opening a file or a socket (FreeBSD Capsicum): a read only leases one (ADR-0739). Keys come from main's
    // memory under the store's own key mutex.
    [[nodiscard]] auto make_snapshot_service(HomeserverRuntime& runtime, std::uint32_t shards)
        -> std::unique_ptr<WorkerSnapshotService>
    {
        auto const& main_store = runtime.database.persistent_store;
        // Shared by the two sources, which the service keeps for its life.
        auto readers = std::make_shared<database::SnapshotReaderPool>(main_store, shards);
        auto sources = WorkerSnapshotSources{};
        sources.list_rooms = [readers]() {
            return readers->room_ids();
        };
        sources.read_room = [readers](std::string_view room_id) {
            return readers->room_snapshot(room_id);
        };
        sources.server_keys = [&main_store](std::string_view server_name, std::size_t max_rows) {
            return database::public_signing_keys_of_server(main_store, server_name, max_rows);
        };
        sources.now = []() {
            return std::chrono::steady_clock::now();
        };
        return std::make_unique<WorkerSnapshotService>(
            std::move(sources), ipc::worker_store_page_budget(worker_ipc_frame_bytes(runtime.config)));
    }

} // namespace

WorkerPool::WorkerPool(config::FederationWorkerConfig const& cfg, HomeserverRuntime& runtime, std::string worker_path,
                       std::string config_path)
    : cfg_{cfg}
    , runtime_{runtime}
    , handler_pool_{cfg_.relay_threads}
    , snapshot_service_{make_snapshot_service(runtime, cfg.shards > 0U ? cfg.shards : 1U)}
    , snapshot_pool_{cfg_.shards > 0U ? cfg_.shards : 1U}
    , worker_path_{std::move(worker_path)}
    , config_path_{std::move(config_path)}
{
    // Both sides derive one frame cap from the same response and request budgets
    // in --config (worker_ipc_frame_bytes).
    auto const max_frame_bytes = worker_ipc_frame_bytes(runtime_.config);

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
        auto supervisor = std::make_unique<WorkerSupervisor>(worker_path_, config_path_, cfg_.request_timeout_seconds,
                                                             i, std::move(key_material), max_frame_bytes);
        supervisor->set_max_in_flight(cfg_.ipc_max_in_flight_requests);
        supervisor->set_dispatch_queue_limits(cfg_.ipc_max_dispatch_queue_count, cfg_.ipc_max_dispatch_queue_bytes);

        // Per-worker request handler: the IPC dispatch thread only classifies
        // the frame and enqueues the real work on handler_pool_. Each task
        // holds its own ref-counted channel snapshot and sends the response
        // from the pool, so a slow handler can never stall later queued frames.
        supervisor->set_channel_request_handler(
            [this, shard_index = i](std::shared_ptr< // SHARED_PTR: reviewed - queued receiver.
                                        ipc::IpcChannel> const& ch,
                                    std::uint64_t id, std::string json) {
                auto const type = json_get_str(json, "type");
                // The supervisor supplies the exact receiving channel. Capture it
                // in each task: a later snapshot could be another worker generation
                // with colliding channel-local parent IDs.
                // ADR-0078: frames a worker must never send are refused first,
                // inline, with no runtime lock, no handler-pool slot and no work.
                if (ch && refuse_forbidden_worker_request(*ch, id, type))
                {
                    return;
                }
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
                                // see WorkerEventLoop.cpp), and nothing else refreshes a
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
                            ch->send_response(id, handle_edu_ingest_request(runtime_, json, *ch));
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
                            ch->send_response(id, handle_otk_claim_ingest_request(runtime_, json, *ch));
                        }))
                    {
                        ch->send_response(id, overload_response_for(type));
                    }
                }
                else if (type == "user_devices_ingest")
                {
                    if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                            auto const guard = InFlightGuard{*ch};
                            ch->send_response(id, handle_user_devices_ingest_request(runtime_, json, *ch));
                        }))
                    {
                        ch->send_response(id, overload_response_for(type));
                    }
                }
                else if (type == "device_keys_query_ingest")
                {
                    if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                            auto const guard = InFlightGuard{*ch};
                            ch->send_response(id, handle_device_keys_query_ingest_request(runtime_, json, *ch));
                        }))
                    {
                        ch->send_response(id, overload_response_for(type));
                    }
                }
                else if (type == "profile_query_ingest")
                {
                    if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                            auto const guard = InFlightGuard{*ch};
                            ch->send_response(id, handle_profile_query_ingest_request(runtime_, json, *ch));
                        }))
                    {
                        ch->send_response(id, overload_response_for(type));
                    }
                }
                else if (type == "directory_query_ingest")
                {
                    if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                            auto const guard = InFlightGuard{*ch};
                            ch->send_response(id, handle_directory_query_ingest_request(runtime_, json));
                        }))
                    {
                        ch->send_response(id, overload_response_for(type));
                    }
                }
                else if (type == "public_rooms_ingest")
                {
                    if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                            auto const guard = InFlightGuard{*ch};
                            ch->send_response(id, handle_public_rooms_ingest_request(runtime_, json));
                        }))
                    {
                        ch->send_response(id, overload_response_for(type));
                    }
                }
                else if (type == "membership_template_ingest")
                {
                    if (!submit_limited(handler_pool_, ch, [this, ch, id, json = std::move(json)]() mutable {
                            auto const guard = InFlightGuard{*ch};
                            ch->send_response(id, handle_membership_template_ingest_request(runtime_, json));
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
                else if (type == "room_list_request" || type == "room_snapshot_request" ||
                         type == "server_keys_request")
                {
                    // The worker's store (ADR-0733): answered on the snapshot pool, under the channel's in-flight
                    // cap, with no runtime.mutex. Permits are checked by the service before any read (ADR-0735).
                    if (!submit_limited(snapshot_pool_, ch, [this, ch, id, type, json = std::move(json)]() mutable {
                            auto const guard = InFlightGuard{*ch};
                            ch->send_response(id, snapshot_service_->answer(ch, type, json));
                        }))
                    {
                        ch->send_response(id, ipc::serialize_worker_store_refusal(type, "overloaded"));
                    }
                }
                else if (type == "room_sync_result")
                {
                    // Fire-and-forget notification from the worker reporting the
                    // outcome of an asynchronous room_sync reload.  No response is
                    // sent.  Handle it inline on the dispatch thread: it only
                    // updates an in-memory status map.
                    auto const result_room_id = json_get_str(json, "room_id");
                    auto const result_state = json_get_str(json, "state");
                    auto const result_generation = ipc::ipc_json_get_u64(json, "generation");
                    // Main never sends generation 0: the worker uses it to report a room its start-up fill left out
                    // (ADR-0756). It is taken only for a room main listed to this channel, once, so a worker cannot
                    // grow main's status map with rooms main never named. Every worker's fill lists every room, and
                    // the status is kept per room, so only the shard that owns a room reports on it: another shard's
                    // failed copy says nothing about the copy requests for that room are routed to.
                    if (shard_for(result_room_id) != std::size_t{shard_index})
                    {
                        if (result_generation != 0U)
                        {
                            LOG_WARNING("WorkerPool shard " + std::to_string(shard_index) +
                                        ": ignoring a room_sync_result for a room another shard owns");
                        }
                    }
                    else if (result_generation == 0U)
                    {
                        if (result_state == "failed" && snapshot_service_->consume_fill_omission(ch, result_room_id))
                        {
                            record_room_left_out_of_fill(result_room_id);
                        }
                    }
                    else
                    {
                        record_room_sync_result(result_room_id, result_state, result_generation);
                    }
                }
                else
                {
                    LOG_WARNING("WorkerPool shard " + std::to_string(shard_index) +
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
    // The proxy sets these fields only after main's signature verification.
    // Ordinary/unsigned requests must not acquire an EDU-authorizing context.
    auto const verified_origin = request.sig_verified ? std::string_view{request.verified_origin} : std::string_view{};
    // F-74 (ADR-0395): the EDUs of the body main authenticated, so a relay can be bound to them.
    auto edu_digests = verified_send_edu_digests(
        request, std::max<std::uint32_t>(1U, runtime_.config.security().federation.max_transaction_edus));
    // GHSA-3p5v-vrg8-f545 (ADR-0595): the one claim or key/profile query relay this verified request may cause.
    auto relay_digests = verified_origin.empty()
                             ? std::vector<std::string>{}
                             : federation::verified_request_relay_digests(request.method, request.target, request.body);
    auto const reply = ch->send_request(ipc::serialize_fed_request(request), timeout, verified_origin,
                                        std::move(edu_digests), std::move(relay_digests));
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
    // The status is written even when the notification cannot be sent: a room first notified while the worker's
    // channel is down is one the worker may never have loaded, and main serves it until a reload of it succeeds.
    auto const generation = [this, room_id]() {
        auto guard = std::lock_guard{room_sync_mu_};
        auto const next = ++room_sync_generations_[std::string{room_id}];
        auto& status = room_sync_status_[std::string{room_id}];
        // A first notification may be for a room created after the worker's fill, which it has never loaded: that
        // room is held only once a reload of it succeeds (ADR-0756). A room the worker had already loaded stays held.
        auto const held = !status.state.empty() && status.held;
        status = RoomSyncStatus{"pending", next, held};
        return next;
    }();

    auto const ch = workers_[index]->channel_snapshot();
    if (!ch || !ch->healthy())
    {
        return;
    }

    // The permit is recorded before the notification is sent, so a worker that reloads at once finds it (ADR-0735).
    snapshot_service_->permit_reload(ch, room_id, generation);
    if (!ch->send_notification(ipc::serialize_room_sync_notification(room_id, generation)))
    {
        LOG_WARNING("Federation worker pool: room_sync notification could not be sent for room_id=" +
                    std::string{room_id});
    }
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
    snapshot_pool_.request_stop();

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

auto WorkerPool::worker_pid(std::size_t shard) const noexcept -> pid_t
{
    if (shard >= workers_.size() || !workers_[shard])
    {
        return -1;
    }
    return workers_[shard]->worker_pid();
}

auto WorkerPool::room_sync_status(std::string_view room_id) const -> RoomSyncStatus
{
    auto guard = std::lock_guard{room_sync_mu_};
    auto const it = room_sync_status_.find(std::string{room_id});
    if (it == room_sync_status_.end())
    {
        return RoomSyncStatus{"ok", 0U};
    }
    return it->second;
}

auto WorkerPool::record_room_sync_result(std::string_view room_id, std::string_view state, std::uint64_t generation)
    -> void
{
    auto guard = std::lock_guard{room_sync_mu_};
    auto const it = room_sync_generations_.find(std::string{room_id});
    if (it == room_sync_generations_.end() || generation > it->second)
    {
        // Stale or unmatched result for a room we no longer track; ignore it.
        return;
    }
    auto& status = room_sync_status_[std::string{room_id}];
    // Any successful reload, even of an older generation, means the worker now holds a copy of the room (ADR-0756).
    if (state == "ok")
    {
        status.held = true;
    }
    if (generation == it->second)
    {
        status.state = std::string{state};
        status.generation = generation;
    }
    // An older generation is also ignored; the pending entry for the latest
    // generation remains until its own result arrives or the room is re-synced.
}

auto WorkerPool::record_room_left_out_of_fill(std::string_view room_id) -> void
{
    auto guard = std::lock_guard{room_sync_mu_};
    auto& status = room_sync_status_[std::string{room_id}];
    status.held = false;
    if (status.state != "pending")
    {
        status.state = "failed";
    }
}

auto validate_worker_outbound_reply(http::OutboundRequest const& request, http::OutboundResult reply)
    -> http::OutboundResult
{
    auto detail = std::string{};
    detail.reserve(std::min(reply.error_detail.size(), max_worker_outbound_error_detail_bytes));
    for (auto const byte : reply.error_detail)
    {
        if (detail.size() >= max_worker_outbound_error_detail_bytes)
        {
            break;
        }
        auto const code = static_cast<unsigned char>(byte);
        detail += (code >= 0x20U && code < 0x7fU) ? byte : '?';
    }
    reply.error_detail = std::move(detail);

    if (reply.ok)
    {
        auto const status_in_range = reply.response.status >= 100U && reply.response.status <= 599U;
        if (!status_in_range || reply.response.body.size() > request.max_response_body_bytes)
        {
            return {false,
                    {},
                    http::OutboundError::network_error,
                    status_in_range ? "federation worker reply exceeds the response cap"
                                    : "federation worker reply has no valid HTTP status"};
        }
        return reply;
    }
    // A failure carries no answer: whatever status or body the worker attached is not the remote's.
    reply.response = {};
    return reply;
}

auto WorkerPool::send_outbound_request(http::OutboundRequest const& request, std::string_view room_id,
                                       std::chrono::seconds ipc_margin) -> http::OutboundResult
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

    // Give the IPC channel a buffer (10 s unless the caller asked for less)
    // beyond the HTTP total timeout so the worker always has time to return a
    // response before we declare a timeout.
    auto const ipc_timeout = std::chrono::seconds{static_cast<long>(request.total_timeout_seconds)} + ipc_margin;
    auto const reply = ch->send_request(ipc::serialize_outbound_http_request(request), ipc_timeout);
    if (!reply.has_value())
    {
        LOG_WARNING("WorkerPool: shard " + std::to_string(index) + " outbound HTTP IPC timed out for " + request.url);
        return {false, {}, http::OutboundError::timeout, "IPC timeout waiting for outbound HTTP result"};
    }

    return validate_worker_outbound_reply(request, ipc::deserialize_outbound_http_response(*reply));
}

} // namespace merovingian::homeserver
