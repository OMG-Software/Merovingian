// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "WorkerEventLoop.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/crypto/IpcAuthKey.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentServerSigningKey.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/RoomReloadSnapshot.hpp"
#include "merovingian/federation/EduDispositionResult.hpp"
#include "merovingian/federation/EduDispositionStatus.hpp"
#include "merovingian/federation/FederationEndpoint.hpp"
#include "merovingian/federation/InboundEduEnvelope.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/InviteAcceptResult.hpp"
#include "merovingian/federation/InviteRequest.hpp"
#include "merovingian/federation/MembershipAcceptResult.hpp"
#include "merovingian/federation/MembershipEventTemplate.hpp"
#include "merovingian/federation/PduIngestionResult.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/federation/Transactions.hpp"
#include "merovingian/federation/WorkerRelayKind.hpp"
#include "merovingian/federation_worker/IpcKeyFd.hpp"
#include "merovingian/federation_worker/RoomReloadCoalescer.hpp"
#include "merovingian/federation_worker/StoreReadGuard.hpp"
#include "merovingian/federation_worker/WorkerDatabaseConfig.hpp"
#include "merovingian/federation_worker/WorkerRelayFrame.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RuntimeStartOptions.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/WorkerIpcLimits.hpp"
#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/http/OutboundError.hpp"
#include "merovingian/http/OutboundResult.hpp"
#include "merovingian/ipc/FederationIpcFrames.hpp"
#include "merovingian/ipc/IpcChannel.hpp"
#include "merovingian/ipc/MembershipTemplateIngest.hpp"
#include "merovingian/ipc/RoomSnapshotAssembler.hpp"
#include "merovingian/ipc/RoomSnapshotPageRequest.hpp"
#include "merovingian/net/ThreadPool.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace merovingian::federation_worker
{

namespace
{

    // Only synchronous sinks on this fed_request task inherit its main-side parent.
    thread_local std::uint64_t current_fed_parent_request_id{0U};

    class FedRequestParentScope final
    {
    public:
        explicit FedRequestParentScope(std::uint64_t parent_request_id) noexcept
            : previous_parent_request_id_{std::exchange(current_fed_parent_request_id, parent_request_id)}
        {
        }

        ~FedRequestParentScope() noexcept
        {
            current_fed_parent_request_id = previous_parent_request_id_;
        }

        FedRequestParentScope(FedRequestParentScope const&) = delete;
        auto operator=(FedRequestParentScope const&) -> FedRequestParentScope& = delete;
        FedRequestParentScope(FedRequestParentScope&&) = delete;
        auto operator=(FedRequestParentScope&&) -> FedRequestParentScope& = delete;

    private:
        std::uint64_t previous_parent_request_id_;
    };

    // ---- JSON helpers --------------------------------------------------------
    // The pdu_ingest frame uses the same JSON schema as the federation IPC
    // frames. Rather than keep a second hand-rolled parser here (which shared
    // the escaped-quote/substring bug of issue #320), route through the shared
    // canonicaljson-based helpers in merovingian::ipc.

    // Shared body for both pdu_ingest and membership_ingest frames — the two
    // IPC calls carry the identical InboundPduEnvelope payload, differing only
    // in the "type" (and membership_ingest's extra "endpoint") field, which
    // the caller writes before/after calling this.
    auto append_envelope_fields(std::string& result, federation::InboundPduEnvelope const& env) -> void
    {
        result += R"("event_id":)";
        result += ipc::ipc_json_str(env.event_id);
        result += R"(,"room_id":)";
        result += ipc::ipc_json_str(env.room_id);
        result += R"(,"room_version":)";
        result += ipc::ipc_json_str(env.room_version);
        result += R"(,"sender":)";
        result += ipc::ipc_json_str(env.sender);
        result += R"(,"event_type":)";
        result += ipc::ipc_json_str(env.event_type);
        if (env.state_key.has_value())
        {
            result += R"(,"state_key":)";
            result += ipc::ipc_json_str(*env.state_key);
        }
        result += R"(,"origin_server_ts":)";
        result += std::to_string(env.origin_server_ts);
        result += R"(,"depth":)";
        result += std::to_string(env.depth);
        result += R"(,"auth_event_ids":[)";
        auto first = true;
        for (auto const& id : env.auth_event_ids)
        {
            if (!first)
            {
                result += ',';
            }
            first = false;
            result += ipc::ipc_json_str(id);
        }
        result += R"(],"prev_event_ids":[)";
        first = true;
        for (auto const& id : env.prev_event_ids)
        {
            if (!first)
            {
                result += ',';
            }
            first = false;
            result += ipc::ipc_json_str(id);
        }
        result += R"(],"signatures":[)";
        first = true;
        for (auto const& sig : env.signatures)
        {
            if (!first)
            {
                result += ',';
            }
            first = false;
            result += R"({"sn":)";
            result += ipc::ipc_json_str(sig.server_name);
            result += R"(,"ki":)";
            result += ipc::ipc_json_str(sig.key_id);
            result += R"(,"sig":)";
            result += ipc::ipc_json_str(sig.signature);
            result += '}';
        }
        result += R"(],"json":)";
        result += ipc::ipc_json_str(env.json);
        result += R"(,"origin":)";
        result += ipc::ipc_json_str(env.origin);
    }

    // Serialize an InboundPduEnvelope for the pdu_ingest IPC call to main.
    auto serialize_pdu_ingest(federation::InboundPduEnvelope const& env) -> std::string
    {
        auto result = std::string{R"({"type":"pdu_ingest",)"};
        result.reserve(512U + env.json.size());
        append_envelope_fields(result, env);
        result += '}';
        return result;
    }

    // FederationEndpoint values that reach membership_acceptor (send_join,
    // send_leave, send_knock only — see InboundRequest.cpp's route dispatch).
    [[nodiscard]] auto membership_endpoint_to_string(federation::FederationEndpoint endpoint) -> std::string_view
    {
        switch (endpoint)
        {
        case federation::FederationEndpoint::send_join:
            return "send_join";
        case federation::FederationEndpoint::send_leave:
            return "send_leave";
        case federation::FederationEndpoint::send_knock:
            return "send_knock";
        default:
            return "";
        }
    }

    // Serialize an (endpoint, InboundPduEnvelope) pair for the membership_ingest
    // IPC call to main. See docs/architecture.md, "Federation worker room
    // staleness" — membership_acceptor must relay through main the same way
    // pdu_sink already does, or a join/leave/knock accepted by a worker is
    // invisible to main's own store (and therefore to every subsequent /send
    // message from that member, which main authorizes against its own state).
    auto serialize_membership_ingest(federation::FederationEndpoint endpoint, federation::InboundPduEnvelope const& env)
        -> std::string
    {
        auto result = std::string{R"({"type":"membership_ingest","endpoint":)"};
        result.reserve(512U + env.json.size());
        result += ipc::ipc_json_str(membership_endpoint_to_string(endpoint));
        result += ',';
        append_envelope_fields(result, env);
        if (env.omit_members)
        {
            result += R"(,"omit_members":1)";
        }
        result += '}';
        return result;
    }

    // Deserialize a `pdu_ingest_result` JSON frame from main.
    auto deserialize_pdu_ingest_result(std::string_view json) -> federation::PduIngestionResult
    {
        auto result = federation::PduIngestionResult{};
        auto const status_str = ipc::ipc_json_get_str(json, "status");
        if (status_str == "accepted")
        {
            result.status = federation::PduIngestionStatus::accepted;
        }
        else if (status_str == "rejected_auth")
        {
            result.status = federation::PduIngestionStatus::rejected_auth;
        }
        else if (status_str == "rejected_state_conflict")
        {
            result.status = federation::PduIngestionStatus::rejected_state_conflict;
        }
        else if (status_str == "rejected_invalid")
        {
            result.status = federation::PduIngestionStatus::rejected_invalid;
        }
        else if (status_str == "missing_prev_state")
        {
            result.status = federation::PduIngestionStatus::missing_prev_state;
        }
        else if (status_str == "soft_failed")
        {
            result.status = federation::PduIngestionStatus::soft_failed;
        }
        else if (status_str == "main_overloaded")
        {
            result.status = federation::PduIngestionStatus::main_overloaded;
        }
        else if (status_str == "deferred")
        {
            result.status = federation::PduIngestionStatus::deferred;
        }
        else if (status_str == "rejected_acl")
        {
            result.status = federation::PduIngestionStatus::rejected_acl;
        }
        else if (status_str == "already_stored")
        {
            result.status = federation::PduIngestionStatus::already_stored;
        }
        else
        {
            result.status = federation::PduIngestionStatus::internal_error;
        }
        result.reason = ipc::ipc_json_get_str(json, "reason");
        result.accepted_stream_ordering = ipc::ipc_json_get_u64(json, "stream_ordering");
        return result;
    }

    // Serialize an InboundEduEnvelope for the edu_ingest IPC call to main.
    // content_json is embedded as an escaped JSON string value (via
    // ipc::ipc_json_str), the same way append_envelope_fields embeds a raw
    // PDU's "json" field above — this is what makes it safe for content_json
    // to itself contain arbitrary nested JSON (including a literal "type"
    // key, as e.g. m.room_key.withheld content does) without corrupting the
    // outer frame that ipc_json_get_str parses on the other side.
    auto serialize_edu_ingest(federation::InboundEduEnvelope const& env, std::uint64_t parent_request_id) -> std::string
    {
        auto result = std::string{R"({"type":"edu_ingest","parent_request_id":)"};
        result.reserve(256U + env.content_json.size());
        result += std::to_string(parent_request_id);
        result += R"(,"edu_type":)";
        result += ipc::ipc_json_str(env.edu_type);
        result += R"(,"origin":)";
        result += ipc::ipc_json_str(env.origin);
        result += R"(,"content_json":)";
        result += ipc::ipc_json_str(env.content_json);
        result += '}';
        return result;
    }

    // Deserialize an `edu_ingest_result` JSON frame from main.
    auto deserialize_edu_ingest_result(std::string_view json) -> federation::EduDispositionResult
    {
        auto result = federation::EduDispositionResult{};
        auto const status_str = ipc::ipc_json_get_str(json, "status");
        if (status_str == "accepted")
        {
            result.status = federation::EduDispositionStatus::accepted;
        }
        else if (status_str == "dropped_unknown_type")
        {
            result.status = federation::EduDispositionStatus::dropped_unknown_type;
        }
        else
        {
            result.status = federation::EduDispositionStatus::rejected_invalid;
        }
        result.reason = ipc::ipc_json_get_str(json, "reason");
        return result;
    }

    // MembershipAcceptResult carries whole event JSON blobs (auth_chain_json,
    // state_json) that can legitimately contain arbitrary remote-user content
    // — including strings that look like `"status":123` or `"accepted":true`
    // if a message body happens to contain them. A substring-needle scanner
    // (as pdu_ingest's simpler string/int-only fields use above) would then
    // misparse the *outer* frame, exactly the class of bug issue #320 fixed
    // for ipc::ipc_json_get_str. Parse the whole frame as real JSON instead.
    [[nodiscard]] auto field_string(canonicaljson::Object const& obj, std::string_view key) -> std::string
    {
        for (auto const& member : obj)
        {
            if (member.key == key)
            {
                if (auto const* text = std::get_if<std::string>(&member.value->storage()); text != nullptr)
                {
                    return *text;
                }
            }
        }
        return {};
    }

    [[nodiscard]] auto field_bool(canonicaljson::Object const& obj, std::string_view key) -> bool
    {
        for (auto const& member : obj)
        {
            if (member.key == key)
            {
                if (auto const* flag = std::get_if<bool>(&member.value->storage()); flag != nullptr)
                {
                    return *flag;
                }
            }
        }
        return false;
    }

    [[nodiscard]] auto field_int(canonicaljson::Object const& obj, std::string_view key) -> std::int64_t
    {
        for (auto const& member : obj)
        {
            if (member.key == key)
            {
                if (auto const* number = std::get_if<std::int64_t>(&member.value->storage()); number != nullptr)
                {
                    return *number;
                }
            }
        }
        return 0;
    }

    [[nodiscard]] auto field_string_array(canonicaljson::Object const& obj, std::string_view key)
        -> std::vector<std::string>
    {
        auto out = std::vector<std::string>{};
        for (auto const& member : obj)
        {
            if (member.key != key)
            {
                continue;
            }
            auto const* array = std::get_if<canonicaljson::Array>(&member.value->storage());
            if (array == nullptr)
            {
                break;
            }
            for (auto const& entry : *array)
            {
                if (auto const* text = std::get_if<std::string>(&entry.storage()); text != nullptr)
                {
                    out.push_back(*text);
                }
            }
        }
        return out;
    }

    // Deserialize a `membership_ingest_result` JSON frame from main.
    auto deserialize_membership_ingest_result(std::string_view json) -> federation::MembershipAcceptResult
    {
        auto result = federation::MembershipAcceptResult{};
        auto const parsed = canonicaljson::parse_lossless(json);
        auto const* obj = parsed.error == canonicaljson::ParseError::none
                              ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                              : nullptr;
        if (obj == nullptr)
        {
            result.status = 500U;
            result.reason = "membership_ingest_result frame did not parse as a JSON object";
            return result;
        }
        result.accepted = field_bool(*obj, "accepted");
        result.status = static_cast<std::uint16_t>(field_int(*obj, "status"));
        result.reason = field_string(*obj, "reason");
        result.room_version = field_string(*obj, "room_version");
        result.signed_event_json = field_string(*obj, "signed_event_json");
        result.auth_chain_json = field_string_array(*obj, "auth_chain_json");
        result.state_json = field_string_array(*obj, "state_json");
        result.knock_room_state_json = field_string_array(*obj, "knock_room_state_json");
        result.members_omitted = field_bool(*obj, "members_omitted");
        result.servers_in_room = field_string_array(*obj, "servers_in_room");
        return result;
    }

    // Serialize an InviteRequest for the invite_ingest IPC call to main.
    // invite_event_json and each invite_room_state_json entry are embedded as
    // escaped JSON string values via ipc::ipc_json_str, the same technique
    // append_envelope_fields uses for a raw PDU's "json" field above — safe
    // for arbitrary nested event content for the same reason.
    auto serialize_invite_ingest(federation::InviteRequest const& request) -> std::string
    {
        auto result = std::string{R"({"type":"invite_ingest","room_id":)"};
        result.reserve(512U + request.invite_event_json.size());
        result += ipc::ipc_json_str(request.room_id);
        result += R"(,"event_id":)";
        result += ipc::ipc_json_str(request.event_id);
        result += R"(,"room_version":)";
        result += ipc::ipc_json_str(request.room_version);
        result += R"(,"invite_event_json":)";
        result += ipc::ipc_json_str(request.invite_event_json);
        result += R"(,"origin":)";
        result += ipc::ipc_json_str(request.origin);
        result += R"(,"invite_room_state_json":[)";
        auto first = true;
        for (auto const& state_json : request.invite_room_state_json)
        {
            if (!first)
            {
                result += ',';
            }
            first = false;
            result += ipc::ipc_json_str(state_json);
        }
        result += "]}";
        return result;
    }

    // Deserialize an `invite_ingest_result` JSON frame from main. Reuses the
    // same full-JSON-parse approach as deserialize_membership_ingest_result
    // above: "accepted"/"status" are raw bool/int fields that
    // ipc::ipc_json_get_str (a quote-terminated string extractor) cannot
    // parse at all, and signed_event_json can legitimately carry arbitrary
    // nested event content.
    auto deserialize_invite_ingest_result(std::string_view json) -> federation::InviteAcceptResult
    {
        auto result = federation::InviteAcceptResult{};
        auto const parsed = canonicaljson::parse_lossless(json);
        auto const* obj = parsed.error == canonicaljson::ParseError::none
                              ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                              : nullptr;
        if (obj == nullptr)
        {
            result.status = 500U;
            result.reason = "invite_ingest_result frame did not parse as a JSON object";
            return result;
        }
        result.accepted = field_bool(*obj, "accepted");
        result.status = static_cast<std::uint16_t>(field_int(*obj, "status"));
        result.reason = field_string(*obj, "reason");
        result.signed_event_json = field_string(*obj, "signed_event_json");
        return result;
    }

    // Deserialize an `otk_claim_ingest_result` JSON frame from main.
    auto deserialize_otk_claim_ingest_result(std::string_view json) -> std::string
    {
        return ipc::ipc_json_get_str(json, "response_body");
    }

    // Deserialize a `user_devices_ingest_result` JSON frame from main.
    auto deserialize_user_devices_ingest_result(std::string_view json) -> std::string
    {
        return ipc::ipc_json_get_str(json, "response_body");
    }

    // Deserialize a `device_keys_query_ingest_result` JSON frame from main.
    auto deserialize_device_keys_query_ingest_result(std::string_view json) -> std::string
    {
        return ipc::ipc_json_get_str(json, "response_body");
    }

    // Deserialize a `profile_query_ingest_result` JSON frame from main. Uses
    // the same full-JSON-parse approach as deserialize_membership_ingest_result
    // above rather than ipc::ipc_json_get_str, since "found" is a raw bool
    // field that a quote-terminated string extractor cannot parse.
    auto deserialize_profile_query_ingest_result(std::string_view json) -> federation::FederationProfile
    {
        auto result = federation::FederationProfile{};
        auto const parsed = canonicaljson::parse_lossless(json);
        auto const* obj = parsed.error == canonicaljson::ParseError::none
                              ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                              : nullptr;
        if (obj == nullptr)
        {
            return result;
        }
        result.found = field_bool(*obj, "found");
        result.displayname = field_string(*obj, "displayname");
        result.avatar_url = field_string(*obj, "avatar_url");
        result.fields_json = field_string(*obj, "fields_json");
        return result;
    }

    // Serialize a room alias for the directory_query_ingest IPC call to main.
    auto serialize_directory_query_ingest(std::string_view room_alias) -> std::string
    {
        auto result = std::string{R"({"type":"directory_query_ingest","room_alias":)"};
        result.reserve(64U + room_alias.size());
        result += ipc::ipc_json_str(room_alias);
        result += '}';
        return result;
    }

    // Deserialize a `directory_query_ingest_result` JSON frame from main.
    auto deserialize_directory_query_ingest_result(std::string_view json) -> federation::FederationDirectory
    {
        auto result = federation::FederationDirectory{};
        auto const parsed = canonicaljson::parse_lossless(json);
        auto const* obj = parsed.error == canonicaljson::ParseError::none
                              ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                              : nullptr;
        if (obj == nullptr)
        {
            return result;
        }
        result.found = field_bool(*obj, "found");
        result.room_id = field_string(*obj, "room_id");
        result.servers = field_string_array(*obj, "servers");
        return result;
    }

    // Serialize an event_id and the X-Matrix-verified origin of the requesting
    // server for the event_query_ingest IPC call to main. Main, not the worker,
    // resolves the event's room and decides whether that origin may read it
    // (FED-2).
    auto serialize_event_query_ingest(std::string_view event_id, std::string_view origin) -> std::string
    {
        auto result = std::string{R"({"type":"event_query_ingest","event_id":)"};
        result.reserve(96U + event_id.size() + origin.size());
        result += ipc::ipc_json_str(event_id);
        result += R"(,"origin":)";
        result += ipc::ipc_json_str(origin);
        result += '}';
        return result;
    }

    // Deserialize an `event_query_ingest_result` JSON frame from main.
    auto deserialize_event_query_ingest_result(std::string_view json) -> federation::RoomReadResult
    {
        auto result = federation::RoomReadResult{};
        result.status = federation::room_read_status_from_name(ipc::ipc_json_get_str(json, "status"));
        if (result.status == federation::RoomReadStatus::ok)
        {
            result.body = ipc::ipc_json_get_str(json, "response_body");
        }
        return result;
    }

    // ---- The worker's store, from main (ADR-0733) ----------------------------
    // This process opens no database. Its store is filled at start from the rooms main lists and the snapshots main
    // sends, a room_sync reload asks main for the room again, and a key-cache miss asks main for one server's public
    // keys. Each page is one request: main answers it from a snapshot it read with its read transaction already closed.

    constexpr auto store_page_timeout = std::chrono::seconds{60};
    constexpr auto server_keys_timeout = std::chrono::seconds{30};

    auto log_store_refusal(std::string_view what, std::string_view reply) -> void
    {
        auto reason = ipc::ipc_json_get_str(reply, "refused");
        LOG_ERROR("Federation worker: main did not send " + std::string{what} + ": " +
                  (reason.empty() ? std::string{"malformed answer"} : reason));
    }

    // Every room main lists, page by page in order. nullopt when main refuses, does not answer, or a page does not
    // follow from the one before.
    [[nodiscard]] auto room_ids_from_main(ipc::IpcChannel& channel) -> std::optional<std::vector<std::string>>
    {
        auto room_ids = std::vector<std::string>{};
        auto pages = std::uint64_t{1U};
        for (auto page = std::uint64_t{0U}; page < pages; ++page)
        {
            auto const reply = channel.send_request(ipc::serialize_room_list_request(page), store_page_timeout);
            if (!reply.has_value())
            {
                LOG_ERROR("Federation worker: main did not answer the room list request");
                return std::nullopt;
            }
            auto listed = ipc::deserialize_room_list_page(*reply);
            if (!listed.has_value())
            {
                log_store_refusal("the room list", *reply);
                return std::nullopt;
            }
            if (listed->page != page || listed->pages == 0U || (page != 0U && listed->pages != pages))
            {
                LOG_ERROR("Federation worker: main's room list pages are out of order");
                return std::nullopt;
            }
            pages = listed->pages;
            room_ids.insert(room_ids.end(), std::make_move_iterator(listed->room_ids.begin()),
                            std::make_move_iterator(listed->room_ids.end()));
        }
        return room_ids;
    }

    // One room's snapshot, page by page, for room_sync `generation` (0 for the start-up fill). nullopt when main
    // refuses or does not answer, or a page breaks the assembler's rules: a room is applied whole or not at all.
    [[nodiscard]] auto snapshot_from_main(ipc::IpcChannel& channel, std::string_view room_id, std::uint64_t generation)
        -> std::optional<database::RoomReloadSnapshot>
    {
        auto assembler = ipc::RoomSnapshotAssembler{std::string{room_id}, generation};
        while (!assembler.complete())
        {
            auto const request = ipc::RoomSnapshotPageRequest{std::string{room_id}, generation, assembler.next_page()};
            auto const reply = channel.send_request(ipc::serialize_room_snapshot_request(request), store_page_timeout);
            if (!reply.has_value())
            {
                LOG_ERROR("Federation worker: main did not answer a snapshot request for room_id=" +
                          std::string{room_id});
                return std::nullopt;
            }
            auto page = ipc::deserialize_room_snapshot_page(*reply);
            if (!page.has_value())
            {
                log_store_refusal("a snapshot of room_id=" + std::string{room_id}, *reply);
                return std::nullopt;
            }
            if (!assembler.add_page(std::move(*page)))
            {
                LOG_ERROR("Federation worker: main's snapshot pages do not fit together for room_id=" +
                          std::string{room_id});
                return std::nullopt;
            }
        }
        return assembler.take();
    }

    // The start-up fill. False only when main will not list its rooms: the worker then does not start, and the
    // supervisor restarts it. A room main cannot send is logged and left out; its next room_sync fills it.
    [[nodiscard]] auto fill_store_from_main(ipc::IpcChannel& channel, database::PersistentStore& store) -> bool
    {
        auto const room_ids = room_ids_from_main(channel);
        if (!room_ids.has_value())
        {
            return false;
        }
        // One room at a time: main holds the pages of one snapshot per channel.
        auto snapshots = std::vector<database::RoomReloadSnapshot>{};
        snapshots.reserve(room_ids->size());
        for (auto const& room_id : *room_ids)
        {
            auto snapshot = snapshot_from_main(channel, room_id, 0U);
            if (!snapshot.has_value())
            {
                LOG_ERROR("Federation worker: room_id=" + room_id + " left out of the start-up copy");
                continue;
            }
            snapshots.push_back(std::move(*snapshot));
        }
        auto const filled = database::fill_store_from_room_snapshots(store, std::move(snapshots));
        LOG_INFO("Federation worker: store filled from main: rooms=" + std::to_string(filled) + " of " +
                 std::to_string(room_ids->size()));
        // A key-cache miss asks main, which answers from its own key table, public columns only.
        store.remote_signing_key_source =
            [&channel](
                std::string_view server_name) -> std::optional<std::vector<database::PersistentServerSigningKey>> {
            auto const reply =
                channel.send_request(ipc::serialize_server_keys_request(server_name), server_keys_timeout);
            if (!reply.has_value())
            {
                return std::nullopt;
            }
            return ipc::deserialize_server_keys_result(*reply);
        };
        return true;
    }

    // The channel's dispatch thread starts before the runtime exists, because the start-up fill needs the channel's
    // replies. Frames main sends meanwhile wait here, in order, until run() opens the gate with the real handler, or
    // are dropped once it is closed without one. The handler is set once and never changed after, so it is called
    // without the lock. Close the gate before the channel stops, or the dispatch thread never returns.
    class DispatchGate final
    {
    public:
        using Handler = std::function<void(std::uint64_t, std::string)>;

        auto dispatch(std::uint64_t id, std::string json) -> void
        {
            auto lock = std::unique_lock{mu_};
            cv_.wait(lock, [this]() {
                return handler_ != nullptr || closed_;
            });
            if (handler_ == nullptr)
            {
                return;
            }
            // The handler is set once and never changed, and it runs for as long as a request takes; holding mu_
            // across it would block open() and close() behind that request.
            lock.unlock(); // LOCK_RELEASE: reviewed — handler_ is immutable once set; never call it under mu_
            handler_(id, std::move(json));
        }

        auto open(Handler handler) -> void
        {
            {
                auto const lock = std::lock_guard{mu_};
                handler_ = std::move(handler);
            }
            cv_.notify_all();
        }

        auto close() -> void
        {
            {
                auto const lock = std::lock_guard{mu_};
                closed_ = true;
            }
            cv_.notify_all();
        }

    private:
        std::mutex mu_{};
        std::condition_variable cv_{};
        Handler handler_{};
        bool closed_{false};
    };

    // Closes the gate when run() leaves, on every path. Declared after the channel, so it runs before the channel's
    // destructor joins the dispatch thread.
    class DispatchGateCloser final
    {
    public:
        explicit DispatchGateCloser(DispatchGate& gate) noexcept
            : gate_{gate}
        {
        }

        ~DispatchGateCloser() noexcept
        {
            gate_.close();
        }

        DispatchGateCloser(DispatchGateCloser const&) = delete;
        auto operator=(DispatchGateCloser const&) -> DispatchGateCloser& = delete;
        DispatchGateCloser(DispatchGateCloser&&) = delete;
        auto operator=(DispatchGateCloser&&) -> DispatchGateCloser& = delete;

    private:
        DispatchGate& gate_;
    };

} // namespace

WorkerEventLoop::WorkerEventLoop(core::FileDescriptor ipc_fd, core::FileDescriptor ipc_key_fd, config::Config config,
                                 std::uint32_t threads, std::uint32_t shard_index)
    : ipc_fd_{std::move(ipc_fd)}
    , ipc_key_fd_{std::move(ipc_key_fd)}
    , config_{std::move(config)}
    , threads_{threads}
    , shard_index_{shard_index}
{
}

auto WorkerEventLoop::shard_index() const noexcept -> std::uint32_t
{
    return shard_index_;
}

auto WorkerEventLoop::run() -> void
{
    // Read the IPC auth key main already derived from the operator master-key
    // file and wrote into our inherited key-fd at spawn time (see
    // homeserver::WorkerSupervisor::spawn_and_connect). This worker never
    // opens the master key file itself — see ADR-0062, "Federation worker
    // holds no secret files; secrets arrive over inherited fds" (0.12.13
    // audit, finding N1). Fail closed if the key is missing, short, long, or
    // otherwise unusable: an unauthenticated handshake would let any peer
    // inject AEAD frames.
    auto const auth_key = federation_worker::read_ipc_auth_key(std::move(ipc_key_fd_));
    if (!auth_key.has_value())
    {
        LOG_CRITICAL("Federation worker: failed to read a usable IPC auth key from the inherited key-fd");
        return;
    }

    // Clear the master-key-file path in this worker's own config copy before
    // starting the runtime, so no later code path — reached today or added in
    // the future — can open the file this process must never touch. Every
    // consumer of security.secrets.master_key_file that is actually reachable
    // from start_runtime() in a worker either is skipped outright (signing
    // disabled bypasses key generation/decryption) or degrades safely to "no
    // master key configured" on an empty path; see docs/threat-model.md,
    // "Worker trust boundary".
    federation_worker::clear_master_key_file(config_);
    // The same for the SMTP relay (ADR-0220): only main sends email, so the worker's copy names no
    // relay and no password file, and nothing started in this process can send or open one.
    config_.server().email = config::EmailConfig{};

    // ADR-0733: this process opens no database. Its copy names none (main.cpp cleared it before Landlock; cleared again
    // here whoever built the loop), so the runtime opens an in-memory store, which main fills over the channel below.
    federation_worker::clear_database_location(config_);

    // Create the IPC channel first; the blocking key exchange completes here
    // before the runtime starts. Both peers derive the same frame cap from the
    // same configured response and request budgets rather than negotiating it.
    auto const max_frame_bytes = homeserver::worker_ipc_frame_bytes(config_);
    auto dispatch_gate = DispatchGate{};
    auto channel = std::make_unique<ipc::IpcChannel>(std::move(ipc_fd_), ipc::IpcChannel::Role::client, *auth_key,
                                                     max_frame_bytes);
    auto* channel_ptr = channel.get();
    // The dispatch thread starts now, before the runtime: the start-up fill needs the channel's replies. Frames main
    // sends meanwhile wait at the gate (declared before the channel, closed before it stops).
    auto gate_closer = DispatchGateCloser{dispatch_gate};
    channel->set_request_handler([&dispatch_gate](std::uint64_t id, std::string json) {
        dispatch_gate.dispatch(id, std::move(json));
    });
    channel->start();

    // F-27 (ADR-0360): the one lock between the request threads that read this process's store and the
    // room_sync reloads that rewrite it. Declared before the runtime so it outlives every provider that
    // refers to it.
    auto store_guard = federation_worker::StoreReadGuard{};

    // Start a full HomeserverRuntime using the same config as main, on an in-memory store main fills (ADR-0733). It
    // does NOT write events: accepted PDUs are sent to main via pdu_ingest IPC and main commits them with the
    // authoritative counter.
    auto started = homeserver::start_runtime(homeserver::RuntimeStartOptions{
        .config = config_,
        // ADR-0078: the worker never signs and never asks main to sign for it.
        // start_runtime installs a provider that refuses every request, so a
        // compromised worker has no signing capability to abuse.
        .signing_disabled = true,
        // The worker's profile: a key-cache miss reads through to main (remote_signing_keys_read_through), and the
        // main-only start-up work (redaction reconciliation, the stream token epoch) is skipped.
        .database_load_profile = database::TableLoadProfile::federation_worker,
        // main.cpp has already applied the worker hardening (core-dump limit,
        // no_new_privs, capability drop, worker seccomp filter) when this is
        // on. Re-applying the main-process profile would call setrlimit,
        // which the worker filter denies (ISO-2, ADR-0112).
        .process_hardening_applied_by_caller = config_.federation_worker().apply_hardening,
        // FED-10, ADR-0153: each shard resolves keys within its share of the
        // configured budgets, so all shards together stay within them.
        .key_resolution_shards = config_.federation_worker().shards,
        // ADR-0296: registrations hold the as_token and hs_token, kept outside
        // this process's Landlock grants, and everything that uses the registry
        // runs in main. Loading them here only logged a rejection per start.
        .load_appservices = false,
        // ADR-0733: the store is filled from main before the runtime hydrates from it.
        .fill_store =
            [channel_ptr](database::PersistentStore& store) {
                return fill_store_from_main(*channel_ptr, store);
            },
    });
    if (!started.started)
    {
        LOG_CRITICAL("Federation worker: failed to start runtime: " + started.reason);
        return;
    }
    auto& runtime = started.runtime;
    homeserver::wire_federation_callbacks(runtime);
    // Every provider below that reads this store (ACL, room version, state, state_ids, event_auth,
    // get_missing_events, backfill, timestamp_to_event, hierarchy, the local make_leave/make_knock template)
    // now holds the shared lock for its own call. This comes before the overrides that relay to main: a
    // relay waits on another process and must hold no store lock while it does.
    store_guard.wrap_store_readers(runtime.federation);
    // Main judges the admin's federation policy before it forwards a request (ADR-0358).
    runtime.federation_policy_decided_upstream = true;

    // ADR-0285: the wired probe answers from this process's own event snapshot, which is taken at
    // start-up and is not main's record of what is stored. Left in place it could call a PDU main
    // never stored "handled". Unset, every PDU goes to main, which holds the record and checks.
    runtime.federation.pdu_already_stored = nullptr;

    // Override pdu_sink: instead of writing to DB directly, call main via IPC.
    runtime.federation.pdu_sink =
        [channel_ptr](federation::InboundPduEnvelope const& env) -> federation::PduIngestionResult {
        auto const json_body = serialize_pdu_ingest(env);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {federation::PduIngestionStatus::internal_error, "pdu_ingest IPC timeout"};
        }
        return deserialize_pdu_ingest_result(*reply);
    };

    // Override membership_acceptor the same way: wire_federation_callbacks()'s
    // default implementation (still used above for membership_template_provider,
    // etc.) writes send_join/send_leave/send_knock acceptances
    // straight into this process's own PersistentStore — which, per the "does
    // NOT write events" invariant this file states for pdu_sink above, main
    // never sees. A room this worker just accepted a remote join into would be
    // invisible to main's own store, and every subsequent /send message from
    // that member — authorized by main via pdu_sink against main's own state —
    // would then fail with "sender is not joined to the room" even though the
    // join genuinely succeeded. See docs/architecture.md, "Federation worker
    // room staleness".
    runtime.federation.membership_acceptor =
        [channel_ptr](federation::FederationEndpoint endpoint, [[maybe_unused]] std::string_view room_id,
                      [[maybe_unused]] std::string_view event_id,
                      federation::InboundPduEnvelope const& envelope) -> federation::MembershipAcceptResult {
        // room_id is redundant (envelope.room_id carries the same value) and event_id is
        // unused by the default implementation too.
        auto const json_body = serialize_membership_ingest(endpoint, envelope);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {false, 503U, "membership_ingest IPC timeout", {}, {}};
        }
        return deserialize_membership_ingest_result(*reply);
    };

    // Override membership_template_provider for make_join only (audit R04,
    // ADR-0185). In a restricted room the template names an authorising user
    // only after the allow conditions are checked, and those conditions name
    // OTHER rooms, whose state this shard's snapshot may not hold or may hold
    // stale (room_sync refreshes only the shard that owns a room). Main holds
    // every room, so it builds the template. make_leave and make_knock need
    // nothing outside the room being left or knocked on, so they stay local.
    runtime.federation.membership_template_provider =
        [channel_ptr, local_provider = runtime.federation.membership_template_provider](
            federation::FederationEndpoint endpoint, std::string_view room_id, std::string_view user_id,
            std::vector<std::string> const& supported_versions) -> std::optional<federation::MembershipEventTemplate> {
        if (endpoint != federation::FederationEndpoint::make_join)
        {
            return local_provider ? local_provider(endpoint, room_id, user_id, supported_versions) : std::nullopt;
        }
        auto const json_body = ipc::serialize_membership_template_ingest(
            ipc::MembershipTemplateIngest{std::string{room_id}, std::string{user_id}, supported_versions});
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            auto unavailable = federation::MembershipEventTemplate{};
            unavailable.error_status = 503U;
            unavailable.reason = R"({"errcode":"M_UNKNOWN","error":"membership_template_ingest IPC timeout"})";
            return unavailable;
        }
        return ipc::deserialize_membership_template_ingest_result(*reply);
    };

    // Override invite_handler the same way as membership_acceptor above: the
    // default implementation (LocalHttpRouter.cpp) persists the invite's
    // membership row, invite metadata, and event straight into this
    // process's own PersistentStore. PUT /_matrix/federation/{v1,v2}/invite
    // is room-scoped, so with federation.worker.shards >= 1 (the shipped
    // example config) it is handled by a worker, and the write landed only
    // in that worker's own store — invisible to main, which is the only
    // process a real client's /sync ever reaches. A remote server inviting
    // one of this server's local users to a room hosted elsewhere was
    // therefore silently swallowed: the invite never appeared in the
    // invited user's own sync, with nothing to indicate why. See
    // docs/architecture.md, "Federation worker invite relay".
    runtime.federation.invite_handler =
        [channel_ptr](federation::InviteRequest const& request) -> federation::InviteAcceptResult {
        auto const json_body = serialize_invite_ingest(request);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {false, 503U, "invite_ingest IPC timeout", {}};
        }
        return deserialize_invite_ingest_result(*reply);
    };

    // Override edu_sink the same way as pdu_sink/membership_acceptor above:
    // relay the EDU to main via IPC instead of handling (or dropping) it in
    // this process. A prior "EDUs are ephemeral, safe to drop" design set
    // this to a hard no-op for every EDU type — but m.direct_to_device
    // carries E2EE megolm room-key shares and m.room_key.withheld notices,
    // which are not safe to drop: a recipient whose key-share transaction
    // landed on this worker shard was left permanently unable to decrypt any
    // message encrypted with that session, with no trace anywhere in main's
    // logs (the transaction was still ack'd 200 to the sending server, and
    // InboundRequest.cpp counts an EDU with no edu_sink installed as
    // "dispatched" rather than "dropped"). Typing/receipt/presence really
    // are ephemeral, but relaying everything through one uniform path avoids
    // special-casing by EDU type. See docs/architecture.md, "Federation
    // worker EDU relay".
    runtime.federation.edu_sink =
        [channel_ptr](federation::InboundEduEnvelope const& envelope) -> federation::EduDispositionResult {
        auto const parent_request_id = current_fed_parent_request_id;
        if (parent_request_id == 0U)
        {
            return {federation::EduDispositionStatus::rejected_invalid, "edu_ingest has no active fed_request parent"};
        }
        auto const json_body = serialize_edu_ingest(envelope, parent_request_id);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {federation::EduDispositionStatus::rejected_invalid, "edu_ingest IPC timeout"};
        }
        return deserialize_edu_ingest_result(*reply);
    };

    // Override one_time_keys_claim_provider: relay the raw claim request body
    // to main via IPC instead of deciding it against this process's own
    // PersistentStore::one_time_keys. The default implementation
    // (LocalHttpRouter.cpp) decides key availability from an in-memory
    // vector hydrated once at worker startup, then issues a DELETE. Two
    // processes each running this locally can both believe the same
    // one-time key is still available — main's copy is never invalidated by
    // a DELETE a worker issued, and vice versa — handing the same key to two
    // different claimants and reusing an Olm one-time prekey, exactly the
    // property it exists to prevent. It also goes stale in one direction
    // only: keys uploaded through main after this worker started are
    // invisible to it, so claims can dry up here even as the user's client
    // keeps replenishing keys. Routing every claim through main's single
    // authoritative copy removes the split-brain. See docs/architecture.md,
    // "Federation worker one-time-key claim relay".
    runtime.federation.one_time_keys_claim_provider = [channel_ptr](std::string_view request_body) -> std::string {
        // GHSA-3p5v-vrg8-f545 (ADR-0595): main admits the relay only for the verified request it forwarded.
        auto const reply =
            federation_worker::relay_to_main(*channel_ptr, federation::WorkerRelayKind::otk_claim, request_body,
                                             current_fed_parent_request_id, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {};
        }
        return deserialize_otk_claim_ingest_result(*reply);
    };

    // Override user_devices_provider, device_keys_query_provider, and
    // profile_query_provider the same way as one_time_keys_claim_provider
    // above: relay to main via IPC instead of deciding against this
    // process's own PersistentStore. Unlike the write-relay hooks
    // (pdu_sink/membership_acceptor/edu_sink/invite_handler), these three are
    // pure reads with no DB write to make visible — the bug is that
    // PersistentStore::device_keys and PersistentStore::profiles are
    // per-process snapshots hydrated once at worker startup, and none of the
    // three backing routes (GET /user/devices/{userId}, POST
    // /user/keys/query, GET /query/profile) are room-scoped, so unlike
    // room_sync there is no per-room notification that could ever refresh
    // them — a device or profile change made through main's client-server
    // API after this worker started is permanently invisible to it. A remote
    // server querying one of these routes for a real local user/device can
    // therefore get a spurious 404 indefinitely, which for
    // GET /user/devices/{userId} specifically means a sender can never learn
    // which device to target an m.room_key to-device share at, leaving the
    // recipient permanently unable to decrypt the corresponding megolm
    // session with no error surfaced anywhere (the transaction that carried
    // the encrypted message is still delivered and accepted normally). See
    // docs/architecture.md, "Federation worker user/device/profile/event query
    // relay".
    runtime.federation.user_devices_provider = [channel_ptr](std::string_view user_id) -> std::string {
        // GHSA-3p5v-vrg8-f545 (ADR-0595): main admits the relay only for the verified request it forwarded.
        auto const reply =
            federation_worker::relay_to_main(*channel_ptr, federation::WorkerRelayKind::user_devices, user_id,
                                             current_fed_parent_request_id, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {};
        }
        return deserialize_user_devices_ingest_result(*reply);
    };

    runtime.federation.device_keys_query_provider = [channel_ptr](std::string_view request_body) -> std::string {
        // GHSA-3p5v-vrg8-f545 (ADR-0595): main admits the relay only for the verified request it forwarded.
        auto const reply =
            federation_worker::relay_to_main(*channel_ptr, federation::WorkerRelayKind::device_keys_query, request_body,
                                             current_fed_parent_request_id, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {};
        }
        return deserialize_device_keys_query_ingest_result(*reply);
    };

    runtime.federation.profile_query_provider =
        [channel_ptr](std::string_view user_id) -> federation::FederationProfile {
        // GHSA-3p5v-vrg8-f545 (ADR-0595): main admits the relay only for the verified request it forwarded.
        auto const reply =
            federation_worker::relay_to_main(*channel_ptr, federation::WorkerRelayKind::profile_query, user_id,
                                             current_fed_parent_request_id, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {};
        }
        return deserialize_profile_query_ingest_result(*reply);
    };

    // GET /query/directory carries no room ID either, so a room alias created through main after
    // this worker started is not in its snapshot and a remote server asking for it got a 404.
    runtime.federation.directory_query_provider =
        [channel_ptr](std::string_view room_alias) -> federation::FederationDirectory {
        auto const json_body = serialize_directory_query_ingest(room_alias);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {};
        }
        return deserialize_directory_query_ingest_result(*reply);
    };

    // The published directory names no room, so no room_sync refreshes this snapshot for it and the request
    // lands on one shard whatever it lists; `third_party_instance_id` also needs the appservice registrations
    // no worker loads (ADR-0296). Main lists from its own store (ADR-0461).
    runtime.federation.public_rooms_provider =
        [channel_ptr](federation::PublicRoomsRequest const& request) -> std::optional<std::string> {
        auto const reply =
            channel_ptr->send_request(ipc::serialize_public_rooms_ingest(request), std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return std::nullopt;
        }
        return ipc::deserialize_public_rooms_ingest_result(*reply);
    };

    // Override event_query_provider the same way as the three providers
    // above, but for a different reason: GET /_matrix/federation/v1/event/
    // {eventId} carries no room ID, so unlike state/state_ids/backfill/
    // get_missing_events (which are room-scoped and stay correct via
    // notify_room_changed()/reload_room()) it always routes to shard 0
    // regardless of which shard actually owns the event's room. Relaying
    // through main — which receives every event via pdu_sink from every
    // shard — answers correctly no matter which shard the request happened
    // to land on, rather than trying to fix shard selection for an ID space
    // with no room ID to key off. See docs/architecture.md, "Federation
    // worker user/device/profile/event query relay".
    runtime.federation.event_query_provider = [channel_ptr](std::string_view event_id,
                                                            std::string_view origin) -> federation::RoomReadResult {
        auto const json_body = serialize_event_query_ingest(event_id, origin);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {};
        }
        return deserialize_event_query_ingest_result(*reply);
    };

    // Two pools, deliberately separate (see FederationWorkerConfig::relay_threads
    // and federation::federation_endpoint_requires_main_relay): local_pool handles
    // fed_requests answerable entirely from this worker's own local snapshot and
    // always completes quickly; relay_pool handles fed_requests that call back to
    // main over IPC (pdu_sink/edu_sink/membership_acceptor/invite_handler, the
    // query-provider relays) plus outbound_http_request, both of which spend most
    // of their time blocked on I/O rather than CPU. Sharing one small pool between
    // these two classes let a burst of slow relay calls exhaust every thread and
    // starve the fast local endpoints of anywhere to run — the federation worker
    // shard hang this splits the pool to fix.
    auto local_pool = net::ThreadPool{threads_};
    auto relay_pool = net::ThreadPool{config_.federation_worker().relay_threads};

    // room_sync reloads have a thread of their own, so a burst of them cannot queue ahead of local_pool's reads, and
    // the coalescer merges them per room (ADR-0623). Its queue holds at most one entry per room.
    auto reload_pool = net::ThreadPool{1U};
    auto reload_coalescer = RoomReloadCoalescer{};
    auto run_reload_round = std::function<void(std::string const&)>{};
    run_reload_round = [&runtime, &store_guard, channel_ptr, &reload_pool, &reload_coalescer,
                        &run_reload_round](std::string const& room_id) {
        auto const again = reload_coalescer.run_round(room_id, [&](std::uint64_t generation) {
            // ADR-0733: main reads the room under the permit it issued with this generation's room_sync.
            auto const ok = store_guard.reload_room_from(runtime.database.persistent_store, room_id,
                                                         [channel_ptr, generation](std::string_view room) {
                                                             return snapshot_from_main(*channel_ptr, room, generation);
                                                         });
            if (!ok)
            {
                LOG_WARNING("Federation worker: room_sync reload failed for room_id=" + room_id);
            }
            if (!channel_ptr->send_notification(
                    ipc::serialize_room_sync_result(room_id, ok ? "ok" : "failed", generation)))
            {
                LOG_WARNING("Federation worker: room_sync result could not be sent for room_id=" + room_id);
            }
        });
        if (again && !reload_pool.submit([&run_reload_round, room_id]() {
                std::invoke(run_reload_round, room_id);
            }))
        {
            reload_coalescer.abandon(room_id);
            LOG_WARNING("Federation worker: room_sync dropped because the reload thread is stopped");
        }
    };

    auto shutdown = std::atomic<bool>{false};
    auto shutdown_mu = std::mutex{};
    auto shutdown_cv = std::condition_variable{};

    // Wakes the main worker thread when the main process sends a shutdown
    // notification or closes the IPC fd without one.
    auto signal_shutdown = [&shutdown, &shutdown_mu, &shutdown_cv]() {
        {
            auto const lk = std::lock_guard{shutdown_mu};
            shutdown.store(true);
        }
        shutdown_cv.notify_all();
    };

    dispatch_gate.open([&runtime, channel_ptr, &local_pool, &relay_pool, &reload_pool, &reload_coalescer,
                        &run_reload_round, signal_shutdown](std::uint64_t id, std::string json) {
        auto const type = ipc::ipc_json_get_str(json, "type");
        if (type == "fed_request")
        {
            // Deserializing here (cheap JSON parsing, no I/O) rather than inside
            // the submitted task lets us classify the endpoint and pick a pool
            // before committing a thread — the whole point of the split.
            auto request = ipc::deserialize_fed_request(json);
            auto const route_match = federation::match_federation_route(request.method, request.target);
            auto const needs_relay =
                route_match.matched && federation::federation_endpoint_requires_main_relay(route_match.route.endpoint);
            auto& target_pool = needs_relay ? relay_pool : local_pool;
            auto const enqueued =
                target_pool.submit([&runtime, channel_ptr, id, request = std::move(request)]() mutable {
                    auto const response = [&runtime, &request, id]() {
                        auto const parent_scope = FedRequestParentScope{id};
                        return homeserver::handle_federation_http_request(runtime, request);
                    }();
                    channel_ptr->send_response(id, ipc::serialize_fed_response(response));
                });
            if (!enqueued)
            {
                auto const response = homeserver::LocalHttpResponse{
                    503U, R"({"errcode":"M_UNAVAILABLE","error":"Federation worker thread pool unavailable"})"};
                channel_ptr->send_response(id, ipc::serialize_fed_response(response));
            }
        }
        else if (type == "outbound_http_request")
        {
            // Outbound HTTP blocks on a remote server's response, same as a
            // main-relay round-trip — route it to the generously-sized relay
            // pool so it can never be starved by (or itself starve) the fast
            // local endpoints, and the IPC reader thread is never blocked.
            auto const outbound_enqueued =
                relay_pool.submit([&runtime, channel_ptr, id, json = std::move(json)]() mutable {
                    auto const request = ipc::deserialize_outbound_http_request(json);
                    auto outcome = http::OutboundResult{};
                    if (runtime.outbound_client)
                    {
                        outcome = runtime.outbound_client->perform(request);
                    }
                    else
                    {
                        outcome = {false, {}, http::OutboundError::network_error, "outbound client not available"};
                    }
                    channel_ptr->send_response(id, ipc::serialize_outbound_http_response(outcome));
                });
            if (!outbound_enqueued)
            {
                auto const outcome = http::OutboundResult{
                    false, {}, http::OutboundError::network_error, "federation worker relay thread pool unavailable"};
                channel_ptr->send_response(id, ipc::serialize_outbound_http_response(outcome));
            }
        }
        else if (type == "room_sync")
        {
            // Fire-and-forget: no reply is sent. Asks main for this one room
            // again and swaps it into our own PersistentStore copy, which is
            // otherwise as main sent it at this worker's own startup (ADR-0733,
            // docs/architecture.md, "Federation worker room staleness"). Runs
            // on the reload pool, NOT inline on this handler: the reload waits
            // on main's answer and then waits for
            // the readers of the store (StoreReadGuard) to drain, and main
            // sends this very notification (from its pdu_ingest handler's
            // notify_room_changed) moments before the pdu_ingest response.
            // Blocking the channel's dispatch thread on either would park
            // every later queued request behind it. The read from main takes
            // no lock; only the in-memory swap excludes readers (F-27,
            // ADR-0360). One accepted PDU is one notification and a reload
            // reads the whole room, so notifications go through the coalescer
            // (ADR-0623): main commits before it notifies, and a notification
            // that finds the room scheduled makes the coalescer run a round
            // whose read begins after it, so the last PDU is never lost.
            auto const room_id = ipc::ipc_json_get_str(json, "room_id");
            auto const generation = ipc::ipc_json_get_u64(json, "generation");
            if (reload_coalescer.note_changed(room_id, generation) &&
                !reload_pool.submit([&run_reload_round, room_id]() {
                    std::invoke(run_reload_round, room_id);
                }))
            {
                reload_coalescer.abandon(room_id);
                LOG_WARNING("Federation worker: room_sync dropped because the reload thread is stopped");
            }
        }
        else if (type == "shutdown")
        {
            // Do NOT call channel->stop() here: this handler runs on the IPC
            // dispatch thread, and IpcChannel::stop() joins that thread.  A
            // thread cannot join itself; doing so throws
            // std::system_error(EDEADLK). Signal shutdown so the main worker
            // thread wakes and stops the channel from a different thread.
            signal_shutdown();
        }
        else
        {
            LOG_WARNING("Federation worker: unexpected IPC request type: " + type);
        }
    });

    LOG_INFO("[fed-worker/" + std::to_string(shard_index_) + "] Federation worker ready: threads=" +
             std::to_string(threads_) + " relay_threads=" + std::to_string(config_.federation_worker().relay_threads));

    // Block until shutdown is signalled.  A watcher thread also wakes us if
    // the main process closes the IPC fd without sending a notification.
    // The watcher checks `shutdown` in addition to `healthy()` so it exits
    // promptly after a graceful "shutdown" notification: on a clean shutdown
    // the channel stays healthy, so checking only healthy() deadlocks here.
    auto watcher = std::thread{[channel_ptr, signal_shutdown, &shutdown]() {
        while (!shutdown.load() && channel_ptr->healthy())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        signal_shutdown();
    }};

    {
        auto lk = std::unique_lock{shutdown_mu};
        shutdown_cv.wait(lk, [&shutdown]() {
            return shutdown.load();
        });
    }

    watcher.join();

    // Drain the thread pools first: any in-flight handler still needs to send
    // its IPC response through the channel. Closing the channel before the
    // pools empty would make send_response fail and drop responses on the
    // floor (issue #327). request_stop() blocks until all workers exit.
    local_pool.request_stop();
    relay_pool.request_stop();
    reload_pool.request_stop();

    // Idempotent: if the shutdown handler already stopped the channel this
    // is a no-op; otherwise it joins the reader and dispatch threads now.
    channel->stop();

    LOG_INFO("Federation worker stopped");
}

} // namespace merovingian::federation_worker
