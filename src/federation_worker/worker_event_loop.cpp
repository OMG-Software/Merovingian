// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "worker_event_loop.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/crypto/master_key.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/ipc/channel.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"
#include "merovingian/ipc/ipc_ed25519_provider.hpp"
#include "merovingian/net/thread_pool.hpp"
#include "merovingian/observability/logger.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
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
    // send_leave, send_knock only — see inbound_request.cpp's route dispatch).
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
    auto serialize_membership_ingest(federation::FederationEndpoint endpoint,
                                     federation::InboundPduEnvelope const& env) -> std::string
    {
        auto result = std::string{R"({"type":"membership_ingest","endpoint":)"};
        result.reserve(512U + env.json.size());
        result += ipc::ipc_json_str(membership_endpoint_to_string(endpoint));
        result += ',';
        append_envelope_fields(result, env);
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
    auto serialize_edu_ingest(federation::InboundEduEnvelope const& env) -> std::string
    {
        auto result = std::string{R"({"type":"edu_ingest","edu_type":)"};
        result.reserve(256U + env.content_json.size());
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

    [[nodiscard]] auto field_string_array(canonicaljson::Object const& obj,
                                          std::string_view key) -> std::vector<std::string>
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

    // Serialize a raw one-time-keys-claim request body for the
    // otk_claim_ingest IPC call to main. The body is the untouched federation
    // request payload (embedded as an escaped JSON string, same technique as
    // above), so main's own one_time_keys_claim_provider parses it exactly as
    // if it had received the federation request directly.
    auto serialize_otk_claim_ingest(std::string_view request_body) -> std::string
    {
        auto result = std::string{R"({"type":"otk_claim_ingest","request_body":)"};
        result.reserve(128U + request_body.size());
        result += ipc::ipc_json_str(request_body);
        result += '}';
        return result;
    }

    // Deserialize an `otk_claim_ingest_result` JSON frame from main.
    auto deserialize_otk_claim_ingest_result(std::string_view json) -> std::string
    {
        return ipc::ipc_json_get_str(json, "response_body");
    }

    // Serialize a user_id for the user_devices_ingest IPC call to main.
    auto serialize_user_devices_ingest(std::string_view user_id) -> std::string
    {
        auto result = std::string{R"({"type":"user_devices_ingest","user_id":)"};
        result.reserve(64U + user_id.size());
        result += ipc::ipc_json_str(user_id);
        result += '}';
        return result;
    }

    // Deserialize a `user_devices_ingest_result` JSON frame from main.
    auto deserialize_user_devices_ingest_result(std::string_view json) -> std::string
    {
        return ipc::ipc_json_get_str(json, "response_body");
    }

    // Serialize a raw device-keys-query request body for the
    // device_keys_query_ingest IPC call to main. The body is the untouched
    // federation request payload (embedded as an escaped JSON string, same
    // technique as serialize_otk_claim_ingest above), so main's own
    // device_keys_query_provider parses it exactly as if it had received the
    // federation request directly.
    auto serialize_device_keys_query_ingest(std::string_view request_body) -> std::string
    {
        auto result = std::string{R"({"type":"device_keys_query_ingest","request_body":)"};
        result.reserve(128U + request_body.size());
        result += ipc::ipc_json_str(request_body);
        result += '}';
        return result;
    }

    // Deserialize a `device_keys_query_ingest_result` JSON frame from main.
    auto deserialize_device_keys_query_ingest_result(std::string_view json) -> std::string
    {
        return ipc::ipc_json_get_str(json, "response_body");
    }

    // Serialize a user_id for the profile_query_ingest IPC call to main.
    auto serialize_profile_query_ingest(std::string_view user_id) -> std::string
    {
        auto result = std::string{R"({"type":"profile_query_ingest","user_id":)"};
        result.reserve(64U + user_id.size());
        result += ipc::ipc_json_str(user_id);
        result += '}';
        return result;
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
        return result;
    }

    // Serialize an event_id for the event_query_ingest IPC call to main.
    auto serialize_event_query_ingest(std::string_view event_id) -> std::string
    {
        auto result = std::string{R"({"type":"event_query_ingest","event_id":)"};
        result.reserve(64U + event_id.size());
        result += ipc::ipc_json_str(event_id);
        result += '}';
        return result;
    }

    // Deserialize an `event_query_ingest_result` JSON frame from main.
    auto deserialize_event_query_ingest_result(std::string_view json) -> std::string
    {
        return ipc::ipc_json_get_str(json, "response_body");
    }

} // namespace

WorkerEventLoop::WorkerEventLoop(core::FileDescriptor ipc_fd, config::Config config, std::uint32_t threads,
                                 std::uint32_t shard_index)
    : ipc_fd_{std::move(ipc_fd)}
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
    // Derive the IPC auth key from the operator master-key file so the worker
    // can authenticate the crypto_kx handshake. The main process derives the
    // same key from the same file; the key never crosses the IPC boundary.
    // The worker seccomp filter (issue #319) is installed in main() before
    // run(), but it allows open(), so reading the master-key file here works
    // under the filter. Fail closed if the master key is unavailable.
    auto const master_material = crypto::load_master_key_material(config_.security().secrets.master_key_file);
    if (!master_material.has_value())
    {
        LOG_CRITICAL("Federation worker: master key file '" + config_.security().secrets.master_key_file +
                     "' is unavailable; cannot authenticate IPC channel");
        return;
    }
    auto const auth_key = crypto::derive_ipc_auth_key(*master_material);
    if (!auth_key.has_value())
    {
        LOG_CRITICAL("Federation worker: failed to derive IPC auth key from master key file");
        return;
    }

    // Create the IPC channel first; the blocking key exchange completes here
    // before any runtime signing operation can be requested. The worker is the
    // client side of the exchange. max_frame_bytes must match what
    // WorkerPool derives for the supervisor side of this same channel (see
    // ipc::frame_bytes_for_response_cap) — both sides parse the same
    // --config file independently rather than negotiating it over IPC.
    auto const join_response_max_size = config::parse_size_limit(config_.security().federation.join_response_max_size);
    auto const max_frame_bytes =
        ipc::frame_bytes_for_response_cap(join_response_max_size.valid ? join_response_max_size.bytes : 0U);
    auto channel = std::make_unique<ipc::IpcChannel>(std::move(ipc_fd_), ipc::IpcChannel::Role::client, *auth_key,
                                                     max_frame_bytes);
    auto* channel_ptr = channel.get();

    // Delegate all Ed25519 signing to the main process so the Matrix signing
    // secret never enters this child address space.
    auto ipc_provider = ipc::IpcEd25519Provider{channel_ptr};

    // Start a full HomeserverRuntime using the same config as main. The worker
    // has its own DB connection for remote key resolution and room-version
    // lookups. It does NOT write events — accepted PDUs are sent to main via
    // pdu_ingest IPC and main commits them with the authoritative counter.
    auto started = homeserver::start_runtime(
        homeserver::RuntimeStartOptions{.config = config_, .signing_override = &ipc_provider});
    if (!started.started)
    {
        LOG_CRITICAL("Federation worker: failed to start runtime: " + started.reason);
        return;
    }
    auto& runtime = started.runtime;
    homeserver::wire_federation_callbacks(runtime);

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
        [channel_ptr](federation::FederationEndpoint endpoint, std::string_view room_id, std::string_view event_id,
                      federation::InboundPduEnvelope const& envelope) -> federation::MembershipAcceptResult {
        std::ignore = room_id;  // envelope.room_id carries the same value
        std::ignore = event_id; // unused by the default implementation too
        auto const json_body = serialize_membership_ingest(endpoint, envelope);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {false, 503U, "membership_ingest IPC timeout", {}, {}};
        }
        return deserialize_membership_ingest_result(*reply);
    };

    // Override invite_handler the same way as membership_acceptor above: the
    // default implementation (local_http_router.cpp) persists the invite's
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
    // inbound_request.cpp counts an EDU with no edu_sink installed as
    // "dispatched" rather than "dropped"). Typing/receipt/presence really
    // are ephemeral, but relaying everything through one uniform path avoids
    // special-casing by EDU type. See docs/architecture.md, "Federation
    // worker EDU relay".
    runtime.federation.edu_sink =
        [channel_ptr](federation::InboundEduEnvelope const& envelope) -> federation::EduDispositionResult {
        auto const json_body = serialize_edu_ingest(envelope);
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
    // (local_http_router.cpp) decides key availability from an in-memory
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
        auto const json_body = serialize_otk_claim_ingest(request_body);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
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
        auto const json_body = serialize_user_devices_ingest(user_id);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {};
        }
        return deserialize_user_devices_ingest_result(*reply);
    };

    runtime.federation.device_keys_query_provider = [channel_ptr](std::string_view request_body) -> std::string {
        auto const json_body = serialize_device_keys_query_ingest(request_body);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {};
        }
        return deserialize_device_keys_query_ingest_result(*reply);
    };

    runtime.federation.profile_query_provider =
        [channel_ptr](std::string_view user_id) -> federation::FederationProfile {
        auto const json_body = serialize_profile_query_ingest(user_id);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {};
        }
        return deserialize_profile_query_ingest_result(*reply);
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
    runtime.federation.event_query_provider = [channel_ptr](std::string_view event_id) -> std::string {
        auto const json_body = serialize_event_query_ingest(event_id);
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

    channel->set_request_handler([&runtime, channel_ptr, &local_pool, &relay_pool, signal_shutdown](std::uint64_t id,
                                                                                                    std::string json) {
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
                    auto const response = homeserver::handle_federation_http_request(runtime, request);
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
            // Fire-and-forget: no reply is sent. Re-reads this one room from
            // the database into our own PersistentStore snapshot, which is
            // otherwise frozen as of this worker's own startup (see
            // database::reload_room and docs/architecture.md, "Federation
            // worker room staleness"). Runs on the local pool, NOT inline on
            // this handler: reload_room needs runtime.mutex, which a
            // relay-pool transaction holds across its pdu_ingest round trips
            // to main — and main sends this very notification (from its
            // pdu_ingest handler's notify_room_changed) moments before the
            // pdu_ingest response. Blocking the channel's dispatch thread on
            // that mutex would park every later queued request behind a lock
            // the in-flight transaction won't release for its whole duration.
            // Concurrent reloads still serialize on runtime.mutex inside the
            // task, and reload_room is a full fresh re-read, so pool
            // scheduling order between two reloads of the same room is
            // immaterial.
            auto const room_id = ipc::ipc_json_get_str(json, "room_id");
            auto const sync_enqueued = local_pool.submit([&runtime, room_id]() {
                auto guard = std::unique_lock{runtime.mutex};
                if (!database::reload_room(runtime.database.persistent_store, room_id))
                {
                    LOG_WARNING("Federation worker: room_sync reload failed for room_id=" + room_id);
                }
            });
            if (!sync_enqueued)
            {
                LOG_WARNING("Federation worker: room_sync dropped because local thread pool is stopped");
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

    channel->start();

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

    // Idempotent: if the shutdown handler already stopped the channel this
    // is a no-op; otherwise it joins the reader and dispatch threads now.
    channel->stop();

    LOG_INFO("Federation worker stopped");
}

} // namespace merovingian::federation_worker
