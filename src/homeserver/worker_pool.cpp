// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_pool.hpp"

#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"
#include "merovingian/observability/logger.hpp"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    // Minimal JSON helpers for sign_request / pdu_ingest frames.

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

    auto json_get_str(std::string_view json, std::string_view key) -> std::string
    {
        auto const needle = std::string{"\""} + std::string{key} + "\":\"";
        auto const pos = json.find(needle);
        if (pos == std::string_view::npos)
        {
            return {};
        }
        auto i = pos + needle.size();
        auto result = std::string{};
        while (i < json.size())
        {
            auto const ch = json[i];
            if (ch == '\"')
            {
                break;
            }
            if (ch == '\\' && i + 1 < json.size())
            {
                ++i;
                switch (json[i])
                {
                case '\"':
                    result += '\"';
                    break;
                case '\\':
                    result += '\\';
                    break;
                case 'b':
                    result += '\b';
                    break;
                case 'f':
                    result += '\f';
                    break;
                case 'n':
                    result += '\n';
                    break;
                case 'r':
                    result += '\r';
                    break;
                case 't':
                    result += '\t';
                    break;
                default:
                    result += json[i];
                    break;
                }
            }
            else
            {
                result += ch;
            }
            ++i;
        }
        return result;
    }

    auto json_get_u64(std::string_view json, std::string_view key) -> std::uint64_t
    {
        auto const needle = std::string{"\""} + std::string{key} + "\":";
        auto const pos = json.find(needle);
        if (pos == std::string_view::npos)
        {
            return 0U;
        }
        auto const start = pos + needle.size();
        auto value = std::uint64_t{0U};
        std::from_chars(json.data() + start, json.data() + json.size(), value);
        return value;
    }

    auto json_str_array(std::string_view json, std::size_t pos) -> std::vector<std::string>
    {
        auto result = std::vector<std::string>{};
        while (pos < json.size() && json[pos] != ']')
        {
            if (json[pos] == '\"')
            {
                ++pos;
                auto item = std::string{};
                while (pos < json.size() && json[pos] != '\"')
                {
                    if (json[pos] == '\\' && pos + 1 < json.size())
                    {
                        ++pos;
                        switch (json[pos])
                        {
                        case '\"':
                            item += '\"';
                            break;
                        case '\\':
                            item += '\\';
                            break;
                        case 'n':
                            item += '\n';
                            break;
                        case 'r':
                            item += '\r';
                            break;
                        case 't':
                            item += '\t';
                            break;
                        default:
                            item += json[pos];
                            break;
                        }
                    }
                    else
                    {
                        item += json[pos];
                    }
                    ++pos;
                }
                result.push_back(std::move(item));
            }
            ++pos;
        }
        return result;
    }

    auto deserialize_pdu_ingest(std::string_view json) -> federation::InboundPduEnvelope
    {
        auto env = federation::InboundPduEnvelope{};
        env.event_id = json_get_str(json, "event_id");
        env.room_id = json_get_str(json, "room_id");
        env.room_version = json_get_str(json, "room_version");
        env.sender = json_get_str(json, "sender");
        env.event_type = json_get_str(json, "event_type");
        env.origin_server_ts = static_cast<std::int64_t>(json_get_u64(json, "origin_server_ts"));
        env.depth = json_get_u64(json, "depth");
        env.json = json_get_str(json, "json");

        auto const sk_needle = std::string_view{R"("state_key":")"};
        auto const sk_pos = json.find(sk_needle);
        if (sk_pos != std::string_view::npos)
        {
            env.state_key = json_get_str(json, "state_key");
        }

        auto const aei_needle = std::string_view{R"("auth_event_ids":[)"};
        auto const aei_pos = json.find(aei_needle);
        if (aei_pos != std::string_view::npos)
        {
            env.auth_event_ids = json_str_array(json, aei_pos + aei_needle.size());
        }

        auto const pei_needle = std::string_view{R"("prev_event_ids":[)"};
        auto const pei_pos = json.find(pei_needle);
        if (pei_pos != std::string_view::npos)
        {
            env.prev_event_ids = json_str_array(json, pei_pos + pei_needle.size());
        }

        auto const sigs_needle = std::string_view{R"("signatures":[)"};
        auto const sigs_pos = json.find(sigs_needle);
        if (sigs_pos != std::string_view::npos)
        {
            auto pos = sigs_pos + sigs_needle.size();
            while (pos < json.size() && json[pos] != ']')
            {
                auto const obj_start = json.find('{', pos);
                if (obj_start == std::string_view::npos)
                {
                    break;
                }
                auto const obj_end = json.find('}', obj_start);
                if (obj_end == std::string_view::npos)
                {
                    break;
                }
                auto const obj = json.substr(obj_start, obj_end - obj_start + 1U);
                auto sig = events::EventSignature{};
                sig.server_name = json_get_str(obj, "sn");
                sig.key_id = json_get_str(obj, "ki");
                sig.signature = json_get_str(obj, "sig");
                if (!sig.server_name.empty())
                {
                    env.signatures.push_back(std::move(sig));
                }
                pos = obj_end + 1U;
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
        }
        auto body = std::string{R"({"type":"pdu_ingest_result","status":)"};
        body += json_str(status_str);
        body += R"(,"reason":)";
        body += json_str(result.reason);
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

WorkerPool::WorkerPool(config::FederationWorkerConfig const& cfg, HomeserverRuntime& runtime, std::string worker_path,
                       std::string config_path)
    : cfg_{cfg}
    , runtime_{runtime}
    , worker_path_{std::move(worker_path)}
    , config_path_{std::move(config_path)}
{
    auto const count = cfg_.shards > 0U ? cfg_.shards : 1U;
    workers_.reserve(count);
    for (auto i = std::uint32_t{0U}; i < count; ++i)
    {
        auto supervisor =
            std::make_unique<WorkerSupervisor>(worker_path_, config_path_, cfg_.request_timeout_seconds, i);

        // Per-worker request handler: the lambda must respond on the channel
        // that received the request, so capture the supervisor reference.
        supervisor->set_request_handler([this, ptr = supervisor.get()](std::uint64_t id, std::string json) {
            auto const type = json_get_str(json, "type");
            if (type == "pdu_ingest")
            {
                auto const env = deserialize_pdu_ingest(json);
                auto result = federation::PduIngestionResult{};
                auto stream_ordering = std::uint64_t{0U};
                {
                    auto guard = std::unique_lock{runtime_.mutex};
                    // Capture ordering before pdu_sink so the sync notification
                    // uses the event's own position (not next_stream_ordering
                    // after pdu_sink has incremented it, which would publish
                    // one past the stored event and cause spurious sync wakeups).
                    stream_ordering = runtime_.database.next_stream_ordering;
                    if (runtime_.federation.pdu_sink)
                    {
                        result = runtime_.federation.pdu_sink(env);
                    }
                    else
                    {
                        result.status = federation::PduIngestionStatus::internal_error;
                        result.reason = "pdu_sink not wired";
                    }
                    if (result.status == federation::PduIngestionStatus::accepted && runtime_.sync_notifier != nullptr)
                    {
                        runtime_.sync_notifier->publish(stream_ordering, 0U);
                    }
                }
                ptr->channel().send_response(id, serialize_pdu_ingest_result(result));
            }
            else if (type == "sign_request")
            {
                auto const key_id = json_get_str(json, "key_id");
                auto const canonical = json_get_str(json, "canonical_json");
                auto result = crypto::SignatureResult{};
                {
                    auto guard = std::unique_lock{runtime_.mutex};
                    if (runtime_.crypto_provider != nullptr)
                    {
                        result = runtime_.crypto_provider->sign(crypto::Ed25519SecretKeyHandle{key_id}, canonical);
                    }
                    else
                    {
                        result.error = "crypto provider not available";
                    }
                }
                ptr->channel().send_response(id, serialize_sign_response(result));
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
    // Grab a shared_ptr snapshot before checking health; this keeps the channel
    // alive across a concurrent supervisor restart that might reset channel_.
    auto const ch = worker.channel_snapshot();
    if (!ch || !ch->healthy())
    {
        return {503U, R"({"errcode":"M_UNAVAILABLE","error":"Federation worker shard unavailable"})"};
    }

    auto const timeout = std::chrono::seconds{cfg_.request_timeout_seconds};
    auto const reply = ch->send_request(ipc::serialize_fed_request(request), timeout);
    if (!reply.has_value())
    {
        LOG_WARNING("WorkerPool: shard " + std::to_string(index) + " request timed out or failed for " +
                    request.target);
        return {503U, R"({"errcode":"M_UNAVAILABLE","error":"Federation worker shard unavailable"})"};
    }

    return ipc::deserialize_fed_response(*reply);
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

} // namespace merovingian::homeserver
