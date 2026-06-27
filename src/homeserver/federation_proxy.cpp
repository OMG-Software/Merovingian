// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/federation_proxy.hpp"

#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/worker_supervisor.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/observability/logger.hpp"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

// Minimal JSON string escaping. Produces a quoted, escaped JSON string value.
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
        case '"':  result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b";  break;
        case '\f': result += "\\f";  break;
        case '\n': result += "\\n";  break;
        case '\r': result += "\\r";  break;
        case '\t': result += "\\t";  break;
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

// Extract a JSON-escaped string value for `key`. Returns empty string on failure.
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
        if (ch == '"')
        {
            break;
        }
        if (ch == '\\' && i + 1 < json.size())
        {
            ++i;
            switch (json[i])
            {
            case '"':  result += '"';  break;
            case '\\': result += '\\'; break;
            case 'b':  result += '\b'; break;
            case 'f':  result += '\f'; break;
            case 'n':  result += '\n'; break;
            case 'r':  result += '\r'; break;
            case 't':  result += '\t'; break;
            default:   result += json[i]; break;
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

// Extract an unsigned integer for `key`. Returns 0 on failure.
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

// Reads all quoted strings from a JSON array literal `[...]` starting at `pos`.
auto json_str_array(std::string_view json, std::size_t pos) -> std::vector<std::string>
{
    auto result = std::vector<std::string>{};
    while (pos < json.size() && json[pos] != ']')
    {
        if (json[pos] == '"')
        {
            ++pos;
            auto item = std::string{};
            while (pos < json.size() && json[pos] != '"')
            {
                if (json[pos] == '\\' && pos + 1 < json.size())
                {
                    ++pos;
                    switch (json[pos])
                    {
                    case '"':  item += '"';  break;
                    case '\\': item += '\\'; break;
                    case 'n':  item += '\n'; break;
                    case 'r':  item += '\r'; break;
                    case 't':  item += '\t'; break;
                    default:   item += json[pos]; break;
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

// Serialize LocalHttpRequest to JSON for forwarding to the worker.
// access_token is intentionally omitted — it must never cross the IPC boundary.
auto serialize_fed_request(LocalHttpRequest const& request) -> std::string
{
    auto result = std::string{};
    result.reserve(512U + request.body.size());
    result += R"({"type":"fed_request","method":)";
    result += json_str(request.method);
    result += R"(,"target":)";
    result += json_str(request.target);
    result += R"(,"remote_addr":)";
    result += json_str(request.remote_addr);
    result += R"(,"headers":[)";
    auto first = true;
    for (auto const& hdr : request.headers)
    {
        if (!first)
        {
            result += ',';
        }
        first = false;
        result += R"({"n":)";
        result += json_str(hdr.name);
        result += R"(,"v":)";
        result += json_str(hdr.value);
        result += '}';
    }
    result += R"(],"body":)";
    result += json_str(request.body);
    result += '}';
    return result;
}

// Deserialize a `fed_response` JSON frame from the worker.
auto deserialize_fed_response(std::string_view json) -> LocalHttpResponse
{
    auto response = LocalHttpResponse{};
    response.status = static_cast<std::uint16_t>(json_get_u64(json, "status"));
    if (response.status == 0U)
    {
        response.status = 500U;
    }
    response.body = json_get_str(json, "body");

    // Parse headers: [{"n":"...","v":"..."},...]
    auto const headers_key = std::string_view{R"("headers":[)"};
    auto const hpos = json.find(headers_key);
    if (hpos != std::string_view::npos)
    {
        auto pos = hpos + headers_key.size();
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
            auto name  = json_get_str(obj, "n");
            auto value = json_get_str(obj, "v");
            if (!name.empty())
            {
                response.headers.emplace_back(std::move(name), std::move(value));
            }
            pos = obj_end + 1U;
        }
    }

    return response;
}

// Deserialize a `pdu_ingest` JSON frame from the worker into an InboundPduEnvelope.
auto deserialize_pdu_ingest(std::string_view json) -> federation::InboundPduEnvelope
{
    auto env = federation::InboundPduEnvelope{};
    env.event_id         = json_get_str(json, "event_id");
    env.room_id          = json_get_str(json, "room_id");
    env.room_version     = json_get_str(json, "room_version");
    env.sender           = json_get_str(json, "sender");
    env.event_type       = json_get_str(json, "event_type");
    env.origin_server_ts = static_cast<std::int64_t>(json_get_u64(json, "origin_server_ts"));
    env.depth            = json_get_u64(json, "depth");
    env.json             = json_get_str(json, "json");

    // state_key: present as "state_key":"..." or absent
    auto const sk_needle = std::string_view{R"("state_key":")"};
    auto const sk_pos = json.find(sk_needle);
    if (sk_pos != std::string_view::npos)
    {
        env.state_key = json_get_str(json, "state_key");
    }

    // auth_event_ids
    auto const aei_needle = std::string_view{R"("auth_event_ids":[)"};
    auto const aei_pos = json.find(aei_needle);
    if (aei_pos != std::string_view::npos)
    {
        env.auth_event_ids = json_str_array(json, aei_pos + aei_needle.size());
    }

    // prev_event_ids
    auto const pei_needle = std::string_view{R"("prev_event_ids":[)"};
    auto const pei_pos = json.find(pei_needle);
    if (pei_pos != std::string_view::npos)
    {
        env.prev_event_ids = json_str_array(json, pei_pos + pei_needle.size());
    }

    // signatures: [{"sn":"...","ki":"...","sig":"..."},...]
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
            sig.key_id      = json_get_str(obj, "ki");
            sig.signature   = json_get_str(obj, "sig");
            if (!sig.server_name.empty())
            {
                env.signatures.push_back(std::move(sig));
            }
            pos = obj_end + 1U;
        }
    }

    return env;
}

// Serialize a PduIngestionResult to JSON for the pdu_ingest_result response.
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

} // namespace

// ----- FederationProxy -------------------------------------------------------

FederationProxy::FederationProxy(config::FederationWorkerConfig const& cfg, HomeserverRuntime& runtime,
                                 std::string worker_path, std::string config_path)
    : cfg_{cfg}
    , runtime_{runtime}
{
    supervisor_ = std::make_unique<WorkerSupervisor>(std::move(worker_path), std::move(config_path),
                                                     cfg_.request_timeout_seconds);

    // Handle inbound IPC requests from the worker (pdu_ingest).
    supervisor_->set_request_handler([this](std::uint64_t id, std::string json) {
        auto const type = json_get_str(json, "type");
        if (type == "pdu_ingest")
        {
            auto const env = deserialize_pdu_ingest(json);
            auto result = federation::PduIngestionResult{};
            {
                auto guard = std::unique_lock{runtime_.mutex};
                if (runtime_.federation.pdu_sink)
                {
                    result = runtime_.federation.pdu_sink(env);
                }
                else
                {
                    result.status = federation::PduIngestionStatus::internal_error;
                    result.reason = "pdu_sink not wired";
                }
                if (result.status == federation::PduIngestionStatus::accepted &&
                    runtime_.sync_notifier != nullptr)
                {
                    runtime_.sync_notifier->publish(runtime_.database.next_stream_ordering, 0U);
                }
            }
            supervisor_->channel().send_response(id, serialize_pdu_ingest_result(result));
        }
        else
        {
            LOG_WARNING("FederationProxy: unexpected IPC request type: " + type);
        }
    });

    supervisor_->start();
}

FederationProxy::~FederationProxy()
{
    if (supervisor_)
    {
        supervisor_->stop();
    }
}

auto FederationProxy::handle(LocalHttpRequest const& request) -> LocalHttpResponse
{
    if (supervisor_ && supervisor_->healthy())
    {
        auto const json_body = serialize_fed_request(request);
        auto const timeout   = std::chrono::seconds{cfg_.request_timeout_seconds};
        auto const reply     = supervisor_->channel().send_request(json_body, timeout);
        if (reply.has_value())
        {
            return deserialize_fed_response(*reply);
        }
        LOG_WARNING("FederationProxy: worker request timed out or failed for " + request.target);
    }

    if (cfg_.fallback_in_process)
    {
        return handle_federation_http_request(runtime_, request);
    }

    return {503U, R"({"errcode":"M_UNAVAILABLE","error":"Federation worker unavailable"})"};
}

auto FederationProxy::healthy() const noexcept -> bool
{
    return supervisor_ && supervisor_->healthy();
}

} // namespace merovingian::homeserver
