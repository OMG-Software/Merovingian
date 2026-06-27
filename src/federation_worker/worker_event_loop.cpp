// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "worker_event_loop.hpp"

#include "merovingian/events/event.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/ipc/channel.hpp"
#include "merovingian/net/thread_pool.hpp"
#include "merovingian/observability/logger.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::federation_worker
{

namespace
{

// ---- Minimal JSON helpers (same schema as federation_proxy.cpp) -------------

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

// Deserialize a `fed_request` JSON frame from main.
auto deserialize_fed_request(std::string_view json) -> homeserver::LocalHttpRequest
{
    auto request = homeserver::LocalHttpRequest{};
    request.method      = json_get_str(json, "method");
    request.target      = json_get_str(json, "target");
    request.remote_addr = json_get_str(json, "remote_addr");
    request.body        = json_get_str(json, "body");

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
                request.headers.push_back({std::move(name), std::move(value)});
            }
            pos = obj_end + 1U;
        }
    }

    return request;
}

// Serialize a LocalHttpResponse to JSON for the fed_response IPC frame.
auto serialize_fed_response(homeserver::LocalHttpResponse const& response) -> std::string
{
    auto result = std::string{};
    result.reserve(64U + response.body.size());
    result += R"({"type":"fed_response","status":)";
    result += std::to_string(response.status);
    result += R"(,"headers":[)";
    auto first = true;
    for (auto const& [name, value] : response.headers)
    {
        if (!first)
        {
            result += ',';
        }
        first = false;
        result += R"({"n":)";
        result += json_str(name);
        result += R"(,"v":)";
        result += json_str(value);
        result += '}';
    }
    result += R"(],"body":)";
    result += json_str(response.body);
    result += '}';
    return result;
}

// Serialize an InboundPduEnvelope for the pdu_ingest IPC call to main.
auto serialize_pdu_ingest(federation::InboundPduEnvelope const& env) -> std::string
{
    auto result = std::string{};
    result.reserve(512U + env.json.size());
    result += R"({"type":"pdu_ingest","event_id":)";
    result += json_str(env.event_id);
    result += R"(,"room_id":)";
    result += json_str(env.room_id);
    result += R"(,"room_version":)";
    result += json_str(env.room_version);
    result += R"(,"sender":)";
    result += json_str(env.sender);
    result += R"(,"event_type":)";
    result += json_str(env.event_type);
    if (env.state_key.has_value())
    {
        result += R"(,"state_key":)";
        result += json_str(*env.state_key);
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
        result += json_str(id);
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
        result += json_str(id);
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
        result += json_str(sig.server_name);
        result += R"(,"ki":)";
        result += json_str(sig.key_id);
        result += R"(,"sig":)";
        result += json_str(sig.signature);
        result += '}';
    }
    result += R"(],"json":)";
    result += json_str(env.json);
    result += '}';
    return result;
}

// Deserialize a `pdu_ingest_result` JSON frame from main.
auto deserialize_pdu_ingest_result(std::string_view json) -> federation::PduIngestionResult
{
    auto result = federation::PduIngestionResult{};
    auto const status_str = json_get_str(json, "status");
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
    result.reason = json_get_str(json, "reason");
    return result;
}

} // namespace

WorkerEventLoop::WorkerEventLoop(core::FileDescriptor ipc_fd, config::Config config, std::uint32_t threads)
    : ipc_fd_{std::move(ipc_fd)}
    , config_{std::move(config)}
    , threads_{threads}
{
}

auto WorkerEventLoop::run() -> void
{
    // Start a full HomeserverRuntime using the same config as main. The worker
    // has its own DB connection for remote key resolution and room-version
    // lookups. It does NOT write events — accepted PDUs are sent to main via
    // pdu_ingest IPC and main commits them with the authoritative counter.
    auto started = homeserver::start_runtime(config_);
    if (!started.started)
    {
        LOG_CRITICAL("Federation worker: failed to start runtime: " + started.reason);
        return;
    }
    auto& runtime = started.runtime;
    homeserver::wire_federation_callbacks(runtime);

    // Create the IPC channel (worker is the client side of the key exchange).
    auto channel =
        std::make_unique<ipc::IpcChannel>(std::move(ipc_fd_), ipc::IpcChannel::Role::client);

    // Override pdu_sink: instead of writing to DB directly, call main via IPC.
    // The channel shared_ptr keeps the channel alive across the lambda lifetime.
    auto* channel_ptr = channel.get();
    runtime.federation.pdu_sink = [channel_ptr](federation::InboundPduEnvelope const& env)
        -> federation::PduIngestionResult {
        auto const json_body = serialize_pdu_ingest(env);
        auto const reply = channel_ptr->send_request(json_body, std::chrono::seconds{60});
        if (!reply.has_value())
        {
            return {federation::PduIngestionStatus::internal_error, "pdu_ingest IPC timeout"};
        }
        return deserialize_pdu_ingest_result(*reply);
    };

    // EDU sink is a no-op in Phase 1; EDUs are ephemeral and acceptable to drop.
    runtime.federation.edu_sink = {};

    // Thread pool for handling concurrent fed_request messages.
    auto pool = net::ThreadPool{threads_};

    auto shutdown = std::atomic<bool>{false};

    channel->set_request_handler(
        [&runtime, channel_ptr, &pool, &shutdown](std::uint64_t id, std::string json) {
            auto const type = json_get_str(json, "type");
            if (type == "fed_request")
            {
                // Dispatch to pool; do not block the reader thread.
                std::ignore = pool.submit([&runtime, channel_ptr, id, json = std::move(json)]() mutable {
                    auto const request  = deserialize_fed_request(json);
                    auto const response = homeserver::handle_federation_http_request(runtime, request);
                    channel_ptr->send_response(id, serialize_fed_response(response));
                });
            }
            else if (type == "shutdown")
            {
                shutdown.store(true);
                channel_ptr->stop();
            }
            else
            {
                LOG_WARNING("Federation worker: unexpected IPC request type: " + type);
            }
        });

    channel->start();

    LOG_INFO("Federation worker ready: threads=" + std::to_string(threads_));

    // Block until the channel's reader thread exits (on shutdown or fd close).
    // IpcChannel::stop() joins the reader thread; calling it here after the
    // reader sets shutdown via the handler is safe (stop() is idempotent).
    channel->stop();

    pool.request_stop();

    LOG_INFO("Federation worker stopped");
}

} // namespace merovingian::federation_worker
