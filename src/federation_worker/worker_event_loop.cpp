// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "worker_event_loop.hpp"

#include "merovingian/events/event.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
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
#include <cstdio>
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
            if (ch == '"')
            {
                break;
            }
            if (ch == '\\' && i + 1 < json.size())
            {
                ++i;
                switch (json[i])
                {
                case '"':
                    result += '"';
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
    // Create the IPC channel first; the blocking key exchange completes here
    // before any runtime signing operation can be requested. The worker is the
    // client side of the exchange.
    auto channel = std::make_unique<ipc::IpcChannel>(std::move(ipc_fd_), ipc::IpcChannel::Role::client);
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

    // EDU sink is a no-op in Phase 1; EDUs are ephemeral and acceptable to drop.
    runtime.federation.edu_sink = {};

    // Thread pool for handling concurrent fed_request messages.
    auto pool = net::ThreadPool{threads_};

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

    channel->set_request_handler([&runtime, channel_ptr, &pool, signal_shutdown](std::uint64_t id, std::string json) {
        auto const type = json_get_str(json, "type");
        if (type == "fed_request")
        {
            // Dispatch to pool; do not block the reader thread.
            std::ignore = pool.submit([&runtime, channel_ptr, id, json = std::move(json)]() mutable {
                auto const request = ipc::deserialize_fed_request(json);
                auto const response = homeserver::handle_federation_http_request(runtime, request);
                channel_ptr->send_response(id, ipc::serialize_fed_response(response));
            });
        }
        else if (type == "shutdown")
        {
            // Do NOT call channel->stop() here: this handler runs on the IPC
            // reader thread, and IpcChannel::stop() joins that thread.  A thread
            // cannot join itself; doing so throws std::system_error(EDEADLK).
            // Signal shutdown so the main worker thread wakes and stops the
            // channel from a different thread.
            signal_shutdown();
        }
        else
        {
            LOG_WARNING("Federation worker: unexpected IPC request type: " + type);
        }
    });

    channel->start();

    LOG_INFO("[fed-worker/" + std::to_string(shard_index_) +
             "] Federation worker ready: threads=" + std::to_string(threads_));

    // Block until shutdown is signalled.  A watcher thread also wakes us if
    // the main process closes the IPC fd without sending a notification.
    auto watcher = std::thread{[channel_ptr, signal_shutdown]() {
        while (channel_ptr->healthy())
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

    // Idempotent: if the shutdown handler already stopped the channel this
    // is a no-op; otherwise it joins the reader thread now.
    channel->stop();

    pool.request_stop();

    LOG_INFO("Federation worker stopped");
}

} // namespace merovingian::federation_worker
