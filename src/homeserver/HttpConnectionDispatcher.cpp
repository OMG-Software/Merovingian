// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/HttpConnectionDispatcher.hpp"

#include "merovingian/config/Config.hpp"
#include "merovingian/config/HttpTransportConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ConnectionContext.hpp"
#include "merovingian/homeserver/HttpServerInternal.hpp"
#include "merovingian/homeserver/Tls.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"
#include "merovingian/sync/ParkedPollLimits.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    using detail::receive_timeout_milliseconds;
    using detail::resume_parked_poll;
    using detail::serve_request_round;

    // Logged under the `http_server` module, like the rest of the transport.
    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("http_server", event, fields, severity);
    }

} // namespace

auto HttpConnectionDispatcher::Impl::start() -> bool
{
    if (m_parker != nullptr)
    {
        return m_parker->running();
    }
    // At most one connection per worker is out of the parker at once, so the
    // pool's queue never holds more than its workers; and one client key may
    // hold at most a quarter of them (HTTP-1). A trusted proxy's connections
    // carry an empty key and are exempt from the second cap only.
    auto const workers = std::max<std::size_t>(1U, pool.worker_count());
    auto const limits = net::ConnectionParker::Limits{workers, std::max<std::size_t>(1U, workers / 4U)};
    m_parker = std::make_unique<net::ConnectionParker>(
        limits, [weak = weak_from_this()](net::ConnectionParker::Dispatched dispatched) {
            if (auto const self = weak.lock(); self != nullptr)
            {
                self->dispatch(std::move(dispatched));
            }
        });
    if (!m_parker->start())
    {
        return false;
    }
    // Parking needs a sync pool to resume into and a notifier; otherwise long-polls keep their thread. A registry
    // already started by another dispatcher on this runtime is left to it.
    if (sync_pool != nullptr && runtime.sync_notifier != nullptr)
    {
        auto const& http_settings = runtime.homeserver.config.server().http;
        auto const park_limits =
            sync::ParkedPollLimits{http_settings.sync_max_in_flight, http_settings.sync_max_per_user};
        m_owns_poll_registry = runtime.sync_notifier->parking().start(
            park_limits, [pool = sync_pool](std::unique_ptr<sync::ParkedPoll> poll, sync::WakeReason reason) {
                resume_parked_poll(*pool, std::move(poll), reason);
            });
    }
    return true;
}

auto HttpConnectionDispatcher::Impl::parks_polls() const -> bool
{
    return m_owns_poll_registry && runtime.sync_notifier != nullptr && runtime.sync_notifier->parking().running();
}

auto HttpConnectionDispatcher::Impl::request_stop() -> void
{
    if (m_parker != nullptr)
    {
        m_parker->request_stop();
    }
    // After the parker: closes every parked long-poll and joins the registry thread before the pools stop (ADR-0569).
    if (m_owns_poll_registry)
    {
        runtime.sync_notifier->parking().request_stop();
    }
}

auto HttpConnectionDispatcher::Impl::running() const -> bool
{
    return m_parker != nullptr && m_parker->running();
}

auto HttpConnectionDispatcher::Impl::accept(core::SocketHandle socket, std::string peer_addr, HttpDispatchMode mode,
                                            ConnectionAdmission admission,
                                            std::optional<std::reference_wrapper<TlsServerContext>> tls_context) -> void
{
    ++stats.accepted_connections;
    auto owner = std::make_unique<HttpConnection>(std::move(socket), mode, std::move(peer_addr),
                                                  std::move(admission.client_key));
    auto& connection = *owner;
    if (admission.slot.has_value())
    {
        connection.connection_slot.emplace(std::move(*admission.slot));
    }
    connection.tls_handshake_owed = tls_context;
    park_awaiting_first_request(std::move(owner));
}

// A connection that has not yet sent its first request: newly accepted, or a
// TLS connection whose handshake has just completed. It must send a byte within
// the first-byte timeout, and at most listeners.max_queued_connections such
// connections wait at once (0: unbounded).
auto HttpConnectionDispatcher::Impl::park_awaiting_first_request(ConnectionOwner owner) -> void
{
    auto& connection = http_connection(owner);
    auto const cap = runtime.homeserver.config.listeners().max_queued_connections;
    auto reservation = ParkingReservation::try_acquire(m_parked_new, cap);
    if (!reservation.has_value())
    {
        log_diagnostic("connection.pending_cap_reached", {
                                                             {"cap", std::to_string(cap), false}
        });
        return; // ~owner closes it
    }
    connection.parked_reservation = std::move(reservation);
    auto key = connection.client_key;
    if (!m_parker->park(std::move(owner), std::move(key), std::chrono::steady_clock::now() + tuning.first_byte_timeout))
    {
        log_diagnostic("connection.refused_stopping", {});
    }
}

auto HttpConnectionDispatcher::Impl::park_for_next_request(ConnectionOwner owner) -> void
{
    auto& connection = http_connection(owner);
    auto const idle = std::chrono::seconds{runtime.homeserver.config.server().http.keep_alive_idle_seconds};
    auto key = connection.client_key;
    // A stopped parker closes the connection: shutdown in progress.
    std::ignore = m_parker->park(std::move(owner), std::move(key), std::chrono::steady_clock::now() + idle);
}

// On the parker thread, with no lock held. The job is shared only because pool
// tasks are copyable std::functions; exactly one task runs it.
auto HttpConnectionDispatcher::Impl::dispatch(net::ConnectionParker::Dispatched dispatched) -> void
{
    auto job = std::make_shared<net::ConnectionParker::Dispatched>( // SHARED_PTR: reviewed — copyable pool task
        std::move(dispatched));
    auto self = shared_from_this();
    if (!pool.submit([self, job] {
            self->serve(std::move(*job));
        }))
    {
        // Only when the pool is stopping: the parker never has more
        // connections out than the pool has workers. ~job closes it.
        log_diagnostic("connection.dispatch_refused", {});
    }
}

// On a pool worker. `dispatched.share` is this connection's claim on the
// worker caps; it is released when this returns, whichever way.
auto HttpConnectionDispatcher::Impl::serve(net::ConnectionParker::Dispatched dispatched) -> void
{
    auto owner = std::move(dispatched.connection);
    auto& connection = http_connection(owner);
    // No longer parked: its parking slot goes back.
    connection.parked_reservation.reset();
    if (connection.tls_handshake_owed.has_value())
    {
        // The ClientHello is readable; the handshake is bounded by the
        // handshake timeout and counts against the client's worker share.
        auto& tls_context = connection.tls_handshake_owed->get();
        connection.tls_handshake_owed.reset();
        auto accepted = accept_tls_connection(tls_context, connection.fd(), receive_timeout_milliseconds);
        if (!accepted.ok())
        {
            ++stats.rejected_requests;
            log_diagnostic("tls.handshake.rejected", {
                                                         {"reason", accepted.error, false}
            });
            return; // ~owner closes it
        }
        connection.tls.emplace(std::move(*accepted.connection));
        park_awaiting_first_request(std::move(owner));
        return;
    }
    auto ctx = ConnectionContext{runtime, stats,           sync_pool,           media_fetch_pool, shared_from_this(),
                                 tuning,  connection.mode, connection.peer_addr};
    switch (serve_request_round(ctx, connection, owner))
    {
    case RoundOutcome::close_connection:
        return; // ~owner closes it
    case RoundOutcome::continue_keep_alive:
        park_for_next_request(std::move(owner));
        return;
    case RoundOutcome::transferred:
        return; // the sync-pool task owns it
    }
}

HttpConnectionDispatcher::HttpConnectionDispatcher(ClientServerRuntime& runtime, HttpServeStats& stats,
                                                   net::ThreadPool& pool, net::ThreadPool* sync_pool,
                                                   HttpServeTuning tuning, net::ThreadPool* media_fetch_pool)
    : m_impl{std::make_shared<Impl>(runtime, stats, pool, sync_pool, tuning, media_fetch_pool)}
{
}

HttpConnectionDispatcher::~HttpConnectionDispatcher()
{
    m_impl->request_stop();
}

auto HttpConnectionDispatcher::start() -> bool
{
    return m_impl->start();
}

auto HttpConnectionDispatcher::request_stop() -> void
{
    m_impl->request_stop();
}

auto HttpConnectionDispatcher::running() const -> bool
{
    return m_impl->running();
}

auto HttpConnectionDispatcher::impl() noexcept -> Impl&
{
    return *m_impl;
}

} // namespace merovingian::homeserver
