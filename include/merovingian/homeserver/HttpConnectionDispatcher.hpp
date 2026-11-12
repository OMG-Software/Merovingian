// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/SocketHandle.hpp"
#include "merovingian/homeserver/ConnectionAdmission.hpp"
#include "merovingian/homeserver/HttpConnection.hpp"
#include "merovingian/homeserver/HttpDispatchMode.hpp"
#include "merovingian/homeserver/HttpServeStats.hpp"
#include "merovingian/homeserver/HttpServeTuning.hpp"
#include "merovingian/homeserver/ParkingReservation.hpp"
#include "merovingian/homeserver/TlsServerContext.hpp"
#include "merovingian/net/ConnectionParker.hpp"
#include "merovingian/net/ThreadPool.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

struct ClientServerRuntime;

// Owns every connection that is not being served (ADR-0077, audit finding
// HTTP-1): fresh connections before their first byte, and kept-alive connections
// between requests, all on one poll(2) thread (net::ConnectionParker). A
// connection reaches a worker of `pool` only once it is readable, at most
// pool-size connections are out at once, and at most max(1, pool-size / 4) of
// them may come from one client address (the TCP peer, IPv6 grouped as for the
// per-IP connection cap; a trusted proxy is exempt). One dispatcher serves
// every listener, so the caps are process-wide.
//
// Lifetime: construct, start() after process hardening (no thread may start
// before it, ADR-0082), hand to serve_http / serve_tls_http, and request_stop()
// once the listeners have returned and before the pools are stopped. Pool tasks
// keep the internals alive, so the object itself may be destroyed while a
// worker still holds a connection; that connection is closed, not re-parked.
// `runtime` and `stats` must outlive every pool task, as before.
class HttpConnectionDispatcher final
{
public:
    // `media_fetch_pool`: remote media requests that must fetch from the origin
    // are handed to it (ADR-0121); null fetches them inline under ADR-0079.
    HttpConnectionDispatcher(ClientServerRuntime& runtime, HttpServeStats& stats, net::ThreadPool& pool,
                             net::ThreadPool* sync_pool = nullptr, HttpServeTuning tuning = {},
                             net::ThreadPool* media_fetch_pool = nullptr);
    HttpConnectionDispatcher(HttpConnectionDispatcher const&) = delete;
    auto operator=(HttpConnectionDispatcher const&) -> HttpConnectionDispatcher& = delete;
    HttpConnectionDispatcher(HttpConnectionDispatcher&&) = delete;
    auto operator=(HttpConnectionDispatcher&&) -> HttpConnectionDispatcher& = delete;
    ~HttpConnectionDispatcher();

    // Starts the dispatcher thread. False (fail closed) when it could not.
    [[nodiscard]] auto start() -> bool;
    // Closes every parked connection and stops the thread; bounded. Workers
    // that finish a request afterwards close their connection. Idempotent.
    auto request_stop() -> void;
    [[nodiscard]] auto running() const -> bool;

    class Impl;
    [[nodiscard]] auto impl() noexcept -> Impl&;

private:
    std::shared_ptr<Impl> m_impl; // SHARED_PTR: reviewed — pool tasks keep the dispatcher internals alive
};

// The dispatcher's internals (ADR-0077). Shared: every pool task that carries a
// connection holds a reference, so a worker finishing a round can always hand
// its connection back (or close it once stopped) even if the public
// HttpConnectionDispatcher has been destroyed.
//
// Threads: the parker thread calls dispatch(); pool workers call serve(); the
// accept threads call accept(); workers and sync-pool tasks call
// park_for_next_request(). None of these holds a lock across another: the
// parker's lock is internal to net::ConnectionParker and is never held while
// this class runs, and the parking counters are atomics.
class HttpConnectionDispatcher::Impl final : public std::enable_shared_from_this<HttpConnectionDispatcher::Impl>
{
public:
    Impl(ClientServerRuntime& runtime_ref, HttpServeStats& stats_ref, net::ThreadPool& pool_ref,
         net::ThreadPool* sync_pool_ptr, HttpServeTuning tuning_value, net::ThreadPool* media_fetch_pool_ptr)
        : runtime{runtime_ref}
        , stats{stats_ref}
        , pool{pool_ref}
        , sync_pool{sync_pool_ptr}
        , media_fetch_pool{media_fetch_pool_ptr}
        , tuning{tuning_value}
    {
    }
    Impl(Impl const&) = delete;
    auto operator=(Impl const&) -> Impl& = delete;
    Impl(Impl&&) = delete;
    auto operator=(Impl&&) -> Impl& = delete;
    ~Impl() = default;

    [[nodiscard]] auto start() -> bool;
    auto request_stop() -> void;
    [[nodiscard]] auto running() const -> bool;
    // Whether a long-poll with nothing to return can park in the notifier's registry (ADR-0569): the registry was
    // started by this dispatcher and is still running.
    [[nodiscard]] auto parks_polls() const -> bool;

    // Accept path: an admitted connection waits, parked, for its first byte.
    auto accept(core::SocketHandle socket, std::string peer_addr, HttpDispatchMode mode, ConnectionAdmission admission,
                std::optional<std::reference_wrapper<TlsServerContext>> tls_context) -> void;
    // A worker or a sync-pool task hands a kept-alive connection back.
    auto park_for_next_request(ConnectionOwner owner) -> void;

    // Reserves the connection's keep-alive parking in the process-wide budget and in its client key's share of it
    // (C01), recording both on the connection. False when either is full; the connection then holds neither.
    [[nodiscard]] auto reserve_keep_alive(HttpConnection& connection, std::uint32_t cap) -> bool;
    [[nodiscard]] auto parked_keep_alive() const noexcept -> std::uint32_t
    {
        return m_parked_keep_alive->load(std::memory_order_relaxed);
    }

    ClientServerRuntime& runtime;
    HttpServeStats& stats;
    net::ThreadPool& pool;
    net::ThreadPool* sync_pool;
    net::ThreadPool* media_fetch_pool;
    HttpServeTuning const tuning;

private:
    auto park_awaiting_first_request(ConnectionOwner owner) -> void;
    auto dispatch(net::ConnectionParker::Dispatched dispatched) -> void;
    auto serve(net::ConnectionParker::Dispatched dispatched) -> void;

    ParkingReservation::Counter m_parked_keep_alive{std::make_shared<std::atomic<std::uint32_t>>(0U)};
    ParkingReservation::Counter m_parked_new{std::make_shared<std::atomic<std::uint32_t>>(0U)};
    // Parked connections per client key (C01), so a few keys cannot fill the budgets above. Declared before the parker:
    // a parked connection holds a slot, and the parker's destructor closes it.
    http::ConnectionLimiter m_pending_per_key{};
    http::ConnectionLimiter m_keep_alive_per_key{};
    // Created by start() before any listener runs; the pointer never changes
    // afterwards, so the threads that use it need no lock to read it.
    std::unique_ptr<net::ConnectionParker> m_parker{};
    // Set by start(), before any listener runs: this dispatcher started the notifier's registry.
    bool m_owns_poll_registry{false};
};

} // namespace merovingian::homeserver
