// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/HttpServeStats.hpp"
#include "merovingian/homeserver/HttpServeTuning.hpp"
#include "merovingian/net/ThreadPool.hpp"

#include <memory>

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

} // namespace merovingian::homeserver
