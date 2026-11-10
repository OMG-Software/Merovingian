// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/HttpConnectionDispatcher.hpp"
#include "merovingian/homeserver/HttpDispatchMode.hpp"
#include "merovingian/homeserver/HttpServeStats.hpp"
#include "merovingian/homeserver/HttpServeTuning.hpp"
#include "merovingian/net/ThreadPool.hpp"

#include <memory>
#include <string>

namespace merovingian::homeserver
{

struct ClientServerRuntime;

// Everything a request round needs besides the connection itself.
// `runtime` and `stats` outlive every pool task (main.cpp stops the pools
// before the runtime is torn down). `dispatcher` is null for direct
// serve_one_http_connection calls, which never keep a connection alive.
struct ConnectionContext final
{
    ClientServerRuntime& runtime;
    HttpServeStats& stats;
    net::ThreadPool* sync_pool;                     // may be null (tests, no long-poll offload)
    net::ThreadPool* media_fetch_pool;              // may be null (tests: remote media fetched inline)
    std::shared_ptr<HttpConnectionDispatcher::Impl> // SHARED_PTR: reviewed — pool tasks keep the dispatcher alive
        dispatcher;
    HttpServeTuning tuning;
    HttpDispatchMode dispatch_mode;
    std::string peer_addr;
};

} // namespace merovingian::homeserver
