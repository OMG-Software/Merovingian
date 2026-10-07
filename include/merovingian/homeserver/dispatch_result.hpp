// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/remote_media_fetch_scope.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// Parameters that the /sync handler returns when it needs to wait outside
// the runtime state mutex before building the response.
struct SyncWaitParams final
{
    std::uint64_t since_stream_ordering{0U};
    std::uint64_t since_sync_stream_id{0U};
    std::chrono::milliseconds timeout{0U};
    // Authenticated identities, supplied by the handler while holding the runtime lock.
    std::string user_id{};
    std::string device_id{};
};

// Result of a handler dispatch. Most handlers complete synchronously
// (status == complete). The /sync handler may return needs_wait when
// no new data is available and a long-poll is requested — the dispatch
// function then releases the lock, waits on the SyncNotifier, reacquires
// the lock, and calls the handler again. A remote media download or thumbnail
// that must fetch from the origin returns needs_media_fetch when it ran in
// RemoteMediaFetchMode::defer: the transport then hands the request to the
// media fetch pool, which runs it again (ADR-0121). `response` is empty for
// both.
struct DispatchResult final
{
    enum class Status
    {
        complete,
        needs_wait,
        needs_media_fetch
    };
    Status status{Status::complete};
    LocalHttpResponse response{};
    SyncWaitParams wait{};
};

// How handle_client_server_request runs one request.
struct ClientServerDispatchOptions final
{
    // A /sync with a timeout may answer needs_wait instead of blocking.
    bool can_wait{true};
    // How a remote media fetch may run (ADR-0121).
    RemoteMediaFetchMode remote_media{RemoteMediaFetchMode::inline_fetch};
    // The transport already counted this request against the rate limiter (the
    // media fetch pool running a deferred request again); do not count it twice.
    bool rate_limit_admitted{false};
};

} // namespace merovingian::homeserver
