// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/local_http_router.hpp"

#include <chrono>
#include <cstdint>

namespace merovingian::homeserver
{

// Parameters that the /sync handler returns when it needs to wait outside
// the runtime state mutex before building the response.
struct SyncWaitParams final
{
    std::uint64_t since_stream_ordering{0U};
    std::uint64_t since_sync_stream_id{0U};
    std::chrono::milliseconds timeout{0U};
};

// Result of a handler dispatch. Most handlers complete synchronously
// (status == complete). The /sync handler may return needs_wait when
// no new data is available and a long-poll is requested — the dispatch
// function then releases the lock, waits on the SyncNotifier, reacquires
// the lock, and calls the handler again.
struct DispatchResult final
{
    enum class Status
    {
        complete,
        needs_wait
    };
    Status status{Status::complete};
    LocalHttpResponse response{};
    SyncWaitParams wait{};
};

} // namespace merovingian::homeserver
