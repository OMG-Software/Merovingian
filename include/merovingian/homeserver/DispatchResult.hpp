// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/SyncWaitParams.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

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

} // namespace merovingian::homeserver
