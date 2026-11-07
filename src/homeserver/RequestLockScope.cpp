// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RequestLockScope.hpp"

#include <utility>

namespace merovingian::homeserver
{
namespace
{

    // The mutex the guard owning runtime.mutex for this thread's in-flight
    // request locks, or null when this thread is not inside a request handler.
    // Never the guard's address (ADR-0529). Only ever read and written by its own
    // thread, so it needs no synchronisation of its own.
    thread_local auto* current_request_mutex = static_cast<RuntimeMutex const*>(nullptr);

} // namespace

// A guard is only ever consulted for which mutex it refers to, never for whether
// it believes it owns it. `unique_lock::mutex()` answers that even when the lock
// is not held.
RequestLockScope::RequestLockScope(RuntimeLock& guard) noexcept
    : previous_{std::exchange(current_request_mutex, guard.mutex())}
{
}

RequestLockScope::~RequestLockScope()
{
    current_request_mutex = previous_;
}

auto published_request_mutex() noexcept -> RuntimeMutex const*
{
    return current_request_mutex;
}

} // namespace merovingian::homeserver
