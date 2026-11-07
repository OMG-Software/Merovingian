// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/RuntimeMutex.hpp"

#include <cstddef>
#include <mutex>

namespace merovingian::homeserver
{

// Publishes the mutex that the `std::unique_lock` owning `HomeserverRuntime::mutex`
// for this thread's in-flight request locks, so code deeper in the call stack can
// release it around a blocking network call without threading the lock object
// through every intervening signature.
//
// The mutex is published, not the guard (ADR-0529): `RuntimeLockRelease` only
// ever asks a guard which mutex it refers to, and the mutex outlives every guard
// on it, whereas the guard is a local variable whose address in thread-local
// storage would be a stack address (CodeQL cpp/stack-address-escape). A published
// guard is never moved or released (`unique_lock::release`), so the mutex read
// here is the one the guard still refers to.
//
// The publication is thread_local, so one request thread never observes
// another's. A thread that publishes nothing — the federation worker, a test
// calling a service function directly — leaves the publication null, and the
// default-constructed `RuntimeLockRelease` below then has nothing to release.
//
// Nesting is supported: the innermost scope wins and restores its predecessor
// on exit. That matches the one nesting path in the server, where the
// client-server dispatcher releases its own guard before delegating a media
// route to the local router, which then takes (and publishes) its own.
class RequestLockScope final
{
public:
    explicit RequestLockScope(RuntimeLock& guard) noexcept;
    ~RequestLockScope();

    RequestLockScope(RequestLockScope const&) = delete;
    auto operator=(RequestLockScope const&) -> RequestLockScope& = delete;
    RequestLockScope(RequestLockScope&&) = delete;
    auto operator=(RequestLockScope&&) -> RequestLockScope& = delete;

private:
    // The mutex the enclosing scope published, put back when this one closes.
    RuntimeMutex const* previous_{nullptr};
};

// The mutex the innermost RequestLockScope on this thread published, or null
// when this thread is not inside a request handler. Used by RuntimeLockRelease.
[[nodiscard]] auto published_request_mutex() noexcept -> RuntimeMutex const*;

} // namespace merovingian::homeserver
