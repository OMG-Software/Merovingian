// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <mutex>

namespace merovingian::homeserver
{

// Publishes the `std::unique_lock` that currently owns `HomeserverRuntime::mutex`
// for this thread's in-flight request, so code deeper in the call stack can
// release that lock around a blocking network call without threading the lock
// object through every intervening signature.
//
// The publication is thread_local, so one request thread never observes
// another's guard. A thread that publishes nothing — the federation worker, a
// test calling a service function directly — leaves the publication null and
// `NetworkIoUnlock` below then does nothing at all.
//
// Nesting is supported: the innermost scope wins and restores its predecessor
// on exit. That matches the one nesting path in the server, where the
// client-server dispatcher releases its own guard before delegating a media
// route to the local router, which then takes (and publishes) its own.
class RequestLockScope final
{
public:
    explicit RequestLockScope(std::unique_lock<std::recursive_mutex>& guard) noexcept;
    ~RequestLockScope();

    RequestLockScope(RequestLockScope const&) = delete;
    auto operator=(RequestLockScope const&) -> RequestLockScope& = delete;
    RequestLockScope(RequestLockScope&&) = delete;
    auto operator=(RequestLockScope&&) -> RequestLockScope& = delete;

private:
    std::unique_lock<std::recursive_mutex>* previous_{nullptr};
};

// Releases this thread's published request lock for the lifetime of the scope
// and re-acquires it on exit, including when the guarded call throws.
//
// Holding `runtime.mutex` across outbound HTTP freezes the whole process:
// every client-server request and every inbound federation transaction
// contends on that one mutex, so one slow or unreachable peer stalls all of
// them for the full duration of the timeout — up to `remote_timeout_seconds`
// per destination. Wrap every blocking network call that can run beneath a
// request handler in one of these, and keep runtime state reads and mutations
// outside it.
//
// Doing nothing is always a valid outcome: when no guard is published, or the
// published guard does not currently own the mutex (a caller released it by
// hand first), the scope neither unlocks nor re-locks. It therefore composes
// with the existing hand-written unlock/lock pairs rather than fighting them.
class NetworkIoUnlock final
{
public:
    NetworkIoUnlock() noexcept;

    // Re-acquires the mutex released by the constructor. A failure to
    // re-acquire leaves the runtime's locking invariant broken with no way to
    // signal it from a destructor, so the resulting exception terminates
    // rather than allowing the caller to continue unsynchronised.
    ~NetworkIoUnlock();

    NetworkIoUnlock(NetworkIoUnlock const&) = delete;
    auto operator=(NetworkIoUnlock const&) -> NetworkIoUnlock& = delete;
    NetworkIoUnlock(NetworkIoUnlock&&) = delete;
    auto operator=(NetworkIoUnlock&&) -> NetworkIoUnlock& = delete;

private:
    std::unique_lock<std::recursive_mutex>* released_{nullptr};
};


// Releases a guard the caller holds directly for the lifetime of the scope and
// re-acquires it on exit, including when the guarded call throws.
//
// This is the counterpart to NetworkIoUnlock for the case where the lock
// object is in hand rather than published: the caller must release its *own*
// outer guard before calling a function that takes runtime.mutex itself (a
// recursive mutex means a nested acquisition would otherwise keep the mutex
// held across the inner call's blocking work). Those sites were written as a
// bare `guard.unlock(); f(); guard.lock();` triple, which never re-acquires if
// `f()` throws or if control leaves the region early — the request then
// continues, and the next request on this thread runs, with the runtime's
// locking invariant silently broken.
//
// Use this rather than NetworkIoUnlock whenever the guard to release is the
// local one: NetworkIoUnlock acts on the thread's *published* guard, which at
// a nested call site is not necessarily the same object.
class ScopedGuardRelease final
{
public:
    explicit ScopedGuardRelease(std::unique_lock<std::recursive_mutex>& guard) noexcept;

    // Re-acquires the guard released by the constructor. As with
    // NetworkIoUnlock, a failure to re-acquire leaves the locking invariant
    // broken with no way to signal it from a destructor, so the resulting
    // exception terminates rather than letting the caller continue
    // unsynchronised.
    ~ScopedGuardRelease();

    ScopedGuardRelease(ScopedGuardRelease const&) = delete;
    auto operator=(ScopedGuardRelease const&) -> ScopedGuardRelease& = delete;
    ScopedGuardRelease(ScopedGuardRelease&&) = delete;
    auto operator=(ScopedGuardRelease&&) -> ScopedGuardRelease& = delete;

private:
    std::unique_lock<std::recursive_mutex>* released_{nullptr};
};

} // namespace merovingian::homeserver
