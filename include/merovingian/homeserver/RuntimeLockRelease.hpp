// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime_mutex.hpp"

#include <cstddef>
#include <mutex>

namespace merovingian::homeserver
{

// Releases `HomeserverRuntime::mutex` for the lifetime of the scope and
// re-acquires it on exit, including when the guarded call throws.
//
// Holding `runtime.mutex` across outbound HTTP freezes the whole process:
// every client-server request and every inbound federation transaction
// contends on that one mutex, so one slow or unreachable peer stalls all of
// them for the full duration of the timeout — up to `remote_timeout_seconds`
// per destination. Wrap every blocking network call that can run beneath a
// request handler in one of these, and keep runtime state reads and mutations
// outside it.
//
// **It releases every recursion level this thread holds, not just one.**
// `runtime.mutex` is recursive and a self-locking service function called from
// a request handler holds it twice: once via the dispatcher's guard and once
// via its own. Dropping a single level leaves the mutex held for the whole
// blocking call — the defect shipped three times over
// (`create_room` 0.12.1, `leave_room` 0.12.3, `invite_user_by_threepid`
// 0.12.6), each time because the author released the guard they had in hand
// and not the one an outer frame held. Every level is restored on exit, in the
// same count, so outer frames resume owning exactly what they owned before.
//
// Two constructors, one behaviour:
//
//   RuntimeLockRelease{}        // the mutex the thread's request published
//   RuntimeLockRelease{guard}   // the mutex a guard in hand refers to
//
// The argument says only which `unique_lock` to read the mutex address from,
// never whether that guard believes it owns it. The set of levels released is
// the same either way, so choosing the "wrong" one can no longer leave the
// mutex held.
//
// **A guard's `owns_lock()` is NOT cleared for the duration of the scope.**
// The levels being dropped belong to `unique_lock` objects in frames this
// scope cannot reach, so the release necessarily goes through the mutex and no
// guard's bookkeeping flag can be updated — the one passed in included. That
// is sound only because nothing outside `request_lock.cpp` reads the flag
// (`grep -rn owns_lock src include`) and the depth is restored exactly before
// any guard can act on it. Read `RuntimeMutex::held_by_current_thread()`
// instead if you need to know whether the mutex is held; a nested release
// scope does exactly that, and so correctly finds nothing left to release.
//
// Doing nothing is always a valid outcome: with no guard published and none
// passed, there is no mutex to act on and the scope neither unlocks nor
// re-locks.
class RuntimeLockRelease final
{
public:
    // Releases this thread's published request lock (see `RequestLockScope`)
    // and any further levels the thread holds.
    RuntimeLockRelease() noexcept;

    // Releases `guard` and any further levels this thread holds. Use this
    // whenever the guard is in hand rather than published: a nested call site
    // has its own guard, and the published one belongs to a different frame.
    explicit RuntimeLockRelease(RuntimeLock& guard) noexcept;

    // Re-acquires everything the constructor released. A failure to re-acquire
    // leaves the runtime's locking invariant broken with no way to signal it
    // from a destructor, so the resulting exception terminates rather than
    // allowing the caller to continue unsynchronised.
    ~RuntimeLockRelease();

    RuntimeLockRelease(RuntimeLockRelease const&) = delete;
    auto operator=(RuntimeLockRelease const&) -> RuntimeLockRelease& = delete;
    RuntimeLockRelease(RuntimeLockRelease&&) = delete;
    auto operator=(RuntimeLockRelease&&) -> RuntimeLockRelease& = delete;

    // Number of recursion levels this scope dropped, and will restore. More
    // than one means some outer frame held `runtime.mutex` across this scope's
    // blocking work and would have stalled the server before this primitive
    // started draining those levels; zero means the thread held nothing, which
    // is the normal case for a nested scope. Exposed for tests and
    // diagnostics; correctness does not depend on anyone reading it.
    [[nodiscard]] auto levels_released() const noexcept -> std::size_t;

private:
    void release(RuntimeMutex const* mutex) noexcept;

    // Non-owning observer of the mutex this scope released, null when it
    // released nothing. A reference member cannot express "nothing to do", and
    // this mirrors what `std::unique_lock` itself stores.
    RuntimeMutex const* mutex_{nullptr};
    std::size_t levels_{0U};
};

} // namespace merovingian::homeserver
