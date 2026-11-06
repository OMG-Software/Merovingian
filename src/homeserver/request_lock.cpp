// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/request_lock.hpp"

namespace merovingian::homeserver
{
namespace
{

    // The guard owning runtime.mutex for this thread's in-flight request, or
    // null when this thread is not inside a request handler. Only ever read and
    // written by its own thread, so it needs no synchronisation of its own.
    thread_local auto* current_request_guard = static_cast<RuntimeLock*>(nullptr);

} // namespace

RequestLockScope::RequestLockScope(RuntimeLock& guard) noexcept
    : previous_{current_request_guard}
{
    current_request_guard = &guard;
}

RequestLockScope::~RequestLockScope()
{
    current_request_guard = previous_;
}

RuntimeLockRelease::RuntimeLockRelease() noexcept
{
    release(current_request_guard);
}

RuntimeLockRelease::RuntimeLockRelease(RuntimeLock& guard) noexcept
{
    release(&guard);
}

void RuntimeLockRelease::release(RuntimeLock* guard) noexcept
{
    if (guard == nullptr)
    {
        // No request handler on the stack and no guard in hand: there is no
        // mutex to act on. This is the federation worker and the direct-call
        // test path.
        return;
    }
    // The guard is only ever consulted for which mutex it refers to, never for
    // whether it believes it owns it. `unique_lock::mutex()` answers that even
    // when the lock is not held.
    mutex_ = guard->mutex();
    if (mutex_ == nullptr)
    {
        return;
    }
    // Drop every level this thread holds, through the mutex rather than
    // through any guard.
    //
    // Two reasons it must work this way. First, the levels belong to
    // `unique_lock` objects in frames this scope cannot reach — a dispatcher's
    // guard, a self-locking caller's — and leaving one held keeps the mutex
    // locked for the whole of the blocking work this scope was opened for.
    // Second, releasing through one guard while draining the rest through the
    // mutex would leave that guard's `owns_lock()` flag and the real recursion
    // depth disagreeing in opposite directions across two objects; an inner
    // release scope that then trusted a flag would unlock a mutex this thread
    // no longer holds, underflow `depth_`, and strand the runtime mutex locked
    // for the life of the process.
    //
    // The consequence, and the reason this is safe: **every `unique_lock` on
    // this mutex keeps reporting `owns_lock() == true` for the lifetime of
    // this scope, including the one passed in.** Nothing outside this file
    // reads that flag (`grep -rn owns_lock src include`), the depth is
    // restored exactly before any of those guards can act on it, and an inner
    // release scope reads the mutex — see `held_by_current_thread` — so it
    // correctly finds nothing left to release.
    while (mutex_->held_by_current_thread())
    {
        mutex_->unlock(); // LOCK_RELEASE: reviewed — this IS the RAII release scope; the destructor
                          // re-acquires exactly `levels_` on every path, throwing included.
        ++levels_;
    }
}

RuntimeLockRelease::~RuntimeLockRelease()
{
    for (auto level = std::size_t{0U}; level < levels_; ++level)
    {
        mutex_->lock();
    }
}

auto RuntimeLockRelease::levels_released() const noexcept -> std::size_t
{
    return levels_;
}

} // namespace merovingian::homeserver
