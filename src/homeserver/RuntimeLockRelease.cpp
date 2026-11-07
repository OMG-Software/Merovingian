// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RuntimeLockRelease.hpp"

#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/runtime_mutex.hpp"

namespace merovingian::homeserver
{

RuntimeLockRelease::RuntimeLockRelease() noexcept
{
    release(published_request_mutex());
}

RuntimeLockRelease::RuntimeLockRelease(RuntimeLock& guard) noexcept
{
    release(guard.mutex());
}

void RuntimeLockRelease::release(RuntimeMutex const* mutex) noexcept
{
    if (mutex == nullptr)
    {
        // No request handler on the stack and no guard in hand, or a guard with
        // no mutex: there is nothing to act on. This is the federation worker
        // and the direct-call test path.
        return;
    }
    mutex_ = mutex;
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
