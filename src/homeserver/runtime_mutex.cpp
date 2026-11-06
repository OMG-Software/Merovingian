// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/runtime_mutex.hpp"

#include <thread>

namespace merovingian::homeserver
{

void RuntimeMutex::lock() const
{
    if (held_by_current_thread())
    {
        // Re-entry: the thread already holds `mutex_`.
        depth_.fetch_add(1U);
        return;
    }
    mutex_.lock();
    depth_.store(1U);
    // Publishing the owner after the acquisition means a concurrent
    // held_by_current_thread() on another thread never sees this thread as the
    // owner before it actually is.
    owner_.store(std::this_thread::get_id(), std::memory_order_release);
}

auto RuntimeMutex::try_lock() const -> bool
{
    if (held_by_current_thread())
    {
        depth_.fetch_add(1U);
        return true;
    }
    if (!mutex_.try_lock())
    {
        return false;
    }
    depth_.store(1U);
    owner_.store(std::this_thread::get_id(), std::memory_order_release);
    return true;
}

void RuntimeMutex::unlock() const
{
    // Intermediate levels leave the owner and `mutex_` in place: the thread
    // genuinely still holds the mutex.
    if (depth_.fetch_sub(1U) != 1U)
    {
        return;
    }
    // Clear the owner before the final release so no window exists in which the
    // mutex is free but still reports an owner.
    owner_.store(std::thread::id{}, std::memory_order_release);
    mutex_.unlock(); // LOCK_RELEASE: reviewed — this IS the runtime mutex’s unlock; the RAII scope
                     // callers are pointed at (RuntimeLockRelease) is built on top of it.
}

auto RuntimeMutex::held_by_current_thread() const noexcept -> bool
{
    return owner_.load(std::memory_order_acquire) == std::this_thread::get_id();
}

} // namespace merovingian::homeserver
