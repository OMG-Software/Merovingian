// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/runtime_mutex.hpp"

#include <thread>

namespace merovingian::homeserver
{

void RuntimeMutex::lock() const
{
    mutex_.lock();
    ++depth_;
    // Publishing the owner after the acquisition means a concurrent
    // held_by_current_thread() on another thread never sees this thread as the
    // owner before it actually is.
    owner_.store(std::this_thread::get_id(), std::memory_order_release);
}

auto RuntimeMutex::try_lock() const -> bool
{
    if (!mutex_.try_lock())
    {
        return false;
    }
    ++depth_;
    owner_.store(std::this_thread::get_id(), std::memory_order_release);
    return true;
}

void RuntimeMutex::unlock() const
{
    // Clear the owner before the final release so no window exists in which the
    // mutex is free but still reports an owner. Intermediate levels leave the
    // owner in place: the thread genuinely still holds the mutex.
    --depth_;
    if (depth_ == 0U)
    {
        owner_.store(std::thread::id{}, std::memory_order_release);
    }
    mutex_.unlock(); // LOCK_RELEASE: reviewed — this IS the runtime mutex’s unlock; the RAII scope
                     // callers are pointed at (RuntimeLockRelease) is built on top of it.
}

auto RuntimeMutex::held_by_current_thread() const noexcept -> bool
{
    return owner_.load(std::memory_order_acquire) == std::this_thread::get_id();
}

} // namespace merovingian::homeserver
