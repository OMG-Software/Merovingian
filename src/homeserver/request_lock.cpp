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
    thread_local auto* current_request_guard = static_cast<std::unique_lock<std::recursive_mutex>*>(nullptr);

} // namespace

RequestLockScope::RequestLockScope(std::unique_lock<std::recursive_mutex>& guard) noexcept
    : previous_{current_request_guard}
{
    current_request_guard = &guard;
}

RequestLockScope::~RequestLockScope()
{
    current_request_guard = previous_;
}

NetworkIoUnlock::NetworkIoUnlock() noexcept
{
    // Only release a lock this thread actually holds. A null publication means
    // no request handler is on the stack; a published guard that does not own
    // the mutex means a caller already released it by hand.
    if (current_request_guard != nullptr && current_request_guard->owns_lock())
    {
        released_ = current_request_guard;
        released_->unlock();
    }
}

NetworkIoUnlock::~NetworkIoUnlock()
{
    if (released_ != nullptr)
    {
        released_->lock();
    }
}


ScopedGuardRelease::ScopedGuardRelease(std::unique_lock<std::recursive_mutex>& guard) noexcept
{
    // Only release a guard that currently owns the mutex; releasing one that
    // does not would re-acquire on exit a lock the caller never held.
    if (guard.owns_lock())
    {
        released_ = &guard;
        released_->unlock();
    }
}

ScopedGuardRelease::~ScopedGuardRelease()
{
    if (released_ != nullptr)
    {
        released_->lock();
    }
}

} // namespace merovingian::homeserver
