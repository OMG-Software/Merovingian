// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <atomic>
#include <cstddef>
#include <mutex>
#include <thread>

namespace merovingian::homeserver
{

// The mutex guarding `HomeserverRuntime`, and the one lock every client-server
// request, every inbound federation transaction, and every background worker
// contends on.
//
// It is a recursive mutex because a request handler that already holds it may
// call a service function which takes it again — `create_room`, `join_room`,
// and `invite_user_by_threepid` all remain independently callable. Recursion is
// what makes releasing it around blocking work subtle: `unlock()` drops ONE
// level, so a handler that releases its own guard while an outer frame still
// holds one leaves the mutex locked for the whole of the network call it
// thought it had released it for. That defect has reached production three
// times (`create_room` in 0.12.1, `leave_room` in 0.12.3,
// `invite_user_by_threepid` in 0.12.6).
//
// The recursion is implemented here, over a plain `std::mutex`, from the owner
// and depth this type records (ADR-0524): `std::recursive_mutex` cannot report
// whether the calling thread owns it, so the owner had to be recorded anyway,
// and keeping the depth in one place leaves one source of truth for both.
// A re-entry by the owner only raises the depth; the first lock takes the mutex
// and the last unlock releases it.
// `RuntimeLockRelease` (RuntimeLockRelease.hpp) uses `held_by_current_thread()` to
// drop *every* level the thread holds rather than only the one guard it was
// handed, which is what makes the release primitive impossible to misuse.
//
// Satisfies `Lockable`, so it works with `std::unique_lock`, `std::lock_guard`
// and `std::scoped_lock` exactly as `std::recursive_mutex` would.
class RuntimeMutex final
{
public:
    RuntimeMutex() noexcept = default;
    ~RuntimeMutex() = default;

    RuntimeMutex(RuntimeMutex const&) = delete;
    auto operator=(RuntimeMutex const&) -> RuntimeMutex& = delete;
    RuntimeMutex(RuntimeMutex&&) = delete;
    auto operator=(RuntimeMutex&&) -> RuntimeMutex& = delete;

    // `const` so a `HomeserverRuntime const&` can still be locked; the state
    // they change is `mutable` below and is the mutex's own, not the runtime's.
    // Every member they touch is a mutex or an atomic.
    void lock() const;
    [[nodiscard]] auto try_lock() const -> bool;
    void unlock() const;

    // True when the calling thread owns this mutex at any recursion depth.
    //
    // Safe to call from a thread that does not own the mutex: `owner_` is
    // atomic, and a non-owner can only ever read "unheld" or "held by some
    // other thread", both of which answer the question correctly. A true
    // result can only be produced by the owning thread itself, which is the
    // only thread that could have written its own id.
    [[nodiscard]] auto held_by_current_thread() const noexcept -> bool;

private:
    // Held from the first lock to the last unlock, whatever the depth.
    mutable std::mutex mutex_{};

    // The owning thread, or a default-constructed id when the mutex is
    // unheld. Written only by the owner while `mutex_` is held; read by any
    // thread, so it is atomic. A thread that reads its own id here owns the
    // mutex: no other thread ever writes that id.
    mutable std::atomic<std::thread::id> owner_{std::thread::id{}};

    // Recursion depth of the current owner. Only the owner reads or writes it,
    // while it holds `mutex_`; it is atomic so that holds by construction, not
    // only by that argument.
    mutable std::atomic<std::size_t> depth_{0U};
};

// Every lock of the runtime mutex uses this type, so the lock is const-correct
// and `RequestLockScope` / `RuntimeLockRelease` can recognise it.
using RuntimeLock = std::unique_lock<RuntimeMutex const>;

} // namespace merovingian::homeserver
