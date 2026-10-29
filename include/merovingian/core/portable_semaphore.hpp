// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>

namespace merovingian::core
{

// Counting semaphore. std::counting_semaphore is not available on every
// supported platform (NetBSD's libc++ lacks it).
class PortableSemaphore final
{
public:
    explicit PortableSemaphore(std::size_t count) noexcept;

    PortableSemaphore(PortableSemaphore const&) = delete;
    auto operator=(PortableSemaphore const&) -> PortableSemaphore& = delete;
    PortableSemaphore(PortableSemaphore&&) = delete;
    auto operator=(PortableSemaphore&&) -> PortableSemaphore& = delete;
    ~PortableSemaphore() = default;

    // Blocks until a slot is free, then takes it.
    auto acquire() -> void;
    auto release() noexcept -> void;

private:
    std::mutex m_mutex{};
    std::condition_variable m_available{};
    std::size_t m_count;
};

// Owns one slot of a PortableSemaphore that the caller has already acquired,
// and releases it on destruction, so a slot is given back however the holder
// leaves its scope (return, throw, or a task that never launched). Movable, so
// a slot can be handed to a task; the moved-from permit releases nothing.
class SemaphorePermit final
{
public:
    explicit SemaphorePermit(PortableSemaphore& semaphore) noexcept;

    SemaphorePermit(SemaphorePermit const&) = delete;
    auto operator=(SemaphorePermit const&) -> SemaphorePermit& = delete;
    SemaphorePermit(SemaphorePermit&& other) noexcept;
    auto operator=(SemaphorePermit&&) -> SemaphorePermit& = delete;
    ~SemaphorePermit() noexcept;

private:
    PortableSemaphore& m_semaphore;
    bool m_owns{true};
};

} // namespace merovingian::core
