// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/SemaphorePermit.hpp" // split-shim

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

} // namespace merovingian::core
