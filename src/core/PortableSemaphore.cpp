// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/PortableSemaphore.hpp"

#include <utility>

namespace merovingian::core
{

PortableSemaphore::PortableSemaphore(std::size_t const count) noexcept
    : m_count{count}
{
}

auto PortableSemaphore::acquire() -> void
{
    auto lock = std::unique_lock{m_mutex};
    m_available.wait(lock, [this] {
        return m_count > 0U;
    });
    --m_count;
}

auto PortableSemaphore::release() noexcept -> void
{
    {
        auto const lock = std::lock_guard{m_mutex};
        ++m_count;
    }
    m_available.notify_one();
}

} // namespace merovingian::core
