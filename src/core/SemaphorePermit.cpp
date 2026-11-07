// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/SemaphorePermit.hpp"

#include "merovingian/core/portable_semaphore.hpp"

#include <utility>

namespace merovingian::core
{

SemaphorePermit::SemaphorePermit(PortableSemaphore& semaphore) noexcept
    : m_semaphore{semaphore}
{
}

SemaphorePermit::SemaphorePermit(SemaphorePermit&& other) noexcept
    : m_semaphore{other.m_semaphore}
    , m_owns{std::exchange(other.m_owns, false)}
{
}

SemaphorePermit::~SemaphorePermit() noexcept
{
    if (m_owns)
    {
        m_semaphore.release();
    }
}

} // namespace merovingian::core
