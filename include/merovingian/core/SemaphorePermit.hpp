// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::core
{

class PortableSemaphore;

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
