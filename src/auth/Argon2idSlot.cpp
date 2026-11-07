// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/Argon2idSlot.hpp"

#include <utility>

namespace merovingian::auth
{

Argon2idSlot::Argon2idSlot(std::counting_semaphore<argon2id_admission_max_capacity>& semaphore) noexcept
    : m_semaphore{&semaphore}
{
}

Argon2idSlot::~Argon2idSlot()
{
    if (m_semaphore != nullptr)
    {
        m_semaphore->release();
    }
}

Argon2idSlot::Argon2idSlot(Argon2idSlot&& other) noexcept
    : m_semaphore{std::exchange(other.m_semaphore, nullptr)}
{
}

auto Argon2idSlot::operator=(Argon2idSlot&& other) noexcept -> Argon2idSlot&
{
    if (this != &other)
    {
        if (m_semaphore != nullptr)
        {
            m_semaphore->release();
        }
        m_semaphore = std::exchange(other.m_semaphore, nullptr);
    }
    return *this;
}

Argon2idSlot::operator bool() const noexcept
{
    return m_semaphore != nullptr;
}

} // namespace merovingian::auth
