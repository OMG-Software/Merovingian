// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/Argon2idAdmission.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>

namespace merovingian::auth
{

Argon2idAdmission::Argon2idAdmission(std::size_t capacity)
    : m_capacity{std::min(capacity, argon2id_admission_max_capacity)}
    , m_semaphore{static_cast<std::ptrdiff_t>(m_capacity)}
{
}

auto Argon2idAdmission::try_acquire() -> std::optional<Argon2idSlot>
{
    if (!m_semaphore.try_acquire())
    {
        return std::nullopt;
    }
    return Argon2idSlot{m_semaphore};
}

auto Argon2idAdmission::capacity() const noexcept -> std::size_t
{
    return m_capacity;
}

} // namespace merovingian::auth
