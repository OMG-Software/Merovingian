// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/Argon2idSlot.hpp"

#include <cstddef>
#include <optional>
#include <semaphore>

namespace merovingian::auth
{

// Bounded admission semaphore for memory-hard Argon2id hashing. `try_acquire()`
// is non-blocking: when the semaphore is exhausted the caller must shed load
// (HTTP 429 / M_LIMIT_EXCEEDED) instead of queueing more work.
class Argon2idAdmission final
{
public:
    explicit Argon2idAdmission(std::size_t capacity);
    ~Argon2idAdmission() = default;

    Argon2idAdmission(Argon2idAdmission const&) = delete;
    auto operator=(Argon2idAdmission const&) -> Argon2idAdmission& = delete;
    Argon2idAdmission(Argon2idAdmission&&) = delete;
    auto operator=(Argon2idAdmission&&) -> Argon2idAdmission& = delete;

    [[nodiscard]] auto try_acquire() -> std::optional<Argon2idSlot>;
    [[nodiscard]] auto capacity() const noexcept -> std::size_t;

private:
    std::size_t m_capacity{};
    std::counting_semaphore<argon2id_admission_max_capacity> m_semaphore;
};

} // namespace merovingian::auth
