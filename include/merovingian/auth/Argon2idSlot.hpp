// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <semaphore>

namespace merovingian::auth
{

constexpr std::size_t argon2id_admission_max_capacity = 128U;

// RAII handle representing one unit of in-flight Argon2id work. The handle
// releases the slot back to the admission semaphore on destruction, including
// when the guarded hash operation throws.
class Argon2idSlot final
{
public:
    Argon2idSlot() noexcept = default;
    explicit Argon2idSlot(std::counting_semaphore<argon2id_admission_max_capacity>& semaphore) noexcept;
    ~Argon2idSlot();

    Argon2idSlot(Argon2idSlot const&) = delete;
    auto operator=(Argon2idSlot const&) -> Argon2idSlot& = delete;
    Argon2idSlot(Argon2idSlot&& other) noexcept;
    auto operator=(Argon2idSlot&& other) noexcept -> Argon2idSlot&;

    [[nodiscard]] explicit operator bool() const noexcept;

private:
    std::counting_semaphore<argon2id_admission_max_capacity>* m_semaphore{nullptr};
};

} // namespace merovingian::auth
