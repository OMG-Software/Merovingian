// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <optional>
#include <semaphore>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::auth
{

constexpr std::size_t argon2id_admission_max_capacity = 128U;

// Default number of concurrent Argon2id hash operations the process will admit.
// This is CPU-bound, memory-hard work; allowing it to run without a cap lets a
// moderate volume of login or registration-token attempts exhaust both memory
// bandwidth and the global runtime mutex (AUTH-4).
[[nodiscard]] constexpr auto default_argon2id_capacity() noexcept -> std::size_t
{
    return 4U;
}

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

// Argon2id-hash a password using libsodium's interactive limits. The returned
// string is safe to keep in memory and to compare with password_matches.
[[nodiscard]] auto hash_password(std::string_view password) -> std::optional<std::string>;

// Constant-time verify a password against an Argon2id hash produced by hash_password.
[[nodiscard]] auto password_matches(std::string_view password_hash, std::string_view password) noexcept -> bool;

// Argon2id-hash a registration token. Empty tokens are rejected so the failure is
// obvious rather than producing a predictable hash.
[[nodiscard]] auto hash_registration_token(std::span<std::uint8_t const> token) -> std::optional<std::string>;

// Constant-time verify a presented registration token against an Argon2id hash
// produced by hash_registration_token.
[[nodiscard]] auto registration_token_matches(std::string_view expected_hash, std::string_view presented) noexcept
    -> bool;

} // namespace merovingian::auth
