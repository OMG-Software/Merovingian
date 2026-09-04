// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace merovingian::core
{

// Erase `bytes` in place with a wipe the compiler may not elide.
//
// Modules outside src/crypto/, src/events/, src/auth/ and this one must not
// call libsodium directly (security/reject-unsafe gate, see
// docs/security-coding-rules.md), so this is the sanctioned way for them to
// clear a buffer that held secret material -- e.g. the at-rest signing secret
// carried by database::PersistentServerSigningKey, which cannot be a
// SecretBuffer because its row has to stay copyable.
//
// Prefer SecretBuffer wherever the type can be move-only: this erases, but
// unlike SecretBuffer it does not pin the pages against swap.
auto secure_zero(std::span<std::byte> bytes) noexcept -> void;

class SecretBuffer final
{
public:
    SecretBuffer() = default;

    explicit SecretBuffer(std::size_t size);

    // Owns a freshly mlocked+zeroised copy of the supplied bytes. Used to move
    // secret material (e.g. the server signing key) out of an unpinned span into
    // a self-managing owner such as DispatchWorkerConfig::secret_key. The caller
    // keeps responsibility for wiping the source; this constructor only copies.
    explicit SecretBuffer(std::span<std::uint8_t const> bytes);

    SecretBuffer(SecretBuffer const&) = delete;
    auto operator=(SecretBuffer const&) -> SecretBuffer& = delete;

    // Custom moves keep the sodium_mlock/munlock pair aligned: the mlocked buffer
    // transfers to the destination and the source is left empty (not mlocked), so
    // neither a move nor a move-assignment over an existing secret can leak the
    // lock or leave residue unwiped.
    SecretBuffer(SecretBuffer&& other) noexcept;
    auto operator=(SecretBuffer&& other) noexcept -> SecretBuffer&;

    ~SecretBuffer();

    [[nodiscard]] auto bytes() noexcept -> std::span<std::uint8_t>;
    [[nodiscard]] auto bytes() const noexcept -> std::span<std::uint8_t const>;

    // True if the underlying page was successfully mlock(2)-ed.  Callers that
    // require locked memory (e.g. high-value secrets loaded from disk) can use
    // this to fail closed when RLIMIT_MEMLOCK prevents locking.
    [[nodiscard]] auto is_locked() const noexcept -> bool;

private:
    // Zeroise (and unpin, if mlocked) the current buffer in place. Used by the
    // destructor and move-assignment before the buffer is replaced or freed.
    auto wipe_current() noexcept -> void;

    std::vector<std::uint8_t> m_buffer{};
    bool m_mlocked{false};
};

} // namespace merovingian::core
