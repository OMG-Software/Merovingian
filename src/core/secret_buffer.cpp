// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/secret_buffer.hpp"

#include <utility>

#include <sodium.h>

namespace merovingian::core
{

SecretBuffer::SecretBuffer(std::size_t size)
    : m_buffer(size, 0U)
{
    // Pin the buffer into RAM so it cannot be swapped to disk while it holds
    // secret material. mlock may fail under RLIMIT_MEMLOCK; in that case the
    // buffer is still reliably zeroised on destruction via sodium_memzero.
    if (!m_buffer.empty())
    {
        m_mlocked = sodium_mlock(m_buffer.data(), m_buffer.size()) == 0;
    }
}

SecretBuffer::SecretBuffer(std::span<std::uint8_t const> bytes)
    : m_buffer(bytes.begin(), bytes.end())
{
    // Copy then pin: the source span may live in an unpinned std::string or a
    // caller-owned buffer, so this owner takes its own mlocked, zeroised copy.
    if (!m_buffer.empty())
    {
        m_mlocked = sodium_mlock(m_buffer.data(), m_buffer.size()) == 0;
    }
}

SecretBuffer::SecretBuffer(SecretBuffer&& other) noexcept
    : m_buffer(std::move(other.m_buffer))
    , m_mlocked(std::exchange(other.m_mlocked, false))
{
    // The mlocked buffer transfers to this object; the source is left empty and
    // no longer considered mlocked, so its destructor is a no-op.
}

auto SecretBuffer::operator=(SecretBuffer&& other) noexcept -> SecretBuffer&
{
    if (this != &other)
    {
        // Wipe the existing secret before replacing it — a plain vector
        // move-assignment would free the old buffer without wiping it.
        wipe_current();
        m_buffer = std::move(other.m_buffer);
        m_mlocked = std::exchange(other.m_mlocked, false);
    }
    return *this;
}

SecretBuffer::~SecretBuffer()
{
    wipe_current();
}

auto SecretBuffer::wipe_current() noexcept -> void
{
    if (m_buffer.empty())
    {
        return;
    }
    if (m_mlocked)
    {
        // sodium_munlock zeroises the buffer (volatile writes the compiler cannot
        // elide) and releases the mlock — an optimisation barrier as well as a wipe.
        sodium_munlock(m_buffer.data(), m_buffer.size());
        m_mlocked = false;
    }
    else
    {
        // Non-elidable volatile zeroise for the case where mlock failed.
        sodium_memzero(m_buffer.data(), m_buffer.size());
    }
}

auto SecretBuffer::bytes() noexcept -> std::span<std::uint8_t>
{
    return std::span<std::uint8_t>{m_buffer};
}

auto SecretBuffer::bytes() const noexcept -> std::span<std::uint8_t const>
{
    return std::span<std::uint8_t const>{m_buffer};
}

} // namespace merovingian::core