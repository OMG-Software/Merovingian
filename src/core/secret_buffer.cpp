// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/secret_buffer.hpp"

#include <algorithm>
#include <new>
#include <utility>

#include <sodium.h>

namespace merovingian::core
{

auto secure_zero(std::span<std::byte> bytes) noexcept -> void
{
    if (!bytes.empty())
    {
        sodium_memzero(bytes.data(), bytes.size());
    }
}

auto SecretBuffer::SodiumDeleter::operator()(std::uint8_t* buffer) const noexcept -> void
{
    sodium_free(buffer); // Wipes and unlocks this allocation's isolated pages.
}

SecretBuffer::SecretBuffer(std::size_t size)
{
    if (size == 0U)
    {
        return;
    }
    if (sodium_init() < 0)
    {
        throw std::bad_alloc{};
    }
    m_buffer.reset(static_cast<std::uint8_t*>(sodium_malloc(size)));
    if (!m_buffer)
    {
        throw std::bad_alloc{};
    }
    m_size = size;
    // sodium_malloc attempts locking but does not report its outcome. Explicitly
    // lock the isolated data pages so is_locked reflects an actual syscall.
    m_mlocked = sodium_mlock(m_buffer.get(), m_size) == 0;
    sodium_memzero(m_buffer.get(), m_size);
}

SecretBuffer::SecretBuffer(std::span<std::uint8_t const> bytes)
    : SecretBuffer(bytes.size())
{
    std::copy(bytes.begin(), bytes.end(), this->bytes().begin());
}

SecretBuffer::SecretBuffer(SecretBuffer&& other) noexcept
    : m_buffer(std::move(other.m_buffer))
    , m_size(std::exchange(other.m_size, 0U))
    , m_mlocked(std::exchange(other.m_mlocked, false))
{
    // The mlocked buffer transfers to this object; the source is left empty and
    // no longer considered mlocked, so its destructor is a no-op.
}

auto SecretBuffer::operator=(SecretBuffer&& other) noexcept -> SecretBuffer&
{
    if (this != &other)
    {
        m_buffer = std::move(other.m_buffer);
        m_size = std::exchange(other.m_size, 0U);
        m_mlocked = std::exchange(other.m_mlocked, false);
    }
    return *this;
}

SecretBuffer::~SecretBuffer() = default;

auto SecretBuffer::bytes() noexcept -> std::span<std::uint8_t>
{
    return std::span<std::uint8_t>{m_buffer.get(), m_size};
}

auto SecretBuffer::bytes() const noexcept -> std::span<std::uint8_t const>
{
    return std::span<std::uint8_t const>{m_buffer.get(), m_size};
}

auto SecretBuffer::is_locked() const noexcept -> bool
{
    return m_mlocked;
}

} // namespace merovingian::core