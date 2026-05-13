// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/secret_buffer.hpp"

#include <algorithm>

namespace merovingian::core
{

SecretBuffer::SecretBuffer(std::size_t size)
    : m_buffer(size, 0U)
{
}

SecretBuffer::~SecretBuffer()
{
    std::ranges::fill(m_buffer, static_cast<std::uint8_t>(0U));
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
