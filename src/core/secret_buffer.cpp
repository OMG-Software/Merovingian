// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/core/secret_buffer.hpp>

#include <algorithm>

namespace merovingian::core {

SecretBuffer::SecretBuffer(std::size_t size)
    : buffer_(size, 0U) {
}

SecretBuffer::~SecretBuffer() {
    std::ranges::fill(buffer_, static_cast<std::uint8_t>(0U));
}

auto SecretBuffer::bytes() noexcept -> std::span<std::uint8_t> {
    return std::span<std::uint8_t>{buffer_};
}

auto SecretBuffer::bytes() const noexcept -> std::span<std::uint8_t const> {
    return std::span<std::uint8_t const>{buffer_};
}

} // namespace merovingian::core
