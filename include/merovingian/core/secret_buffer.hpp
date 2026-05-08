// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace merovingian::core
{

class SecretBuffer final
{
public:
    SecretBuffer() = default;

    explicit SecretBuffer(std::size_t size);

    SecretBuffer(SecretBuffer const&) = delete;
    auto operator=(SecretBuffer const&) -> SecretBuffer& = delete;

    SecretBuffer(SecretBuffer&&) noexcept = default;
    auto operator=(SecretBuffer&&) noexcept -> SecretBuffer& = default;

    ~SecretBuffer();

    [[nodiscard]] auto bytes() noexcept -> std::span<std::uint8_t>;
    [[nodiscard]] auto bytes() const noexcept -> std::span<std::uint8_t const>;

private:
    std::vector<std::uint8_t> m_buffer{};
};

} // namespace merovingian::core
