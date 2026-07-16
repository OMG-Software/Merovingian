// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/random.hpp"

#include <sodium.h>

namespace merovingian::crypto
{
namespace
{

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

} // namespace

auto random_size_is_allowed(std::size_t size) noexcept -> bool
{
    return size > 0U && size <= 4096U;
}

auto secure_random_bytes(std::size_t size) -> std::optional<std::vector<std::uint8_t>>
{
    if (!random_size_is_allowed(size) || !sodium_is_ready())
    {
        return std::nullopt;
    }
    auto bytes = std::vector<std::uint8_t>(size);
    randombytes_buf(bytes.data(), size);
    return bytes;
}

auto secure_random_hex(std::size_t byte_count) -> std::optional<std::string>
{
    if (!random_size_is_allowed(byte_count) || !sodium_is_ready())
    {
        return std::nullopt;
    }
    auto bytes = std::vector<std::uint8_t>(byte_count);
    randombytes_buf(bytes.data(), byte_count);
    auto output = std::string(byte_count * 2U + 1U, '\0');
    if (sodium_bin2hex(output.data(), output.size(), bytes.data(), byte_count) == nullptr)
    {
        return std::nullopt;
    }
    output.pop_back(); // sodium_bin2hex writes a null terminator
    return output;
}

} // namespace merovingian::crypto
