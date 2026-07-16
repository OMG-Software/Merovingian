// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/encoding.hpp"

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

auto to_hex(std::span<unsigned char const> bytes) -> std::optional<std::string>
{
    if (bytes.empty() || !sodium_is_ready())
    {
        return std::nullopt;
    }
    auto output = std::string(bytes.size() * 2U + 1U, '\0');
    if (sodium_bin2hex(output.data(), output.size(), bytes.data(), bytes.size()) == nullptr)
    {
        return std::nullopt;
    }
    output.pop_back(); // sodium_bin2hex writes a null terminator
    return output;
}

auto base64_urlsafe_encode(std::string_view input) -> std::optional<std::string>
{
    if (input.empty() || !sodium_is_ready())
    {
        return std::nullopt;
    }
    auto constexpr variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
    auto output = std::string(sodium_base64_ENCODED_LEN(input.size(), variant), '\0');
    if (sodium_bin2base64(output.data(), output.size(), reinterpret_cast<unsigned char const*>(input.data()),
                          input.size(), variant) == nullptr)
    {
        return std::nullopt;
    }
    output.pop_back(); // sodium_bin2base64 writes a null terminator
    return output;
}

auto base64_urlsafe_decode(std::string_view input) -> std::optional<std::string>
{
    if (input.empty() || !sodium_is_ready())
    {
        return std::nullopt;
    }
    auto constexpr variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
    auto output = std::string(input.size(), '\0');
    auto decoded_len = std::size_t{0U};
    if (sodium_base642bin(reinterpret_cast<unsigned char*>(output.data()), output.size(), input.data(), input.size(),
                          nullptr, &decoded_len, nullptr, variant) != 0)
    {
        return std::nullopt;
    }
    output.resize(decoded_len);
    return output;
}

auto base64_original_encode(std::string_view input) -> std::optional<std::string>
{
    if (input.empty() || !sodium_is_ready())
    {
        return std::nullopt;
    }
    auto constexpr variant = sodium_base64_VARIANT_ORIGINAL;
    auto output = std::string(sodium_base64_ENCODED_LEN(input.size(), variant), '\0');
    if (sodium_bin2base64(output.data(), output.size(), reinterpret_cast<unsigned char const*>(input.data()),
                          input.size(), variant) == nullptr)
    {
        return std::nullopt;
    }
    output.pop_back(); // sodium_bin2base64 writes a null terminator
    return output;
}

auto base64_original_decode(std::string_view input) -> std::optional<std::string>
{
    if (input.empty() || !sodium_is_ready())
    {
        return std::nullopt;
    }
    auto constexpr variant = sodium_base64_VARIANT_ORIGINAL;
    auto output = std::string(input.size(), '\0');
    auto decoded_len = std::size_t{0U};
    if (sodium_base642bin(reinterpret_cast<unsigned char*>(output.data()), output.size(), input.data(), input.size(),
                          nullptr, &decoded_len, nullptr, variant) != 0)
    {
        return std::nullopt;
    }
    output.resize(decoded_len);
    return output;
}

} // namespace merovingian::crypto
