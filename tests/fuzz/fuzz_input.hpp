// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Helpers shared by the fuzz targets that take more than one string from one byte buffer.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::fuzz
{

[[nodiscard]] inline auto to_string(std::uint8_t const* data, std::size_t size) -> std::string
{
    auto input = std::string{};
    input.reserve(size);
    for (auto index = std::size_t{0U}; index < size; ++index)
    {
        input.push_back(static_cast<char>(data[index]));
    }
    return input;
}

// Splits `input` at its first NUL byte. With no NUL the whole input is the first half and the
// second is empty. The NUL itself is dropped.
[[nodiscard]] inline auto split_at_nul(std::string_view input) -> std::pair<std::string_view, std::string_view>
{
    auto const at = input.find('\0');
    if (at == std::string_view::npos)
    {
        return {input, std::string_view{}};
    }
    return {input.substr(0U, at), input.substr(at + 1U)};
}

} // namespace merovingian::fuzz
