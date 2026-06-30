// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/master_key.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <ios>
#include <vector>

namespace merovingian::crypto
{

auto load_master_key_material(std::string_view path) -> std::optional<std::vector<std::uint8_t>>
{
    if (path.empty())
    {
        return std::nullopt;
    }
    auto stream = std::ifstream{std::string{path}, std::ios::binary};
    if (!stream)
    {
        return std::nullopt;
    }
    auto content = std::vector<std::uint8_t>{};
    auto constexpr size_limit = std::size_t{4096U};
    auto buffer = std::array<char, 1024U>{};
    while (stream.good())
    {
        stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        auto const count = stream.gcount();
        if (count <= 0)
        {
            break;
        }
        auto const added = static_cast<std::size_t>(count);
        if (content.size() + added > size_limit)
        {
            return std::nullopt;
        }
        content.insert(content.end(), reinterpret_cast<std::uint8_t*>(buffer.data()),
                       reinterpret_cast<std::uint8_t*>(buffer.data()) + added);
    }
    if (content.empty())
    {
        return std::nullopt;
    }
    return content;
}

} // namespace merovingian::crypto