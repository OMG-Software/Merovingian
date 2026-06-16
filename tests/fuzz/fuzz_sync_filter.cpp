// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sync_filter.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto input = std::string{};
    input.reserve(size);
    for (auto i = std::size_t{0U}; i < size; ++i)
    {
        input.push_back(static_cast<char>(data[i]));
    }

    std::ignore = merovingian::sync::parse_filter_argument(input);
    return 0;
}
