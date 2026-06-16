// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises both the query-string parser (parse_query_params) and the
// percent-decoder (percent_decode) against arbitrary byte sequences.

#include "merovingian/core/query_params.hpp"

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

    std::ignore = merovingian::core::parse_query_params(input);
    std::ignore = merovingian::core::percent_decode(input);
    return 0;
}
