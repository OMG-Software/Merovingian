// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the OAuth 2.0 scope parser (oauth::parse_scope) against arbitrary bytes.

#include "fuzz_input.hpp"
#include "merovingian/oauth/ScopeParser.hpp"

#include <cstddef>
#include <cstdint>
#include <tuple>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = merovingian::fuzz::to_string(data, size);
    std::ignore = merovingian::oauth::parse_scope(input);
    std::ignore = merovingian::oauth::oauth_device_id_is_valid(input);
    return 0;
}
