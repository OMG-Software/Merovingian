// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the Cookie request-header reader (core::RequestCookies::parse) and its lookup against arbitrary bytes.
// Bytes before the first NUL are the header value; the rest is the name looked up.

#include "fuzz_input.hpp"
#include "merovingian/core/RequestCookies.hpp"

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <variant>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = merovingian::fuzz::to_string(data, size);
    auto const [header, name] = merovingian::fuzz::split_at_nul(input);
    auto const parsed = merovingian::core::RequestCookies::parse(header);
    if (auto const* cookies = std::get_if<merovingian::core::RequestCookies>(&parsed))
    {
        std::ignore = cookies->find(name);
        std::ignore = cookies->find("__Host-oauth");
        std::ignore = cookies->size();
    }
    return 0;
}
