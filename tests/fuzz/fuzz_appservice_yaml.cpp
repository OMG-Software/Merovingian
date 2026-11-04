// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the bounded YAML subset parser for an application service registration file, and the
// JSON parser it defers to. A registration is operator-authored, but bridges ship their own files.

#include "fuzz_input.hpp"
#include "merovingian/appservice/registration.hpp"

#include <cstddef>
#include <cstdint>
#include <tuple>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = merovingian::fuzz::to_string(data, size);
    std::ignore = merovingian::appservice::parse_registration_yaml(input);
    std::ignore = merovingian::appservice::parse_registration_json(input);
    return 0;
}
