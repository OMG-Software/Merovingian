// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the strict application/x-www-form-urlencoded reader (core::FormFields::parse) and its lookups against
// arbitrary bytes.

#include "fuzz_input.hpp"
#include "merovingian/core/FormFields.hpp"

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <variant>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = merovingian::fuzz::to_string(data, size);
    auto const parsed = merovingian::core::FormFields::parse(input);
    if (auto const* fields = std::get_if<merovingian::core::FormFields>(&parsed))
    {
        for (auto const& [name, value] : fields->fields())
        {
            std::ignore = fields->find(name);
            std::ignore = value.size();
        }
        std::ignore = fields->find("client_id");
    }
    return 0;
}
