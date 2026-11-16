// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the OAuth 2.0 client metadata validator (oauth::ClientMetadata::validate) on whatever JSON the bytes
// parse to, then its serialisers.

#include "fuzz_input.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/oauth/ClientMetadata.hpp"

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <variant>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = merovingian::fuzz::to_string(data, size);
    auto const parsed = merovingian::canonicaljson::parse_json(input);
    if (parsed.error != merovingian::canonicaljson::ParseError::none)
    {
        return 0;
    }
    auto const result = merovingian::oauth::ClientMetadata::validate(parsed.value);
    if (auto const* metadata = std::get_if<merovingian::oauth::ClientMetadata>(&result))
    {
        std::ignore = metadata->to_json();
        std::ignore = metadata->canonical_bytes();
    }
    return 0;
}
