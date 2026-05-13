// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::canonicaljson
{

enum class ParseError : std::uint8_t
{
    none,
    trailing_data,
    unexpected_end,
    unexpected_token,
    invalid_literal,
    invalid_string,
    invalid_escape,
    invalid_unicode_escape,
    invalid_number,
    integer_out_of_range,
    duplicate_object_key,
    nesting_too_deep,
};

struct ParseResult final
{
    Value value{};
    ParseError error{ParseError::none};
};

[[nodiscard]] auto parse_error_name(ParseError error) noexcept -> char const*;
[[nodiscard]] auto utf8_is_valid(std::string_view value) noexcept -> bool;
[[nodiscard]] auto parse_lossless(std::string_view input) -> ParseResult;

} // namespace merovingian::canonicaljson
