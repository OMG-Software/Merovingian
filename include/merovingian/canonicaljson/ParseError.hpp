// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

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
    too_many_object_members,
};

} // namespace merovingian::canonicaljson
