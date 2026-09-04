// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

#include <cstddef>
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
    too_many_object_members,
};

// Maximum number of members a single JSON object may contain. Enforced during
// parsing as a defense-in-depth cap alongside the O(n) duplicate-key check:
// an unauthenticated body of unique keys (e.g. to /login or /register)
// previously drove an O(n^2) duplicate-key scan into billions of
// comparisons. `max_body_bytes` (http/request_limits.hpp) is 1 MiB; the
// smallest possible object member encoding (`"":0,`) is 5 bytes, so a body
// filled edge-to-edge with members tops out around 200,000 of them. 65536
// (2^16) sits far below that pathological ceiling while remaining far above
// any legitimate Matrix payload this server parses — state event content,
// /keys/query responses, and filter definitions are all orders of magnitude
// smaller in practice.
inline constexpr auto max_object_members = std::size_t{65536U};

struct ParseResult final
{
    Value value{};
    ParseError error{ParseError::none};
};

[[nodiscard]] auto parse_error_name(ParseError error) noexcept -> char const*;
[[nodiscard]] auto utf8_is_valid(std::string_view value) noexcept -> bool;
// Canonical JSON parser: rejects floating-point/exponent numbers per Matrix v1.19.
[[nodiscard]] auto parse_lossless(std::string_view input) -> ParseResult;
// General JSON parser: accepts doubles/exponents while still enforcing depth,
// UTF-8, and duplicate-key constraints. Use for non-signing payloads such as
// account data and room tags.
[[nodiscard]] auto parse_json(std::string_view input) -> ParseResult;

} // namespace merovingian::canonicaljson
