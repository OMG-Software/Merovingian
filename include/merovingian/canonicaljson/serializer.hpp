// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::canonicaljson
{

enum class CanonicalJsonError : unsigned char
{
    none,
    duplicate_object_key,
    invalid_string,
};

struct SerializeResult final
{
    std::string output{};
    CanonicalJsonError error{CanonicalJsonError::none};
};

[[nodiscard]] auto canonical_json_error_name(CanonicalJsonError error) noexcept -> char const*;
[[nodiscard]] auto string_is_valid_for_json(std::string_view value) noexcept -> bool;
[[nodiscard]] auto object_has_duplicate_keys(Object const& object) noexcept -> bool;
[[nodiscard]] auto serialize_canonical(Value const& value) -> SerializeResult;

} // namespace merovingian::canonicaljson
