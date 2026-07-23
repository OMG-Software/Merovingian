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
    float_not_allowed,
};

struct SerializeResult final
{
    std::string output{};
    CanonicalJsonError error{CanonicalJsonError::none};
};

[[nodiscard]] auto canonical_json_error_name(CanonicalJsonError error) noexcept -> char const*;
[[nodiscard]] auto string_is_valid_for_json(std::string_view value) noexcept -> bool;
[[nodiscard]] auto object_has_duplicate_keys(Object const& object) noexcept -> bool;
// General-purpose canonical serialization. Floats are permitted (and
// serialized with a correct, shortest round-tripping representation) because
// this is also used for ordinary, never-signed JSON responses that
// legitimately contain floats (e.g. the m.tag `order` field, account data).
[[nodiscard]] auto serialize_canonical(Value const& value) -> SerializeResult;
// Signing/hashing-path serialization. Identical to serialize_canonical
// except a Value tree containing any double fails closed with
// CanonicalJsonError::float_not_allowed instead of being serialized —
// canonical JSON MUST NOT contain floats in signed/hashed data
// (docs/matrix-v1.19-spec/appendices.md#canonical-json). Use this from
// event_signer.cpp, event_id.cpp, and any other code producing bytes that
// will be hashed or Ed25519-signed.
[[nodiscard]] auto serialize_canonical_strict(Value const& value) -> SerializeResult;

} // namespace merovingian::canonicaljson
