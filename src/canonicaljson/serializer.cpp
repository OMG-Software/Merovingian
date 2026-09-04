// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/serializer.hpp"

#include "merovingian/canonicaljson/parser.hpp"

#include <algorithm>
#include <array>
#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <variant>

namespace merovingian::canonicaljson
{
namespace
{

    struct SerializedMember final
    {
        std::string key{};
        std::string value{};
    };

    [[nodiscard]] auto hex_digit(unsigned char value) noexcept -> char
    {
        constexpr auto digits =
            std::array<char, 16U>{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        return digits[value & 0x0FU];
    }

    auto append_control_escape(std::string& output, unsigned char value) -> void
    {
        output += "\\u00";
        output.push_back(hex_digit(static_cast<unsigned char>(value >> 4U)));
        output.push_back(hex_digit(value));
    }

    auto append_escaped_string(std::string& output, std::string_view value) -> void
    {
        output.push_back('"');
        for (auto const character : value)
        {
            auto const byte = static_cast<unsigned char>(character);
            switch (character)
            {
            case '"':
                output += "\\\"";
                break;
            case '\\':
                output += "\\\\";
                break;
            case '\b':
                output += "\\b";
                break;
            case '\f':
                output += "\\f";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default:
                if (byte < 0x20U)
                {
                    append_control_escape(output, byte);
                }
                else
                {
                    output.push_back(character);
                }
                break;
            }
        }
        output.push_back('"');
    }

    [[nodiscard]] auto serialize_value(Value const& value, bool reject_floats) -> SerializeResult;

    // Shortest decimal representation that round-trips exactly. Escalates
    // %g precision with snprintf/strtod until the formatted text parses back
    // to the exact same bit pattern, rather than relying on std::to_chars'
    // floating-point overload — that overload is part of C++17 but several
    // supported toolchains (e.g. NetBSD's libstdc++ build) only implement
    // to_chars for integers, making a floating-point call ambiguous at
    // compile time. Unlike std::to_string (fixed 6 fractional digits), this
    // cannot silently collapse a small magnitude value like 1e-7 to "0.0" —
    // a real bug in the previous implementation. Only used by the non-strict
    // (general JSON response) serialization path; see
    // serialize_canonical_strict for the signing/hashing path, which rejects
    // floats outright instead.
    // snprintf/strtod both consult LC_NUMERIC (#435): under a non-C numeric
    // locale %g emits e.g. "1,5", and the strtod round-trip check succeeds in
    // the same locale — producing output that is invalid JSON for every
    // conforming parser. Replace the active locale's decimal separator with
    // '.' so the serialized text is locale-independent. (std::to_chars for
    // doubles would avoid this entirely but is unavailable on several
    // supported toolchains, e.g. NetBSD's libstdc++ build.)
    [[nodiscard]] auto normalize_decimal_point(std::string text) -> std::string
    {
        auto const* locale_info = std::localeconv();
        if (locale_info == nullptr || locale_info->decimal_point == nullptr)
        {
            return text;
        }
        auto const decimal_point = std::string_view{locale_info->decimal_point};
        if (decimal_point.empty() || decimal_point == ".")
        {
            return text;
        }
        auto const position = text.find(decimal_point);
        if (position != std::string::npos)
        {
            text.replace(position, decimal_point.size(), ".");
        }
        return text;
    }

    [[nodiscard]] auto format_double(double value) -> std::string
    {
        auto buffer = std::array<char, 32U>{};
        for (auto precision = 1; precision <= 17; ++precision)
        {
            auto const written = std::snprintf(buffer.data(), buffer.size(), "%.*g", precision, value);
            if (written <= 0 || static_cast<std::size_t>(written) >= buffer.size())
            {
                continue;
            }
            char* end = nullptr;
            auto const round_tripped = std::strtod(buffer.data(), &end);
            if (end == buffer.data() + written && round_tripped == value)
            {
                return normalize_decimal_point(std::string{buffer.data(), static_cast<std::size_t>(written)});
            }
        }
        // 17 significant decimal digits always round-trips an IEEE-754 double;
        // this is an unreachable fallback if the loop above ever fails to find
        // a round-tripping precision by 17.
        auto const written = std::snprintf(buffer.data(), buffer.size(), "%.17g", value);
        return normalize_decimal_point(std::string{buffer.data(), static_cast<std::size_t>(written > 0 ? written : 0)});
    }

    // JSON arrays recurse through nested values; value tree depth is parser-bounded.
    // NOLINTNEXTLINE(misc-no-recursion)
    [[nodiscard]] auto serialize_array(Array const& array, bool reject_floats) -> SerializeResult
    {
        auto output = std::string{"["};
        auto first = true;
        for (auto const& item : array)
        {
            auto item_result = serialize_value(item, reject_floats);
            if (item_result.error != CanonicalJsonError::none)
            {
                return {{}, item_result.error};
            }

            if (!first)
            {
                output.push_back(',');
            }
            first = false;
            output += item_result.output;
        }
        output.push_back(']');
        return {std::move(output), CanonicalJsonError::none};
    }

    // JSON objects recurse through nested values; value tree depth is parser-bounded.
    // NOLINTNEXTLINE(misc-no-recursion)
    [[nodiscard]] auto serialize_object(Object const& object, bool reject_floats) -> SerializeResult
    {
        if (object_has_duplicate_keys(object))
        {
            return {{}, CanonicalJsonError::duplicate_object_key};
        }

        auto members = std::vector<SerializedMember>{};
        members.reserve(object.size());
        for (auto const& member : object)
        {
            if (member.value == nullptr || !string_is_valid_for_json(member.key))
            {
                return {{}, CanonicalJsonError::invalid_string};
            }
            auto value_result = serialize_value(*member.value, reject_floats);
            if (value_result.error != CanonicalJsonError::none)
            {
                return {{}, value_result.error};
            }
            members.push_back({member.key, std::move(value_result.output)});
        }

        std::sort(members.begin(), members.end(),
                  [](SerializedMember const& lhs, SerializedMember const& rhs) noexcept {
                      return lhs.key < rhs.key;
                  });

        auto output = std::string{"{"};
        auto first = true;
        for (auto const& member : members)
        {
            if (!first)
            {
                output.push_back(',');
            }
            first = false;
            append_escaped_string(output, member.key);
            output.push_back(':');
            output += member.value;
        }
        output.push_back('}');
        return {std::move(output), CanonicalJsonError::none};
    }

    // Canonical JSON values can be trees; recursion is bounded for parsed inputs.
    // NOLINTNEXTLINE(misc-no-recursion)
    [[nodiscard]] auto serialize_value(Value const& value, bool reject_floats) -> SerializeResult
    {
        auto const& storage = value.storage();
        if (std::holds_alternative<std::nullptr_t>(storage))
        {
            return {"null", CanonicalJsonError::none};
        }
        if (auto const* boolean = std::get_if<bool>(&storage); boolean != nullptr)
        {
            return {*boolean ? "true" : "false", CanonicalJsonError::none};
        }
        if (auto const* integer = std::get_if<std::int64_t>(&storage); integer != nullptr)
        {
            return {std::to_string(*integer), CanonicalJsonError::none};
        }
        if (auto const* number = std::get_if<double>(&storage); number != nullptr)
        {
            // Canonical JSON MUST NOT contain floats in signed/hashed data
            // (docs/matrix-v1.19-spec/appendices.md#canonical-json). The
            // strict signing/hashing path (serialize_canonical_strict, used by
            // event_signer.cpp and event_id.cpp) fails closed here instead of
            // producing a plausible-looking bad hash. The general-purpose path
            // (serialize_canonical) is also used for ordinary, never-signed
            // JSON responses that legitimately contain floats — e.g. the
            // m.tag `order` field — so it still serializes them, now with a
            // correct shortest-round-tripping representation rather than the
            // previous std::to_string-based one, which silently corrupted
            // small magnitudes (e.g. 1e-7) to "0.0".
            if (reject_floats)
            {
                return {{}, CanonicalJsonError::float_not_allowed};
            }
            return {format_double(*number), CanonicalJsonError::none};
        }
        if (auto const* string = std::get_if<std::string>(&storage); string != nullptr)
        {
            if (!string_is_valid_for_json(*string))
            {
                return {{}, CanonicalJsonError::invalid_string};
            }
            auto output = std::string{};
            append_escaped_string(output, *string);
            return {std::move(output), CanonicalJsonError::none};
        }
        if (auto const* array = std::get_if<Array>(&storage); array != nullptr)
        {
            return serialize_array(*array, reject_floats);
        }
        if (auto const* object = std::get_if<Object>(&storage); object != nullptr)
        {
            return serialize_object(*object, reject_floats);
        }

        return {{}, CanonicalJsonError::invalid_string};
    }

} // namespace

auto canonical_json_error_name(CanonicalJsonError error) noexcept -> char const*
{
    switch (error)
    {
    case CanonicalJsonError::none:
        return "none";
    case CanonicalJsonError::duplicate_object_key:
        return "duplicate_object_key";
    case CanonicalJsonError::invalid_string:
        return "invalid_string";
    case CanonicalJsonError::float_not_allowed:
        return "float_not_allowed";
    }

    return "invalid_string";
}

auto string_is_valid_for_json(std::string_view value) noexcept -> bool
{
    return utf8_is_valid(value);
}

auto object_has_duplicate_keys(Object const& object) -> bool
{
    // Previously an O(n^2) nested begin/end scan, called at the top of
    // serialize_object on every serialize_canonical / serialize_canonical_strict
    // — an unauthenticated CPU-exhaustion DoS on a wide enough object (see
    // parser.cpp's matching duplicate-key rewrite for the full analysis).
    // `object` outlives this function call and is never mutated here, so
    // string_view keys aliasing its members are safe for the loop's duration.
    auto seen_keys = std::unordered_set<std::string_view>{};
    seen_keys.reserve(object.size());
    for (auto const& member : object)
    {
        if (!seen_keys.insert(member.key).second)
        {
            return true;
        }
    }

    return false;
}

auto serialize_canonical(Value const& value) -> SerializeResult
{
    return serialize_value(value, /*reject_floats=*/false);
}

auto serialize_canonical_strict(Value const& value) -> SerializeResult
{
    return serialize_value(value, /*reject_floats=*/true);
}

} // namespace merovingian::canonicaljson
