// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/serializer.hpp"

#include "merovingian/canonicaljson/parser.hpp"

#include <algorithm>
#include <array>
#include <string>
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

    [[nodiscard]] auto serialize_value(Value const& value) -> SerializeResult;

    // JSON arrays recurse through nested values; value tree depth is parser-bounded.
    // NOLINTNEXTLINE(misc-no-recursion)
    [[nodiscard]] auto serialize_array(Array const& array) -> SerializeResult
    {
        auto output = std::string{"["};
        auto first = true;
        for (auto const& item : array)
        {
            auto item_result = serialize_value(item);
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
    [[nodiscard]] auto serialize_object(Object const& object) -> SerializeResult
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
            auto value_result = serialize_value(*member.value);
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
    [[nodiscard]] auto serialize_value(Value const& value) -> SerializeResult
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
            return serialize_array(*array);
        }
        if (auto const* object = std::get_if<Object>(&storage); object != nullptr)
        {
            return serialize_object(*object);
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
    }

    return "invalid_string";
}

auto string_is_valid_for_json(std::string_view value) noexcept -> bool
{
    return utf8_is_valid(value);
}

auto object_has_duplicate_keys(Object const& object) noexcept -> bool
{
    for (auto left = object.begin(); left != object.end(); ++left)
    {
        for (auto right = left + 1; right != object.end(); ++right)
        {
            if (left->key == right->key)
            {
                return true;
            }
        }
    }

    return false;
}

auto serialize_canonical(Value const& value) -> SerializeResult
{
    return serialize_value(value);
}

} // namespace merovingian::canonicaljson
