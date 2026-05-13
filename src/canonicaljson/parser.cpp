// SPDX-License-Identifier: GPL-3.0-or-later

#include "yyjson_adapter.h"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "merovingian/canonicaljson/parser.hpp"

namespace merovingian::canonicaljson
{
namespace
{

    constexpr auto max_depth = std::size_t{64U};

    struct YyjsonDocumentDeleter final
    {
        auto operator()(MerovingianYyjsonDoc* document) const noexcept -> void
        {
            merovingian_yyjson_doc_free(document);
        }
    };

    using YyjsonDocument = std::unique_ptr<MerovingianYyjsonDoc, YyjsonDocumentDeleter>;

    struct ConvertResult final
    {
        Value value{};
        ParseError error{ParseError::none};
    };

    [[nodiscard]] auto map_yyjson_error(MerovingianYyjsonReadCode error) noexcept -> ParseError
    {
        switch (error)
        {
        case MEROVINGIAN_YYJSON_READ_SUCCESS:
            return ParseError::none;
        case MEROVINGIAN_YYJSON_READ_ERROR_EMPTY_CONTENT:
        case MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_END:
        case MEROVINGIAN_YYJSON_READ_ERROR_MORE:
            return ParseError::unexpected_end;
        case MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_CONTENT:
            return ParseError::trailing_data;
        case MEROVINGIAN_YYJSON_READ_ERROR_INVALID_NUMBER:
            return ParseError::invalid_number;
        case MEROVINGIAN_YYJSON_READ_ERROR_INVALID_STRING:
            return ParseError::invalid_string;
        case MEROVINGIAN_YYJSON_READ_ERROR_LITERAL:
            return ParseError::invalid_literal;
        case MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_CHARACTER:
        case MEROVINGIAN_YYJSON_READ_ERROR_JSON_STRUCTURE:
        case MEROVINGIAN_YYJSON_READ_ERROR_INVALID_COMMENT:
        case MEROVINGIAN_YYJSON_READ_ERROR_INVALID_PARAMETER:
        case MEROVINGIAN_YYJSON_READ_ERROR_MEMORY_ALLOCATION:
        case MEROVINGIAN_YYJSON_READ_ERROR_FILE_OPEN:
        case MEROVINGIAN_YYJSON_READ_ERROR_FILE_READ:
        default:
            return ParseError::unexpected_token;
        }
    }

    [[nodiscard]] auto input_is_blank(std::string_view input) noexcept -> bool
    {
        return std::ranges::all_of(input, [](char character) {
            return character == ' ' || character == '\n' || character == '\r' || character == '\t';
        });
    }

    [[nodiscard]] auto raw_number_as_int64(std::string_view token) noexcept -> ConvertResult
    {
        if (token.find_first_of(".eE") != std::string_view::npos)
        {
            return {{}, ParseError::invalid_number};
        }

        auto parsed = std::int64_t{0};
        auto const [ptr, error] = std::from_chars(token.data(), token.data() + token.size(), parsed);
        if (error == std::errc::result_out_of_range)
        {
            return {{}, ParseError::integer_out_of_range};
        }
        if (error != std::errc{} || ptr != token.data() + token.size())
        {
            return {{}, ParseError::invalid_number};
        }
        return {Value{parsed}, ParseError::none};
    }

    // yyjson owns parsed values through the document; conversion copies into
    // Merovingian's canonical JSON tree before the document is released.
    // NOLINTNEXTLINE(misc-no-recursion)
    [[nodiscard]] auto convert_yyjson_value(MerovingianYyjsonValue* value, std::size_t depth) -> ConvertResult
    {
        if (depth > max_depth)
        {
            return {{}, ParseError::nesting_too_deep};
        }
        if (value == nullptr)
        {
            return {{}, ParseError::unexpected_token};
        }

        switch (merovingian_yyjson_value_type(value))
        {
        case MEROVINGIAN_YYJSON_TYPE_NULL:
            return {Value{nullptr}, ParseError::none};
        case MEROVINGIAN_YYJSON_TYPE_BOOL:
            return {Value{merovingian_yyjson_bool_value(value) != 0}, ParseError::none};
        case MEROVINGIAN_YYJSON_TYPE_RAW: {
            auto length = std::size_t{0U};
            auto const* raw = merovingian_yyjson_raw_data(value, &length);
            return raw == nullptr ? ConvertResult{{}, ParseError::invalid_number} : raw_number_as_int64({raw, length});
        }
        case MEROVINGIAN_YYJSON_TYPE_STRING: {
            auto length = std::size_t{0U};
            auto const* data = merovingian_yyjson_string_data(value, &length);
            if (data == nullptr)
            {
                return {{}, ParseError::invalid_string};
            }
            return {Value{std::string{data, length}}, ParseError::none};
        }
        case MEROVINGIAN_YYJSON_TYPE_ARRAY: {
            auto array = Array{};
            array.reserve(merovingian_yyjson_array_size(value));

            struct ArrayContext final
            {
                Array* array;
                std::size_t depth;
                ParseError error{ParseError::none};
            };

            auto context = ArrayContext{&array, depth};
            auto const completed = merovingian_yyjson_array_foreach(
                value,
                [](MerovingianYyjsonValue* item, void* user_data) -> int {
                    auto& callback_context = *static_cast<ArrayContext*>(user_data);
                    auto converted = convert_yyjson_value(item, callback_context.depth + 1U);
                    if (converted.error != ParseError::none)
                    {
                        callback_context.error = converted.error;
                        return 0;
                    }
                    callback_context.array->push_back(std::move(converted.value));
                    return 1;
                },
                &context);
            if (completed == 0)
            {
                return {{}, context.error};
            }
            return {Value{std::move(array)}, ParseError::none};
        }
        case MEROVINGIAN_YYJSON_TYPE_OBJECT: {
            auto object = Object{};
            object.reserve(merovingian_yyjson_object_size(value));

            struct ObjectContext final
            {
                Object* object;
                std::size_t depth;
                ParseError error{ParseError::none};
            };

            auto context = ObjectContext{&object, depth};
            auto const completed = merovingian_yyjson_object_foreach(
                value,
                [](char const* key_data, std::size_t key_length, MerovingianYyjsonValue* member_value,
                   void* user_data) -> int {
                    auto& callback_context = *static_cast<ObjectContext*>(user_data);
                    if (key_data == nullptr)
                    {
                        callback_context.error = ParseError::invalid_string;
                        return 0;
                    }
                    auto key_value = std::string{key_data, key_length};
                    auto const duplicate =
                        std::ranges::any_of(*callback_context.object, [&key_value](ObjectMember const& member) {
                            return member.key == key_value;
                        });
                    if (duplicate)
                    {
                        callback_context.error = ParseError::duplicate_object_key;
                        return 0;
                    }

                    auto converted = convert_yyjson_value(member_value, callback_context.depth + 1U);
                    if (converted.error != ParseError::none)
                    {
                        callback_context.error = converted.error;
                        return 0;
                    }
                    callback_context.object->push_back(make_member(std::move(key_value), std::move(converted.value)));
                    return 1;
                },
                &context);
            if (completed == 0)
            {
                return {{}, context.error};
            }
            return {Value{std::move(object)}, ParseError::none};
        }
        case MEROVINGIAN_YYJSON_TYPE_UNKNOWN:
        default:
            break;
        }

        return {{}, ParseError::unexpected_token};
    }

} // namespace

auto parse_error_name(ParseError error) noexcept -> char const*
{
    switch (error)
    {
    case ParseError::none:
        return "none";
    case ParseError::trailing_data:
        return "trailing_data";
    case ParseError::unexpected_end:
        return "unexpected_end";
    case ParseError::unexpected_token:
        return "unexpected_token";
    case ParseError::invalid_literal:
        return "invalid_literal";
    case ParseError::invalid_string:
        return "invalid_string";
    case ParseError::invalid_escape:
        return "invalid_escape";
    case ParseError::invalid_unicode_escape:
        return "invalid_unicode_escape";
    case ParseError::invalid_number:
        return "invalid_number";
    case ParseError::integer_out_of_range:
        return "integer_out_of_range";
    case ParseError::duplicate_object_key:
        return "duplicate_object_key";
    case ParseError::nesting_too_deep:
        return "nesting_too_deep";
    }

    return "unexpected_token";
}

auto utf8_is_valid(std::string_view value) noexcept -> bool
{
    auto index = std::size_t{0U};
    while (index < value.size())
    {
        auto const first = static_cast<unsigned char>(value[index]);
        if (first <= 0x7FU)
        {
            ++index;
            continue;
        }

        auto length = std::size_t{0U};
        auto min_codepoint = std::uint32_t{0U};
        auto codepoint = std::uint32_t{0U};
        if ((first & 0xE0U) == 0xC0U)
        {
            length = 2U;
            min_codepoint = 0x80U;
            codepoint = first & 0x1FU;
        }
        else if ((first & 0xF0U) == 0xE0U)
        {
            length = 3U;
            min_codepoint = 0x800U;
            codepoint = first & 0x0FU;
        }
        else if ((first & 0xF8U) == 0xF0U)
        {
            length = 4U;
            min_codepoint = 0x10000U;
            codepoint = first & 0x07U;
        }
        else
        {
            return false;
        }

        if (index + length > value.size())
        {
            return false;
        }
        for (auto offset = std::size_t{1U}; offset < length; ++offset)
        {
            auto const next = static_cast<unsigned char>(value[index + offset]);
            if ((next & 0xC0U) != 0x80U)
            {
                return false;
            }
            codepoint = (codepoint << 6U) | (next & 0x3FU);
        }
        if (codepoint < min_codepoint || codepoint > 0x10FFFFU || (codepoint >= 0xD800U && codepoint <= 0xDFFFU))
        {
            return false;
        }
        index += length;
    }

    return true;
}

auto parse_lossless(std::string_view input) -> ParseResult
{
    if (input_is_blank(input))
    {
        return {{}, ParseError::unexpected_end};
    }

    if (!utf8_is_valid(input))
    {
        return {{}, ParseError::invalid_string};
    }

    auto owned_input = std::string{input};
    auto error = MEROVINGIAN_YYJSON_READ_SUCCESS;
    auto* raw_document = merovingian_yyjson_read_raw_numbers(owned_input.data(), owned_input.size(), &error);
    auto document = YyjsonDocument{raw_document};
    if (document == nullptr)
    {
        return {{}, map_yyjson_error(error)};
    }

    auto converted = convert_yyjson_value(merovingian_yyjson_doc_root(document.get()), 0U);
    return {std::move(converted.value), converted.error};
}

} // namespace merovingian::canonicaljson
