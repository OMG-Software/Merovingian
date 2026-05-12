// SPDX-License-Identifier: GPL-3.0-or-later

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <merovingian/canonicaljson/parser.hpp>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <yyjson.h>

namespace merovingian::canonicaljson
{
namespace
{

    constexpr auto max_depth = std::size_t{64U};

    struct YyjsonDocumentDeleter final
    {
        auto operator()(yyjson_doc* document) const noexcept -> void
        {
            yyjson_doc_free(document);
        }
    };

    using YyjsonDocument = std::unique_ptr<yyjson_doc, YyjsonDocumentDeleter>;

    struct ConvertResult final
    {
        Value value{};
        ParseError error{ParseError::none};
    };

    [[nodiscard]] auto map_yyjson_error(yyjson_read_err const& error) noexcept -> ParseError
    {
        switch (error.code)
        {
        case YYJSON_READ_SUCCESS:
            return ParseError::none;
        case YYJSON_READ_ERROR_EMPTY_CONTENT:
        case YYJSON_READ_ERROR_UNEXPECTED_END:
        case YYJSON_READ_ERROR_MORE:
            return ParseError::unexpected_end;
        case YYJSON_READ_ERROR_UNEXPECTED_CONTENT:
            return ParseError::trailing_data;
        case YYJSON_READ_ERROR_INVALID_NUMBER:
            return ParseError::invalid_number;
        case YYJSON_READ_ERROR_INVALID_STRING:
            return ParseError::invalid_string;
        case YYJSON_READ_ERROR_LITERAL:
            return ParseError::invalid_literal;
        case YYJSON_READ_ERROR_UNEXPECTED_CHARACTER:
        case YYJSON_READ_ERROR_JSON_STRUCTURE:
        case YYJSON_READ_ERROR_INVALID_COMMENT:
        case YYJSON_READ_ERROR_INVALID_PARAMETER:
        case YYJSON_READ_ERROR_MEMORY_ALLOCATION:
        case YYJSON_READ_ERROR_FILE_OPEN:
        case YYJSON_READ_ERROR_FILE_READ:
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
    [[nodiscard]] auto convert_yyjson_value(yyjson_val* value, std::size_t depth) -> ConvertResult
    {
        if (depth > max_depth)
        {
            return {{}, ParseError::nesting_too_deep};
        }
        if (value == nullptr)
        {
            return {{}, ParseError::unexpected_token};
        }

        if (yyjson_is_null(value))
        {
            return {Value{nullptr}, ParseError::none};
        }
        if (yyjson_is_bool(value))
        {
            return {Value{yyjson_get_bool(value)}, ParseError::none};
        }
        if (yyjson_is_raw(value))
        {
            auto const* raw = yyjson_get_raw(value);
            auto const length = yyjson_get_len(value);
            return raw_number_as_int64({raw, length});
        }
        if (yyjson_is_str(value))
        {
            auto const* data = yyjson_get_str(value);
            auto const length = yyjson_get_len(value);
            if (data == nullptr)
            {
                return {{}, ParseError::invalid_string};
            }
            return {Value{std::string{data, length}}, ParseError::none};
        }
        if (yyjson_is_arr(value))
        {
            auto array = Array{};
            array.reserve(yyjson_arr_size(value));

            auto iterator = yyjson_arr_iter_with(value);
            while (auto* item = yyjson_arr_iter_next(&iterator))
            {
                auto converted = convert_yyjson_value(item, depth + 1U);
                if (converted.error != ParseError::none)
                {
                    return converted;
                }
                array.push_back(std::move(converted.value));
            }
            return {Value{std::move(array)}, ParseError::none};
        }
        if (yyjson_is_obj(value))
        {
            auto object = Object{};
            object.reserve(yyjson_obj_size(value));

            auto iterator = yyjson_obj_iter_with(value);
            while (auto* key = yyjson_obj_iter_next(&iterator))
            {
                auto const* key_data = yyjson_get_str(key);
                auto const key_length = yyjson_get_len(key);
                if (key_data == nullptr)
                {
                    return {{}, ParseError::invalid_string};
                }
                auto key_value = std::string{key_data, key_length};
                auto const duplicate = std::ranges::any_of(object, [&key_value](ObjectMember const& member) {
                    return member.key == key_value;
                });
                if (duplicate)
                {
                    return {{}, ParseError::duplicate_object_key};
                }

                auto* member_value = yyjson_obj_iter_get_val(key);
                auto converted = convert_yyjson_value(member_value, depth + 1U);
                if (converted.error != ParseError::none)
                {
                    return converted;
                }
                object.push_back(make_member(std::move(key_value), std::move(converted.value)));
            }
            return {Value{std::move(object)}, ParseError::none};
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
    auto error = yyjson_read_err{};
    auto* raw_document =
        yyjson_read_opts(owned_input.data(), owned_input.size(), YYJSON_READ_NUMBER_AS_RAW, nullptr, &error);
    auto document = YyjsonDocument{raw_document};
    if (document == nullptr)
    {
        return {{}, map_yyjson_error(error)};
    }

    auto converted = convert_yyjson_value(yyjson_doc_get_root(document.get()), 0U);
    return {std::move(converted.value), converted.error};
}

} // namespace merovingian::canonicaljson
