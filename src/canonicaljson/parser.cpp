// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/serializer.hpp>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace merovingian::canonicaljson
{
namespace
{

constexpr auto max_depth = std::size_t{64U};

class Parser final
{
public:
    explicit Parser(std::string_view input) noexcept
        : m_input{input}
    {
    }

    [[nodiscard]] auto parse() -> ParseResult
    {
        skip_whitespace();
        auto result = parse_value(0U);
        if (result.error != ParseError::none)
        {
            return result;
        }
        skip_whitespace();
        if (m_offset != m_input.size())
        {
            return {{}, ParseError::trailing_data};
        }

        return result;
    }

private:
    [[nodiscard]] auto at_end() const noexcept -> bool
    {
        return m_offset >= m_input.size();
    }

    [[nodiscard]] auto peek() const noexcept -> char
    {
        return at_end() ? '\0' : m_input[m_offset];
    }

    auto skip_whitespace() noexcept -> void
    {
        while (!at_end() && (peek() == ' ' || peek() == '\n' || peek() == '\r' || peek() == '\t'))
        {
            ++m_offset;
        }
    }

    [[nodiscard]] auto consume(char expected) noexcept -> bool
    {
        if (peek() != expected)
        {
            return false;
        }
        ++m_offset;
        return true;
    }

    [[nodiscard]] auto consume_literal(std::string_view literal) noexcept -> bool
    {
        if (m_input.substr(m_offset, literal.size()) != literal)
        {
            return false;
        }
        m_offset += literal.size();
        return true;
    }

    [[nodiscard]] auto parse_value(std::size_t depth) -> ParseResult
    {
        if (depth > max_depth)
        {
            return {{}, ParseError::nesting_too_deep};
        }

        skip_whitespace();
        if (at_end())
        {
            return {{}, ParseError::unexpected_end};
        }

        switch (peek())
        {
        case 'n':
            return parse_null();
        case 't':
            return parse_true();
        case 'f':
            return parse_false();
        case '"':
            return parse_string_value();
        case '[':
            return parse_array(depth);
        case '{':
            return parse_object(depth);
        default:
            if (peek() == '-' || (peek() >= '0' && peek() <= '9'))
            {
                return parse_number();
            }
            return {{}, ParseError::unexpected_token};
        }
    }

    [[nodiscard]] auto parse_null() -> ParseResult
    {
        if (!consume_literal("null"))
        {
            return {{}, ParseError::invalid_literal};
        }
        return {Value{nullptr}, ParseError::none};
    }

    [[nodiscard]] auto parse_true() -> ParseResult
    {
        if (!consume_literal("true"))
        {
            return {{}, ParseError::invalid_literal};
        }
        return {Value{true}, ParseError::none};
    }

    [[nodiscard]] auto parse_false() -> ParseResult
    {
        if (!consume_literal("false"))
        {
            return {{}, ParseError::invalid_literal};
        }
        return {Value{false}, ParseError::none};
    }

    [[nodiscard]] auto parse_string_value() -> ParseResult
    {
        auto string_result = parse_string();
        if (string_result.error != ParseError::none)
        {
            return {{}, string_result.error};
        }
        return {Value{std::move(string_result.value)}, ParseError::none};
    }

    struct StringResult final
    {
        std::string value{};
        ParseError error{ParseError::none};
    };

    [[nodiscard]] auto parse_hex4(char32_t& output) -> bool
    {
        if (m_offset + 4U > m_input.size())
        {
            return false;
        }

        auto value = char32_t{0U};
        for (auto index = std::size_t{0U}; index < 4U; ++index)
        {
            auto const character = m_input[m_offset + index];
            value <<= 4U;
            if (character >= '0' && character <= '9')
            {
                value += static_cast<char32_t>(character - '0');
            }
            else if (character >= 'a' && character <= 'f')
            {
                value += static_cast<char32_t>(character - 'a' + 10);
            }
            else if (character >= 'A' && character <= 'F')
            {
                value += static_cast<char32_t>(character - 'A' + 10);
            }
            else
            {
                return false;
            }
        }
        m_offset += 4U;
        output = value;
        return true;
    }

    auto append_utf8(std::string& output, char32_t codepoint) -> bool
    {
        if (codepoint > 0x10FFFFU || (codepoint >= 0xD800U && codepoint <= 0xDFFFU))
        {
            return false;
        }

        if (codepoint <= 0x7FU)
        {
            output.push_back(static_cast<char>(codepoint));
        }
        else if (codepoint <= 0x7FFU)
        {
            output.push_back(static_cast<char>(0xC0U | (codepoint >> 6U)));
            output.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        }
        else if (codepoint <= 0xFFFFU)
        {
            output.push_back(static_cast<char>(0xE0U | (codepoint >> 12U)));
            output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
            output.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        }
        else
        {
            output.push_back(static_cast<char>(0xF0U | (codepoint >> 18U)));
            output.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3FU)));
            output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
            output.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        }

        return true;
    }

    [[nodiscard]] auto parse_string() -> StringResult
    {
        if (!consume('"'))
        {
            return {{}, ParseError::invalid_string};
        }

        auto output = std::string{};
        while (!at_end())
        {
            auto const character = m_input[m_offset++];
            if (character == '"')
            {
                if (!utf8_is_valid(output))
                {
                    return {{}, ParseError::invalid_string};
                }
                return {std::move(output), ParseError::none};
            }

            auto const byte = static_cast<unsigned char>(character);
            if (byte < 0x20U)
            {
                return {{}, ParseError::invalid_string};
            }

            if (character != '\\')
            {
                output.push_back(character);
                continue;
            }

            if (at_end())
            {
                return {{}, ParseError::unexpected_end};
            }

            auto const escape = m_input[m_offset++];
            switch (escape)
            {
            case '"':
                output.push_back('"');
                break;
            case '\\':
                output.push_back('\\');
                break;
            case '/':
                output.push_back('/');
                break;
            case 'b':
                output.push_back('\b');
                break;
            case 'f':
                output.push_back('\f');
                break;
            case 'n':
                output.push_back('\n');
                break;
            case 'r':
                output.push_back('\r');
                break;
            case 't':
                output.push_back('\t');
                break;
            case 'u': {
                auto high = char32_t{0U};
                if (!parse_hex4(high))
                {
                    return {{}, ParseError::invalid_unicode_escape};
                }
                if (high >= 0xD800U && high <= 0xDBFFU)
                {
                    if (!consume('\\') || !consume('u'))
                    {
                        return {{}, ParseError::invalid_unicode_escape};
                    }
                    auto low = char32_t{0U};
                    if (!parse_hex4(low) || low < 0xDC00U || low > 0xDFFFU)
                    {
                        return {{}, ParseError::invalid_unicode_escape};
                    }
                    auto const codepoint = 0x10000U + (((high - 0xD800U) << 10U) | (low - 0xDC00U));
                    if (!append_utf8(output, codepoint))
                    {
                        return {{}, ParseError::invalid_unicode_escape};
                    }
                }
                else if (!append_utf8(output, high))
                {
                    return {{}, ParseError::invalid_unicode_escape};
                }
                break;
            }
            default:
                return {{}, ParseError::invalid_escape};
            }
        }

        return {{}, ParseError::unexpected_end};
    }

    [[nodiscard]] auto parse_number() -> ParseResult
    {
        auto const begin = m_offset;
        if (peek() == '-')
        {
            ++m_offset;
        }
        if (at_end())
        {
            return {{}, ParseError::invalid_number};
        }
        if (peek() == '0')
        {
            ++m_offset;
            if (!at_end() && peek() >= '0' && peek() <= '9')
            {
                return {{}, ParseError::invalid_number};
            }
        }
        else if (peek() >= '1' && peek() <= '9')
        {
            while (!at_end() && peek() >= '0' && peek() <= '9')
            {
                ++m_offset;
            }
        }
        else
        {
            return {{}, ParseError::invalid_number};
        }

        if (!at_end() && (peek() == '.' || peek() == 'e' || peek() == 'E'))
        {
            return {{}, ParseError::invalid_number};
        }

        auto parsed = std::int64_t{0};
        auto const token = m_input.substr(begin, m_offset - begin);
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

    [[nodiscard]] auto parse_array(std::size_t depth) -> ParseResult
    {
        if (!consume('['))
        {
            return {{}, ParseError::unexpected_token};
        }
        skip_whitespace();
        auto array = Array{};
        if (consume(']'))
        {
            return {Value{std::move(array)}, ParseError::none};
        }

        while (true)
        {
            auto item = parse_value(depth + 1U);
            if (item.error != ParseError::none)
            {
                return item;
            }
            array.push_back(std::move(item.value));
            skip_whitespace();
            if (consume(']'))
            {
                return {Value{std::move(array)}, ParseError::none};
            }
            if (!consume(','))
            {
                return {{}, ParseError::unexpected_token};
            }
        }
    }

    [[nodiscard]] auto parse_object(std::size_t depth) -> ParseResult
    {
        if (!consume('{'))
        {
            return {{}, ParseError::unexpected_token};
        }
        skip_whitespace();
        auto object = Object{};
        if (consume('}'))
        {
            return {Value{std::move(object)}, ParseError::none};
        }

        while (true)
        {
            skip_whitespace();
            auto key = parse_string();
            if (key.error != ParseError::none)
            {
                return {{}, key.error};
            }
            for (auto const& existing : object)
            {
                if (existing.key == key.value)
                {
                    return {{}, ParseError::duplicate_object_key};
                }
            }
            skip_whitespace();
            if (!consume(':'))
            {
                return {{}, ParseError::unexpected_token};
            }
            auto value = parse_value(depth + 1U);
            if (value.error != ParseError::none)
            {
                return value;
            }
            object.push_back(make_member(std::move(key.value), std::move(value.value)));
            skip_whitespace();
            if (consume('}'))
            {
                return {Value{std::move(object)}, ParseError::none};
            }
            if (!consume(','))
            {
                return {{}, ParseError::unexpected_token};
            }
        }
    }

    std::string_view m_input{};
    std::size_t m_offset{0U};
};

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
    auto parser = Parser{input};
    return parser.parse();
}

} // namespace merovingian::canonicaljson
