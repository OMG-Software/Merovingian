// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/FormFields.hpp"

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/core/Utf8.hpp"

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>

namespace merovingian::core
{

namespace
{

    [[nodiscard]] auto hex_value(char character) noexcept -> std::optional<std::uint8_t>
    {
        if (character >= '0' && character <= '9')
        {
            return static_cast<std::uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f')
        {
            return static_cast<std::uint8_t>(character - 'a' + 10);
        }
        if (character >= 'A' && character <= 'F')
        {
            return static_cast<std::uint8_t>(character - 'A' + 10);
        }
        return std::nullopt;
    }

    [[nodiscard]] auto malformed() -> Error
    {
        return Error{ErrorCode::parse_failure, "form body is not well-formed application/x-www-form-urlencoded"};
    }

    [[nodiscard]] auto over_limit(std::string_view what) -> Error
    {
        return Error{ErrorCode::invalid_argument, std::string{"form body exceeds the limit on "} + std::string{what}};
    }

    auto wipe_string(std::string& text) noexcept -> void
    {
        secure_zero(std::as_writable_bytes(std::span{text.data(), text.size()}));
    }

    // Decodes one name or value into `out`, which the caller reserved to `encoded.size()` so no reallocation leaves an
    // unwiped copy. False for a malformed escape or a raw byte a conforming encoder escapes.
    [[nodiscard]] auto decode_component(std::string_view encoded, std::string& out) -> bool
    {
        for (auto index = std::size_t{0U}; index < encoded.size(); ++index)
        {
            auto const character = encoded[index];
            auto const byte = static_cast<unsigned char>(character);
            if (character == '+')
            {
                out.push_back(' ');
                continue;
            }
            if (character == '%')
            {
                if (encoded.size() - index < 3U)
                {
                    return false;
                }
                auto const high = hex_value(encoded[index + 1U]);
                auto const low = hex_value(encoded[index + 2U]);
                if (!high.has_value() || !low.has_value())
                {
                    return false;
                }
                out.push_back(static_cast<char>((*high << 4U) | *low));
                index += 2U;
                continue;
            }
            if (byte < 0x21U || byte > 0x7EU)
            {
                return false;
            }
            out.push_back(character);
        }
        return true;
    }

    [[nodiscard]] auto decoded_text_is_acceptable(std::string_view decoded) noexcept -> bool
    {
        return decoded.find('\0') == std::string_view::npos && utf8_is_valid(decoded);
    }

    // A bare name (a query field with no `=`) is not kept, but it must still be well formed: the same escapes, bytes,
    // UTF-8 and length as a kept name.
    [[nodiscard]] auto bare_name_is_acceptable(std::string_view encoded) -> bool
    {
        auto decoded = std::string{};
        decoded.reserve(encoded.size());
        auto const acceptable = decode_component(encoded, decoded) && decoded.size() <= FormFields::max_name_bytes &&
                                decoded_text_is_acceptable(decoded);
        wipe_string(decoded);
        return acceptable;
    }

} // namespace

FormFields::~FormFields() noexcept
{
    wipe();
}

auto FormFields::operator=(FormFields&& other) noexcept -> FormFields&
{
    if (this != &other)
    {
        wipe();
        m_fields = std::move(other.m_fields);
        other.m_fields.clear();
    }
    return *this;
}

auto FormFields::wipe() noexcept -> void
{
    for (auto& [name, value] : m_fields)
    {
        wipe_string(name);
        wipe_string(value);
    }
    m_fields.clear();
}

auto FormFields::parse(std::string_view body) -> std::variant<FormFields, Error>
{
    return read(body, Omission::refused);
}

auto FormFields::parse_query(std::string_view query) -> std::variant<FormFields, Error>
{
    return read(query, Omission::not_sent);
}

auto FormFields::read(std::string_view body, Omission omission) -> std::variant<FormFields, Error>
{
    if (body.size() > max_body_bytes)
    {
        return over_limit("body size");
    }
    auto result = FormFields{};
    if (body.empty())
    {
        return result;
    }
    auto const field_count = static_cast<std::size_t>(std::ranges::count(body, '&')) + 1U;
    if (field_count > max_fields)
    {
        return over_limit("field count");
    }
    // Reserved once: the vector never reallocates, so no field is moved out of storage that is then freed unwiped.
    result.m_fields.reserve(field_count);

    auto remaining = body;
    while (true)
    {
        auto const separator = remaining.find('&');
        auto const field = remaining.substr(0U, separator);
        auto const equals = field.find('=');
        if (omission == Omission::not_sent && (field.empty() || equals == std::string_view::npos))
        {
            if (!field.empty() && !bare_name_is_acceptable(field))
            {
                return malformed();
            }
            if (separator == std::string_view::npos)
            {
                break;
            }
            remaining.remove_prefix(separator + 1U);
            continue;
        }
        if (field.empty() || equals == std::string_view::npos || equals == 0U)
        {
            return malformed();
        }
        auto const encoded_name = field.substr(0U, equals);
        auto const encoded_value = field.substr(equals + 1U);

        auto& entry = result.m_fields.emplace_back();
        entry.first.reserve(encoded_name.size());
        entry.second.reserve(encoded_value.size());
        if (!decode_component(encoded_name, entry.first) || !decode_component(encoded_value, entry.second))
        {
            return malformed();
        }
        if (entry.first.size() > max_name_bytes)
        {
            return over_limit("name length");
        }
        if (entry.second.size() > max_value_bytes)
        {
            return over_limit("value length");
        }
        if (entry.first.empty() || !decoded_text_is_acceptable(entry.first) ||
            !decoded_text_is_acceptable(entry.second))
        {
            return malformed();
        }
        auto const& name = entry.first;
        auto const earlier = std::ranges::count_if(result.m_fields, [&name](auto const& field_entry) {
            return field_entry.first == name;
        });
        if (earlier > 1)
        {
            return malformed();
        }

        if (separator == std::string_view::npos)
        {
            break;
        }
        remaining.remove_prefix(separator + 1U);
    }
    return result;
}

auto FormFields::find(std::string_view name) const noexcept -> std::optional<std::string_view>
{
    for (auto const& [field_name, value] : m_fields)
    {
        if (field_name == name)
        {
            return std::string_view{value};
        }
    }
    return std::nullopt;
}

auto FormFields::size() const noexcept -> std::size_t
{
    return m_fields.size();
}

auto FormFields::empty() const noexcept -> bool
{
    return m_fields.empty();
}

auto FormFields::fields() const noexcept -> std::vector<std::pair<std::string, std::string>> const&
{
    return m_fields;
}

} // namespace merovingian::core
