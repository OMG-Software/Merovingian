// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/FormContentType.hpp"

#include <cstddef>
#include <string_view>

namespace merovingian::oauth
{
namespace
{

    constexpr auto form_type = std::string_view{"application/x-www-form-urlencoded"};

    [[nodiscard]] constexpr auto lower(char value) noexcept -> char
    {
        return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value;
    }

    // `text` equals the lower-case `expected` in any ASCII case.
    [[nodiscard]] auto equals_ignoring_case(std::string_view text, std::string_view expected) noexcept -> bool
    {
        if (text.size() != expected.size())
        {
            return false;
        }
        for (auto index = std::size_t{0U}; index < expected.size(); ++index)
        {
            if (lower(text[index]) != expected[index])
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto trim_spaces(std::string_view text) noexcept -> std::string_view
    {
        while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        {
            text.remove_prefix(1U);
        }
        while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        {
            text.remove_suffix(1U);
        }
        return text;
    }

} // namespace

auto page_form_content_type_is_accepted(std::string_view content_type) noexcept -> bool
{
    return equals_ignoring_case(content_type, form_type);
}

auto api_form_content_type_is_accepted(std::string_view content_type) noexcept -> bool
{
    auto const separator = content_type.find(';');
    if (!equals_ignoring_case(trim_spaces(content_type.substr(0U, separator)), form_type))
    {
        return false;
    }
    if (separator == std::string_view::npos)
    {
        return true;
    }
    auto const parameter = trim_spaces(content_type.substr(separator + 1U));
    return equals_ignoring_case(parameter, "charset=utf-8") || equals_ignoring_case(parameter, "charset=\"utf-8\"");
}

} // namespace merovingian::oauth
