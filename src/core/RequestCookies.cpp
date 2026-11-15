// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/RequestCookies.hpp"

#include "merovingian/core/CookieOctets.hpp"
#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/core/HttpToken.hpp"
#include "merovingian/core/SecretBuffer.hpp"

#include <algorithm>
#include <span>

namespace merovingian::core
{

namespace
{

    [[nodiscard]] auto is_space_or_tab(char character) noexcept -> bool
    {
        return character == ' ' || character == '\t';
    }

    [[nodiscard]] auto trimmed(std::string_view text) noexcept -> std::string_view
    {
        while (!text.empty() && is_space_or_tab(text.front()))
        {
            text.remove_prefix(1U);
        }
        while (!text.empty() && is_space_or_tab(text.back()))
        {
            text.remove_suffix(1U);
        }
        return text;
    }

    [[nodiscard]] auto has_control_character(std::string_view text) noexcept -> bool
    {
        return std::ranges::any_of(text, [](char character) {
            auto const byte = static_cast<unsigned char>(character);
            return (byte < 0x20U && character != '\t') || byte == 0x7FU;
        });
    }

    auto wipe_string(std::string& text) noexcept -> void
    {
        secure_zero(std::as_writable_bytes(std::span{text.data(), text.size()}));
    }

} // namespace

RequestCookies::~RequestCookies() noexcept
{
    wipe();
}

auto RequestCookies::operator=(RequestCookies&& other) noexcept -> RequestCookies&
{
    if (this != &other)
    {
        wipe();
        m_entries = std::move(other.m_entries);
        other.m_entries.clear();
    }
    return *this;
}

auto RequestCookies::wipe() noexcept -> void
{
    for (auto& entry : m_entries)
    {
        wipe_string(entry.name);
        wipe_string(entry.value);
    }
    m_entries.clear();
}

auto RequestCookies::parse(std::string_view header_value) -> std::variant<RequestCookies, Error>
{
    if (header_value.size() > max_header_bytes)
    {
        return Error{ErrorCode::invalid_argument, "Cookie header exceeds the size limit"};
    }
    if (has_control_character(header_value))
    {
        return Error{ErrorCode::parse_failure, "Cookie header holds a control character"};
    }
    auto const pair_count = static_cast<std::size_t>(std::ranges::count(header_value, ';')) + 1U;
    if (pair_count > max_cookies)
    {
        return Error{ErrorCode::invalid_argument, "Cookie header exceeds the limit on cookies"};
    }
    auto result = RequestCookies{};
    // Reserved once so no entry is moved out of storage that is then freed unwiped.
    result.m_entries.reserve(pair_count);
    auto remaining = header_value;
    while (true)
    {
        auto const separator = remaining.find(';');
        auto const pair = trimmed(remaining.substr(0U, separator));
        if (!pair.empty())
        {
            auto const equals = pair.find('=');
            auto const name = pair.substr(0U, equals);
            auto const value = equals == std::string_view::npos ? std::string_view{} : pair.substr(equals + 1U);
            // A pair whose name is not a token is someone else's malformed cookie: it can name nothing find() is
            // asked for, so it is counted and otherwise dropped.
            if (http_token_is_valid(name))
            {
                auto& entry = result.m_entries.emplace_back();
                entry.name.assign(name);
                entry.value.assign(value);
                entry.well_formed = equals != std::string_view::npos && cookie_octets_are_valid(value);
            }
            else
            {
                result.m_entries.emplace_back();
            }
        }
        if (separator == std::string_view::npos)
        {
            break;
        }
        remaining.remove_prefix(separator + 1U);
    }
    return result;
}

auto RequestCookies::find(std::string_view name) const noexcept -> std::optional<std::string_view>
{
    if (name.empty())
    {
        return std::nullopt;
    }
    auto const* found = static_cast<Entry const*>(nullptr);
    for (auto const& entry : m_entries)
    {
        if (entry.name != name)
        {
            continue;
        }
        if (found != nullptr)
        {
            return std::nullopt;
        }
        found = &entry;
    }
    if (found == nullptr || !found->well_formed)
    {
        return std::nullopt;
    }
    return std::string_view{found->value};
}

auto RequestCookies::size() const noexcept -> std::size_t
{
    return m_entries.size();
}

} // namespace merovingian::core
