// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/UserCode.hpp"

namespace merovingian::oauth
{

namespace
{

    // Twelve whole copies of the twenty-letter alphabet fit in a byte; the sixteen values above them are skipped.
    constexpr auto accepted_byte_limit = std::uint8_t{240U};
    constexpr auto display_group = std::size_t{4U};

    [[nodiscard]] auto in_alphabet(char letter) noexcept -> bool
    {
        return user_code_alphabet.find(letter) != std::string_view::npos;
    }

    [[nodiscard]] auto is_separator(char letter) noexcept -> bool
    {
        return letter == '-' || letter == ' ' || letter == '.' || letter == '_';
    }

} // namespace

auto user_code_from_bytes(std::span<std::uint8_t const> random_bytes) -> std::optional<std::string>
{
    auto code = std::string{};
    code.reserve(user_code_length);
    for (auto const byte : random_bytes)
    {
        if (code.size() == user_code_length)
        {
            break;
        }
        if (byte >= accepted_byte_limit)
        {
            continue;
        }
        code.push_back(user_code_alphabet[byte % user_code_alphabet.size()]);
    }
    if (code.size() != user_code_length)
    {
        return std::nullopt;
    }
    return code;
}

auto normalise_user_code(std::string_view typed) -> std::optional<std::string>
{
    if (typed.size() > max_typed_user_code_bytes)
    {
        return std::nullopt;
    }
    auto code = std::string{};
    code.reserve(user_code_length);
    for (auto letter : typed)
    {
        if (is_separator(letter))
        {
            continue;
        }
        if (letter >= 'a' && letter <= 'z')
        {
            letter = static_cast<char>(letter - 'a' + 'A');
        }
        if (!in_alphabet(letter) || code.size() == user_code_length)
        {
            return std::nullopt;
        }
        code.push_back(letter);
    }
    if (code.size() != user_code_length)
    {
        return std::nullopt;
    }
    return code;
}

auto display_user_code(std::string_view code) -> std::string
{
    if (code.size() != user_code_length)
    {
        return std::string{code};
    }
    auto shown = std::string{code.substr(0U, display_group)};
    shown.push_back('-');
    shown.append(code.substr(display_group));
    return shown;
}

} // namespace merovingian::oauth
