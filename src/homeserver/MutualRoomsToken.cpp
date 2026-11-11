// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/MutualRoomsToken.hpp"

#include "merovingian/crypto/ConstantTime.hpp"
#include "merovingian/crypto/GenericHash.hpp"

#include <array>
#include <charconv>
#include <string>
#include <system_error>

namespace merovingian::homeserver
{

namespace
{
    // The keyed hash over the caller, the target user and the offset (hex), or nullopt without a key.
    [[nodiscard]] auto mac_for(std::string_view caller, std::string_view target_user, std::string_view offset_text,
                               std::span<std::uint8_t const> key) -> std::optional<std::string>
    {
        if (key.empty())
        {
            return std::nullopt;
        }
        auto const pieces = std::array<std::string_view, 3U>{caller, target_user, offset_text};
        return crypto::generic_hash(pieces, key);
    }
} // namespace

auto encode_mutual_rooms_token(std::string_view caller, std::string_view target_user, std::size_t offset,
                               std::span<std::uint8_t const> key) -> std::optional<std::string>
{
    auto const offset_text = std::to_string(offset);
    auto const mac = mac_for(caller, target_user, offset_text, key);
    if (!mac.has_value())
    {
        return std::nullopt;
    }
    return offset_text + "." + *mac;
}

auto decode_mutual_rooms_token(std::string_view caller, std::string_view target_user, std::string_view token,
                               std::span<std::uint8_t const> key) -> std::optional<std::size_t>
{
    if (key.empty())
    {
        return std::nullopt;
    }
    auto const dot = token.find('.');
    if (dot == std::string_view::npos || dot == 0U)
    {
        return std::nullopt;
    }
    auto const offset_text = token.substr(0U, dot);
    // Digits only: from_chars would also accept a sign, and the text is hashed as given, so a second spelling of one
    // number (a leading zero) must not verify.
    if (offset_text.size() > 1U && offset_text.front() == '0')
    {
        return std::nullopt;
    }
    auto offset = std::size_t{0U};
    auto const [end, error] = std::from_chars(offset_text.data(), offset_text.data() + offset_text.size(), offset);
    if (error != std::errc{} || end != offset_text.data() + offset_text.size() || offset_text.front() < '0' ||
        offset_text.front() > '9')
    {
        return std::nullopt;
    }
    auto const mac = mac_for(caller, target_user, offset_text, key);
    if (!mac.has_value() || !crypto::constant_time_equal_variable_length(*mac, token.substr(dot + 1U)))
    {
        return std::nullopt;
    }
    return offset;
}

} // namespace merovingian::homeserver
