// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/appservice/masquerade_token.hpp"

#include <charconv>

namespace merovingian::appservice
{
namespace
{

    // Reads one `<decimal-length>:<bytes>` field starting at `cursor` in
    // `token`. Advances `cursor` past the consumed field on success.
    [[nodiscard]] auto read_length_prefixed_field(std::string_view token, std::size_t& cursor)
        -> std::optional<std::string_view>
    {
        auto const colon = token.find(':', cursor);
        if (colon == std::string_view::npos)
        {
            return std::nullopt;
        }
        auto const length_str = token.substr(cursor, colon - cursor);
        if (length_str.empty())
        {
            return std::nullopt;
        }
        auto length = std::size_t{0U};
        auto const parse_result = std::from_chars(length_str.data(), length_str.data() + length_str.size(), length);
        if (parse_result.ec != std::errc{} || parse_result.ptr != length_str.data() + length_str.size())
        {
            return std::nullopt;
        }
        auto const field_start = colon + 1U;
        if (field_start + length > token.size())
        {
            return std::nullopt;
        }
        cursor = field_start + length;
        return token.substr(field_start, length);
    }

} // namespace

auto is_masquerade_token(std::string_view token) noexcept -> bool
{
    return token.starts_with(masquerade_token_prefix);
}

auto encode_masquerade_token(MasqueradeIdentity const& identity) -> std::string
{
    auto out = std::string{masquerade_token_prefix};
    out += std::to_string(identity.appservice_id.size()) + ":" + identity.appservice_id;
    out += std::to_string(identity.user_id.size()) + ":" + identity.user_id;
    out += std::to_string(identity.device_id.size()) + ":" + identity.device_id;
    return out;
}

auto decode_masquerade_token(std::string_view token) -> std::optional<MasqueradeIdentity>
{
    if (!is_masquerade_token(token))
    {
        return std::nullopt;
    }
    auto cursor = masquerade_token_prefix.size();
    auto const appservice_id = read_length_prefixed_field(token, cursor);
    if (!appservice_id.has_value())
    {
        return std::nullopt;
    }
    auto const user_id = read_length_prefixed_field(token, cursor);
    if (!user_id.has_value())
    {
        return std::nullopt;
    }
    auto const device_id = read_length_prefixed_field(token, cursor);
    if (!device_id.has_value())
    {
        return std::nullopt;
    }
    if (cursor != token.size())
    {
        // Trailing garbage after the third field — fail closed rather than
        // silently ignoring it.
        return std::nullopt;
    }
    return MasqueradeIdentity{std::string{*appservice_id}, std::string{*user_id}, std::string{*device_id}};
}

} // namespace merovingian::appservice
