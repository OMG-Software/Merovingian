// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/HandOffAllowlist.hpp"

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/oauth/ParsedUri.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>

namespace merovingian::oauth
{
namespace
{

    [[nodiscard]] auto refuse(char const* message) -> core::Error
    {
        return core::Error{core::ErrorCode::parse_failure, message};
    }

    [[nodiscard]] auto has_upper_case(std::string_view text) noexcept -> bool
    {
        return std::ranges::any_of(text, [](char value) noexcept {
            return value >= 'A' && value <= 'Z';
        });
    }

    [[nodiscard]] auto origin_error(ParsedUri const& uri) -> std::optional<core::Error>
    {
        if (!uri.path().empty() || uri.has_query())
        {
            return refuse("A hand-off origin must end after the host or port, with no path, not even /.");
        }
        if (uri.port() == std::optional<std::uint16_t>{443U})
        {
            return refuse("A hand-off origin must not write the default port 443.");
        }
        return std::nullopt;
    }

    [[nodiscard]] auto scheme_error(ParsedUri const& uri, std::string_view entry) -> std::optional<core::Error>
    {
        // `scheme:` and nothing else: the reader's text is the scheme and its colon.
        if (!uri.path().empty() || uri.has_query() || entry.size() != uri.scheme().size() + 1U)
        {
            return refuse("A hand-off scheme must be a bare scheme and its colon, such as io.element.app:.");
        }
        if (uri.scheme().find('.') == std::string::npos)
        {
            return refuse("A hand-off scheme must be a private-use scheme with a dot, such as io.element.app:.");
        }
        return std::nullopt;
    }

} // namespace

auto hand_off_allowlist_entry_error(std::string_view entry) -> std::optional<core::Error>
{
    auto parsed = ParsedUri::read(entry);
    if (auto const* error = std::get_if<core::Error>(&parsed))
    {
        return core::Error{error->code(), "A hand-off allowlist entry is not a valid URI."};
    }
    auto const& uri = std::get<ParsedUri>(parsed);
    if (has_upper_case(entry))
    {
        return refuse("A hand-off allowlist entry must be written in lower case.");
    }
    if (uri.has_authority())
    {
        if (uri.scheme() != "https")
        {
            return refuse("A hand-off origin must use the https scheme.");
        }
        return origin_error(uri);
    }
    return scheme_error(uri, entry);
}

auto hand_off_allowlist_error(std::span<std::string const> entries) -> std::optional<core::Error>
{
    if (entries.size() > max_hand_off_allowlist_entries)
    {
        return core::Error{core::ErrorCode::invalid_argument, "The hand-off allowlist holds more than 32 entries."};
    }
    for (auto index = std::size_t{0U}; index < entries.size(); ++index)
    {
        if (auto error = hand_off_allowlist_entry_error(entries[index]); error.has_value())
        {
            return error;
        }
        if (std::find(entries.begin(), entries.begin() + static_cast<std::ptrdiff_t>(index), entries[index]) !=
            entries.begin() + static_cast<std::ptrdiff_t>(index))
        {
            return refuse("The hand-off allowlist names an entry twice.");
        }
    }
    return std::nullopt;
}

} // namespace merovingian::oauth
