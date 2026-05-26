// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/query_params.hpp"

#include <cctype>

namespace merovingian::core
{

namespace
{

    [[nodiscard]] auto from_hex(char ch) noexcept -> std::uint8_t
    {
        if (ch >= '0' && ch <= '9')
        {
            return static_cast<std::uint8_t>(ch - '0');
        }
        if (ch >= 'a' && ch <= 'f')
        {
            return static_cast<std::uint8_t>(ch - 'a') + 10U;
        }
        if (ch >= 'A' && ch <= 'F')
        {
            return static_cast<std::uint8_t>(ch - 'A') + 10U;
        }
        return 0U;
    }

    [[nodiscard]] auto is_unreserved_path_byte(unsigned char byte) noexcept -> bool
    {
        return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
               byte == '-' || byte == '.' || byte == '_' || byte == '~';
    }

    [[nodiscard]] auto hex_digit(unsigned char nibble) noexcept -> char
    {
        return static_cast<char>(nibble < 10U ? ('0' + nibble) : ('A' + (nibble - 10U)));
    }

} // namespace

auto percent_decode(std::string_view encoded) -> std::string
{
    auto result = std::string{};
    result.reserve(encoded.size());
    auto i = std::size_t{0U};
    while (i < encoded.size())
    {
        if (encoded[i] == '%' && i + 2U < encoded.size())
        {
            auto const high = from_hex(encoded[i + 1U]);
            auto const low = from_hex(encoded[i + 2U]);
            result.push_back(static_cast<char>((high << 4U) | low));
            i += 3U;
        }
        else if (encoded[i] == '+')
        {
            result.push_back(' ');
            ++i;
        }
        else
        {
            result.push_back(encoded[i]);
            ++i;
        }
    }
    return result;
}

auto percent_decode_path_component(std::string_view encoded) -> std::string
{
    auto result = std::string{};
    result.reserve(encoded.size());
    auto i = std::size_t{0U};
    while (i < encoded.size())
    {
        if (encoded[i] == '%' && i + 2U < encoded.size())
        {
            auto const high = from_hex(encoded[i + 1U]);
            auto const low = from_hex(encoded[i + 2U]);
            result.push_back(static_cast<char>((high << 4U) | low));
            i += 3U;
        }
        else
        {
            result.push_back(encoded[i]);
            ++i;
        }
    }
    return result;
}

auto percent_encode_path_component(std::string_view decoded) -> std::string
{
    auto result = std::string{};
    result.reserve(decoded.size() * 3U);
    for (auto const ch : decoded)
    {
        auto const byte = static_cast<unsigned char>(ch);
        if (is_unreserved_path_byte(byte))
        {
            result.push_back(static_cast<char>(byte));
            continue;
        }
        result.push_back('%');
        result.push_back(hex_digit(static_cast<unsigned char>(byte >> 4U)));
        result.push_back(hex_digit(static_cast<unsigned char>(byte & 0x0FU)));
    }
    return result;
}

auto parse_query_params(std::string_view target) -> SyncRequest
{
    auto request = SyncRequest{};
    auto const query_start = target.find('?');
    if (query_start == std::string_view::npos)
    {
        return request;
    }
    auto const query = target.substr(query_start + 1U);
    auto pos = std::size_t{0U};
    while (pos < query.size())
    {
        auto const amp_pos = query.find('&', pos);
        auto const param = amp_pos == std::string_view::npos ? query.substr(pos) : query.substr(pos, amp_pos - pos);
        if (amp_pos == std::string_view::npos)
        {
            pos = query.size();
        }
        else
        {
            pos = amp_pos + 1U;
        }
        auto const eq_pos = param.find('=');
        if (eq_pos == std::string_view::npos)
        {
            continue;
        }
        auto const key = param.substr(0U, eq_pos);
        auto const value = percent_decode(param.substr(eq_pos + 1U));

        if (key == "since")
        {
            request.since = std::string{value};
        }
        else if (key == "timeout")
        {
            auto result = std::uint64_t{0U};
            auto parsed = true;
            for (auto const ch : value)
            {
                if (ch >= '0' && ch <= '9')
                {
                    result = result * 10U + static_cast<std::uint64_t>(ch - '0');
                }
                else
                {
                    parsed = false;
                    break;
                }
            }
            if (parsed && !value.empty())
            {
                request.timeout = result;
            }
        }
        else if (key == "full_state")
        {
            request.full_state = (value == "true");
        }
        else if (key == "filter")
        {
            request.filter = std::string{value};
        }
    }
    return request;
}

} // namespace merovingian::core
