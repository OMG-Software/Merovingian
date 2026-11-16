// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RequestHeaders.hpp"

#include <cstddef>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    [[nodiscard]] auto names_equal(std::string_view left, std::string_view right) noexcept -> bool
    {
        if (left.size() != right.size())
        {
            return false;
        }
        for (std::size_t i = 0U; i < left.size(); ++i)
        {
            auto const a = static_cast<unsigned char>(left[i]);
            auto const b = static_cast<unsigned char>(right[i]);
            auto const lo_a = (a >= 'A' && a <= 'Z') ? static_cast<unsigned char>(a + ('a' - 'A')) : a;
            auto const lo_b = (b >= 'A' && b <= 'Z') ? static_cast<unsigned char>(b + ('a' - 'A')) : b;
            if (lo_a != lo_b)
            {
                return false;
            }
        }
        return true;
    }

} // namespace

auto request_header(LocalHttpRequest const& req, std::string_view name) noexcept -> std::string_view
{
    for (auto const& header : req.headers)
    {
        if (names_equal(header.name, name))
        {
            return header.value;
        }
    }
    return {};
}

auto request_header_values(LocalHttpRequest const& req, std::string_view name) -> std::vector<std::string_view>
{
    auto values = std::vector<std::string_view>{};
    for (auto const& header : req.headers)
    {
        if (names_equal(header.name, name))
        {
            values.emplace_back(header.value);
        }
    }
    return values;
}

} // namespace merovingian::homeserver
