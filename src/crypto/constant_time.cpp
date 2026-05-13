// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/constant_time.hpp"

#include <algorithm>
#include <cstddef>

namespace merovingian::crypto
{

auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool
{
    auto difference = left.size() ^ right.size();
    auto const compared_size = std::max(left.size(), right.size());

    for (std::size_t index = 0; index < compared_size; ++index)
    {
        auto const left_byte = index < left.size() ? static_cast<unsigned char>(left[index]) : 0U;
        auto const right_byte = index < right.size() ? static_cast<unsigned char>(right[index]) : 0U;
        difference |= left_byte ^ right_byte;
    }

    return difference == 0U;
}

} // namespace merovingian::crypto
