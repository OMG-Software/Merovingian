// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <functional>
#include <string_view>

namespace merovingian::database::detail
{

// Lets an index be searched with a std::string_view without building a std::string.
struct StateGroupKeyHash final
{
    using is_transparent = void;
    [[nodiscard]] auto operator()(std::string_view key) const noexcept -> std::size_t
    {
        return std::hash<std::string_view>{}(key);
    }
};

} // namespace merovingian::database::detail
