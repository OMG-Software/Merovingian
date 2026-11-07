// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/StateKey.hpp"

#include <cstddef>
#include <functional>
#include <string>

namespace merovingian::events
{

struct StateKeyHash final
{
    [[nodiscard]] auto operator()(StateKey const& key) const noexcept -> std::size_t
    {
        auto h = std::hash<std::string>{};
        return h(key.event_type) ^ (h(key.state_key) * 31);
    }
};

} // namespace merovingian::events
