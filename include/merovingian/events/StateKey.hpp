// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::events
{

struct StateKey final
{
    std::string event_type{};
    std::string state_key{};

    [[nodiscard]] auto operator==(StateKey const& other) const noexcept -> bool
    {
        return event_type == other.event_type && state_key == other.state_key;
    }
};

} // namespace merovingian::events
