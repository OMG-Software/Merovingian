// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/Limits.hpp"

#include <cstddef>

namespace merovingian::events
{

struct StateResolutionLimits final
{
    std::size_t max_state_groups{merovingian::events::max_state_groups};
    std::size_t max_events_per_state_group{merovingian::events::max_events_per_state_group};
    std::size_t max_conflicted_state_keys{merovingian::events::max_conflicted_state_keys};
    std::size_t max_mainline_auth_chain_depth{merovingian::events::max_mainline_auth_chain_depth};
    std::size_t max_auth_chain_walk_events{merovingian::events::max_auth_chain_walk_events};
    std::size_t max_total_state_events{merovingian::events::max_total_state_events};
    std::size_t max_state_tips_per_server{merovingian::events::max_state_tips_per_server};
    std::size_t max_unprivileged_state_tips{merovingian::events::max_unprivileged_state_tips};
};

} // namespace merovingian::events
