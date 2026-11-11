// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::config
{

struct FederationStateResolutionConfig final
{
    std::uint32_t max_state_groups{1000U};
    std::uint32_t max_events_per_state_group{65536U};
    std::uint32_t max_total_state_events{131072U};
    std::uint32_t max_conflicted_state_keys{65536U};
    std::uint32_t max_mainline_auth_chain_depth{10000U};
    std::uint32_t max_auth_chain_walk_events{131072U};
    std::uint32_t max_state_tips_per_server{32U};
};

} // namespace merovingian::config
