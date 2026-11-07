// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::config
{

// A state snapshot can name many already-cached events. Its advertised ID
// capacity is independent of the bounded number of network calls per attempt.
struct FederationBackfillConfig final
{
    std::uint32_t max_missing_events{20U};
    std::uint32_t max_outbound_calls{16U};
    std::uint32_t max_state_ids{65536U};
    std::uint32_t max_auth_chain_ids{65536U};
    std::uint32_t max_snapshot_events{131072U};
    std::uint32_t max_snapshot_outbound_calls{256U};
    std::uint32_t max_total_outbound_calls{512U};
    std::string response_max_size{"16MiB"};
    std::string timeout{"45s"};
};

} // namespace merovingian::config
