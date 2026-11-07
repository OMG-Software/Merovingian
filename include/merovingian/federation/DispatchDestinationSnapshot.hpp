// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/FederationDestination.hpp"

#include <string>

namespace merovingian::federation
{

// Snapshot of a destination's retry state. The dispatch worker keeps these
// in memory keyed by server_name so it can short-circuit through the
// existing destination_should_retry circuit breaker between attempts.
struct DispatchDestinationSnapshot final
{
    std::string server_name{};
    FederationDestination state{};
};

} // namespace merovingian::federation
