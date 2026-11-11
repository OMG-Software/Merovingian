// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/StateEventReference.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace merovingian::events
{

struct StateResolutionResult final
{
    bool resolved{false};
    std::vector<StateEventReference> resolved_state{};
    std::string reason{};
    // Events whose auth_events a traversal read: the auth chains, the enlarging of the power events and
    // the mainline positions. A test reads it to prove that one resolution costs the distinct events it
    // reaches, not the state size times the auth chain's depth (ADR-0599).
    std::size_t auth_walk_visits{0U};
};

} // namespace merovingian::events
