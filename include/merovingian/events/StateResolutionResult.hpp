// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/StateEventReference.hpp"

#include <string>
#include <vector>

namespace merovingian::events
{

struct StateResolutionResult final
{
    bool resolved{false};
    std::vector<StateEventReference> resolved_state{};
    std::string reason{};
};

} // namespace merovingian::events
