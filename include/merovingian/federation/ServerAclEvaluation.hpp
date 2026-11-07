// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/ServerAclDecision.hpp"

#include <string>

namespace merovingian::federation
{

struct ServerAclEvaluation final
{
    ServerAclDecision decision{ServerAclDecision::deny};
    std::string rule{};
    std::string reason{};
};

} // namespace merovingian::federation
