// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::federation
{

struct ServerAclEvent final
{
    std::vector<std::string> allow{};
    std::vector<std::string> deny{};
    bool allow_ip_literals{true};
    // True when the event held more patterns, or a longer pattern, than the server evaluates (ADR-0640). The lists are
    // then empty and the ACL refuses every server.
    bool exceeds_limits{false};
};

} // namespace merovingian::federation
