// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::homeserver
{

// The JSON of the events a plan names, in the plan's order, copied once each.
struct SendJoinAnswerEvents final
{
    std::vector<std::string> state_json{};
    std::vector<std::string> auth_chain_json{};
};

} // namespace merovingian::homeserver
