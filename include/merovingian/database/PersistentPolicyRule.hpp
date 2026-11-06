// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentPolicyRule final
{
    std::string rule_id{};
    std::string scope{};
    std::string entity{};
    std::string action{};
    std::string reason{};
};

} // namespace merovingian::database
