// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/KeyApiRoute.hpp"
#include "merovingian/database/statement.hpp"

#include <string>
#include <vector>

namespace merovingian::auth
{

struct KeyApiBoundaryPlan final
{
    KeyApiRoute route{};
    std::vector<database::PreparedStatement> database_statements{};
    std::string audit_event_type{};
};

} // namespace merovingian::auth
