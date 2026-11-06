// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::platform
{

struct PrivilegeDropPlan final
{
    std::string user{};
    std::string group{};
    bool drop_supplementary_groups{true};
    bool clear_environment{true};
};

} // namespace merovingian::platform
