// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentAdminAction final
{
    std::string admin_user_id{};
    std::string action{};
    std::string target{};
};

} // namespace merovingian::database
