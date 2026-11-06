// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::homeserver
{

struct LocalUser final
{
    std::string user_id{};
    std::string password_hash{};
    bool locked{false};
    bool suspended{false};
    bool admin{false};
    // Permanent account closure (POST /account/deactivate). Unlike locked and
    // suspended this is irreversible, and the localpart is never reissued.
    bool deactivated{false};
};

} // namespace merovingian::homeserver
