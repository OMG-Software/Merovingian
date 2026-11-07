// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::homeserver
{

// Who and what the audit row of a deactivation names (`auth.account_deactivated`): the owner's own
// deactivation records the user and the device, an administrator's records the administrator and the user.
struct DeactivationAudit final
{
    std::string actor{};
    std::string target{};
    std::string reason{};
};

} // namespace merovingian::homeserver
