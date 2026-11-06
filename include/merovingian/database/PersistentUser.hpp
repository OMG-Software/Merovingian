// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentUser final
{
    std::string user_id{};
    std::string password_hash{};
    bool locked{false};
    bool suspended{false};
    bool admin{false};
    // Permanent, irreversible account closure (spec: POST /account/deactivate).
    // Distinct from `locked`/`suspended`, which are reversible admin actions: a
    // deactivated account can never log in again and its localpart is never
    // reissued.
    bool deactivated{false};
};

} // namespace merovingian::database
