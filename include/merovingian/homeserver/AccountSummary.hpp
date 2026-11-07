// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::homeserver
{

// What the operator accounts route reports about an account. Nothing here is a credential.
struct AccountSummary final
{
    bool deactivated{false};
    bool locked{false};
    bool suspended{false};
    bool admin{false};
    std::size_t devices{0U};
};

} // namespace merovingian::homeserver
