// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/ThirdPartyBindInvite.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace merovingian::federation
{

struct ThirdPartyBindNotification final
{
    std::string address{};
    std::string medium{};
    // The user the third-party identifier is now bound to.
    std::string mxid{};
    // Only the entries that are well formed and name `mxid`; `dropped` counts the others, which are not acted on.
    std::vector<ThirdPartyBindInvite> invites{};
    std::size_t dropped{0U};
};

} // namespace merovingian::federation
