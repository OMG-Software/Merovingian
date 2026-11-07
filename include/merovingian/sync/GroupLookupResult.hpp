// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/GroupLookup.hpp"

#include <string_view>

namespace merovingian::sync
{

struct GroupLookupResult final
{
    GroupLookup outcome{GroupLookup::broken};
    // Names an entry of the store; valid while the store's state group rows are not changed.
    std::string_view event_id{};
};

} // namespace merovingian::sync
