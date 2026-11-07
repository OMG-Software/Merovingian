// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/EventTypeFilter.hpp"

#include <string>
#include <vector>

namespace merovingian::sync
{

struct RoomFilter final
{
    std::vector<std::string> rooms{};
    std::vector<std::string> not_rooms{};
    EventTypeFilter timeline{};
    EventTypeFilter state{};
    EventTypeFilter ephemeral{};
    EventTypeFilter account_data{};
    bool include_leave{false};
};

} // namespace merovingian::sync
