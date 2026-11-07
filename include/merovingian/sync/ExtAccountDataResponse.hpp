// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <map>
#include <string>
#include <vector>

namespace merovingian::sync
{

struct ExtAccountDataResponse final
{
    std::vector<std::string> global_json{};
    // Key: room_id, value: serialised account-data events for that room.
    std::map<std::string, std::vector<std::string>> rooms_json{};
};

} // namespace merovingian::sync
