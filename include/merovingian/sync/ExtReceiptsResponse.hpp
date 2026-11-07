// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <map>
#include <string>

namespace merovingian::sync
{

struct ExtReceiptsResponse final
{
    // Key: room_id, value: serialised m.receipt event content JSON.
    std::map<std::string, std::string> rooms_json{};
};

} // namespace merovingian::sync
