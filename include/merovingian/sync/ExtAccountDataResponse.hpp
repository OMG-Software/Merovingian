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
    // Whether a row at or before the request's position went down because the extension was turned on or its room
    // entered the scope. Not sent: the handler gives such a response a new `pos` page, as for typing and receipts,
    // or the next request could not acknowledge it and would be sent the same rows again.
    bool sent_on_scope_entry{false};
};

} // namespace merovingian::sync
