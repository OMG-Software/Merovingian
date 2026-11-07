// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

// A client-uploaded sync filter. The server stores the raw JSON verbatim and
// returns an opaque `filter_id`; clients pass the id as a query parameter on
// subsequent /sync requests so the server can apply the filter criteria.
struct PersistentFilter final
{
    std::string user_id{};
    std::string filter_id{};
    std::string json{};
};

} // namespace merovingian::database
