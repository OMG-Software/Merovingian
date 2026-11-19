// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/ExtensionNames.hpp"

#include <optional>
#include <string>
#include <vector>

namespace merovingian::sync
{

// MSC4548 account_data extension request.
struct ExtAccountDataRequest final
{
    bool enabled{false};
    // MSC4508's scope, as for typing and receipts: the lists and room subscriptions whose rooms are sent room account
    // data. Absent is every one; an empty array is none (ADR-0865).
    std::optional<std::vector<std::string>> lists{};
    std::optional<std::vector<std::string>> rooms{};
    ExtensionNames names{};
};

} // namespace merovingian::sync
