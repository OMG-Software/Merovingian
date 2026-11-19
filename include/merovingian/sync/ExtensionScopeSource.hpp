// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <map>
#include <string>
#include <vector>

namespace merovingian::sync
{

// What a sliding sync extension's scope is chosen from in one response (MSC4508, `extension_scope_rooms`).
struct ExtensionScopeSource final
{
    // Each list key of the request, with the room IDs within its range in this response.
    std::map<std::string, std::vector<std::string>> list_windows{};
    // The room IDs of the request's `room_subscriptions`, whatever the user's membership; the caller of
    // `joined_extension_scope_rooms` keeps only the joined ones.
    std::vector<std::string> subscriptions{};
};

} // namespace merovingian::sync
