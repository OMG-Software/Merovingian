// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace merovingian::sync
{

// What one sliding sync response left in the typing and receipts extensions' MSC4508 scope, kept with the rest of the
// connection's state, so the next response can tell a room entering scope from one that stayed in it (ADR-0863).
// Every room ID is one the user had joined: nothing here comes from the client.
struct ExtensionScopeHistory final
{
    // The joined rooms of the typing extension's scope. A room in scope that is not here enters it, and is sent its
    // current typing state whatever its typing position (MSC4508).
    std::unordered_set<std::string> typing_rooms{};
    // The joined rooms of the receipts extension's scope.
    std::unordered_set<std::string> receipt_rooms{};
    // Each joined room that dropped out of the receipts scope, with the sync stream position after which it was sent
    // no receipt. A room that comes back is sent the receipts that changed after it, not only those after the
    // request's position (MSC4508's re-entry rule).
    std::unordered_map<std::string, std::uint64_t> receipt_floors{};
    // Whether the account_data extension was on, and the rooms of its scope, whatever the user's membership in them
    // (MSC4548). With it off, the next response that turns it on sends all global account data; a room in scope that
    // is not here enters it and is sent all of its account data, which covers a room re-entering the scope too.
    bool account_data_enabled{false};
    std::unordered_set<std::string> account_data_rooms{};
};

} // namespace merovingian::sync
