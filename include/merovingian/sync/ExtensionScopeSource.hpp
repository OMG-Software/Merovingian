// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/ExtensionScopeHistory.hpp"

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
    // Borrowed, may be null: what the connection's last acknowledged response left in the typing and receipts scope
    // (ADR-0863). With it, `build_extensions` sends a room entering the typing scope its current typing state and a
    // room re-entering the receipts scope the receipts it missed, and returns the history this response leaves. With
    // none, every room is read from the request's position alone and no history is returned.
    ExtensionScopeHistory const* history{nullptr};
};

} // namespace merovingian::sync
