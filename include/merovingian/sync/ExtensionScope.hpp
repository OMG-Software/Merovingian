// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/ExtensionScopeHistory.hpp"
#include "merovingian/sync/ExtensionScopeSource.hpp"
#include "merovingian/sync/RoomAccess.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::sync
{

// The rooms in scope for a sliding-sync extension (MSC4508, "Common extension semantics"): each room within the range
// of a list `lists` names, then each room subscription `rooms` names, without repeats, in that order.
//
// * `list_windows` maps each list key of the request to the room IDs within its range; `subscriptions` holds the room
//   IDs of the request's `room_subscriptions` the user may be served.
// * An absent `lists` (nullopt) names every list and an absent `rooms` every subscription. An empty array names none,
//   so `{"lists": []}` scopes the extension to the subscriptions alone. A "*" entry names every one, as the older
//   MSC3575 form did.
// * A list key the request does not hold, and a room ID that is not one of `subscriptions`, name nothing. A room named
//   in `rooms` without a subscription is never in scope: the extension cannot reach a room the request did not ask for.
//
// Being in scope does not mean the user is joined; the caller judges that.
[[nodiscard]] auto extension_scope_rooms(std::optional<std::vector<std::string>> const& lists,
                                         std::optional<std::vector<std::string>> const& rooms,
                                         std::map<std::string, std::vector<std::string>> const& list_windows,
                                         std::vector<std::string> const& subscriptions) -> std::vector<std::string>;

// The rooms of `extension_scope_rooms` over `source` that `room_access` classifies as joined, in the same order. Every
// room-scoped extension (typing, receipts, sticky_events) serves only these: an invited, left, kicked or banned room in
// scope is sent nothing (CSAZ-1). `room_access` is the request's `room_access_index` for the user.
[[nodiscard]] auto joined_extension_scope_rooms(std::optional<std::vector<std::string>> const& lists,
                                                std::optional<std::vector<std::string>> const& rooms,
                                                ExtensionScopeSource const& source,
                                                std::map<std::string, RoomAccess, std::less<>> const& room_access)
    -> std::vector<std::string>;

// Whether `room_id`, in the typing extension's joined scope now, enters it: `history` (the connection's last
// acknowledged response) did not hold it there. MSC4508: such a room is sent its current typing state, whatever its
// typing position (ADR-0863).
[[nodiscard]] auto enters_typing_scope(ExtensionScopeHistory const& history, std::string const& room_id) -> bool;

// The sync stream position after which `room_id`, in the receipts extension's joined scope now, is sent its receipts:
// the position it dropped out of scope at when it comes back (`history.receipt_floors`), else `since_sync_stream_id`.
// MSC4508: a room that re-enters scope ends up with up-to-date state, so it is sent what changed while it was out
// (ADR-0863). The handler's long-poll check and `build_extensions` both read it, so a poll is woken only for what the
// response sends.
[[nodiscard]] auto receipt_floor_for(ExtensionScopeHistory const& history, std::string const& room_id,
                                     std::uint64_t since_sync_stream_id) -> std::uint64_t;

} // namespace merovingian::sync
