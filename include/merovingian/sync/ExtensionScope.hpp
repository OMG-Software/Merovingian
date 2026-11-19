// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

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

} // namespace merovingian::sync
