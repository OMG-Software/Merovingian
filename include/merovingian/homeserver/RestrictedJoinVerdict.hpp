// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// How this server, resident in a room, answers a join by a user who is not yet
// a member (audit R04, ADR-0185).
//
// client-server-api.md "Restricted rooms": "When joining without an invite,
// the server MUST verify that the requesting user meets at least one of the
// conditions." server-server-api.md "Restricted rooms" names the refusals:
// 400 M_UNABLE_TO_AUTHORISE_JOIN when no condition can be validated, 400
// M_UNABLE_TO_GRANT_JOIN when a condition holds but no user of this server can
// meet the auth rules for join_authorised_via_users_server, and 403 M_FORBIDDEN
// when the user fails every condition.
enum class RestrictedJoinVerdict : std::uint8_t
{
    // The room's join rule is not restricted or knock_restricted under its
    // room version: join_authorised_via_users_server plays no part.
    not_restricted,
    // The user is invited or already joined: "If the user has an invite to the
    // room then the restrictions will not affect them."
    already_permitted,
    // A condition holds and `authorising_user` (a joined user of this server
    // with at least the invite power level) may authorise the join.
    authorised,
    unable_to_authorise,
    unable_to_grant,
    forbidden,
};

} // namespace merovingian::homeserver
