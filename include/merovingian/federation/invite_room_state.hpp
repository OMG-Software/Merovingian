// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/inbound_request.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// The most entries of an invite's `invite_room_state` that are looked at. The
// stripped-state set is seven event types with an empty state key, so a longer
// list is not an honest one; refusing it bounds the signature checks (and the
// key lookups behind them) one invite can cause.
inline constexpr std::size_t max_invite_room_state_entries{16U};

// Server-Server API v1.19, PUT /v2/invite: `invite_room_state` "MUST contain the
// `m.room.create` event for the room" and every entry must be "formatted
// according to the room version" (a full PDU, not a stripped event). Servers
// "SHOULD apply" the following validation "to all other room versions" than 1
// through 11, and answer M_INVALID_PARAM when:
//   - the m.room.create event is missing from `invite_room_state`;
//   - an entry is not formatted according to the room's version;
//   - an entry fails a signature check;
//   - an entry does not reside in the same room as the invite (for a room
//     version whose create event carries no room_id, the room ID is computed
//     from the create event's reference hash).
//
// Applied to room versions whose create event defines the room ID (12 and up,
// MSC4291). Room versions 1 through 11 are accepted as they arrive: the spec
// only says servers MAY validate them, and servers that have not finished
// migrating still send stripped entries ("servers SHOULD warn about invites
// which fail the validation rather than error in room versions 1 through 11").
//
// `known_key` is the X-Matrix key of the request when there is one (used
// without a lookup when an entry is signed by that server and key). Every other
// key goes through `resolve_key`, which MUST be an admitted path (FED-10). A
// refusal is status 400 (M_INVALID_PARAM); a key lookup refused for local load is
// status 503, which is not a verdict on the invite.
[[nodiscard]] auto validate_invite_room_state(std::string_view room_id, std::string_view room_version,
                                              std::vector<std::string> const& invite_room_state_json,
                                              std::optional<FederationKeyRecord> const& known_key,
                                              SignatureKeyResolver const& resolve_key) -> FederationDecision;

} // namespace merovingian::federation
