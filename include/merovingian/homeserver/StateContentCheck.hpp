// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/StateContentRefusal.hpp"

#include <optional>
#include <string_view>

namespace merovingian::homeserver
{

// F-19: the content checks the spec asks of a state event this server composes for a local client. Every local writer
// of the event calls this one function: PUT /rooms/{roomId}/state, POST /rooms/{roomId}/send with a `state_key`, and
// createRoom `initial_state`. Only a state event with the empty state key is judged, and only these two types:
//
//  - `m.room.canonical_alias` (spec, PUT /state): "servers SHOULD ensure that any added aliases being listed in the
//  event
//    are valid per their grammar/syntax and that they point to the room ID where the state event is to be sent."
//    400 `M_INVALID_PARAM` for syntax, `M_BAD_ALIAS` for a local alias that does not point to `room_id`. Aliases the
//    room's current event already lists are not judged. An alias on another server is judged for syntax only.
//    `pending_alias` is an alias that will point to the room once it exists (createRoom's `room_alias_name`): it counts
//    as pointing to it. `room_id` is empty for a room that does not exist yet.
//  - `m.room.encryption` (spec): `algorithm` is required and must be `m.megolm.v1.aes-sha2`; 400 `M_BAD_JSON`.
//
// `content` is the event's content object.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
[[nodiscard]] auto state_content_refusal(database::PersistentStore const& store, std::string_view room_id,
                                         std::string_view local_server_name, std::string_view event_type,
                                         std::string_view state_key, canonicaljson::Object const& content,
                                         std::string_view pending_alias = {}) -> std::optional<StateContentRefusal>;

} // namespace merovingian::homeserver
