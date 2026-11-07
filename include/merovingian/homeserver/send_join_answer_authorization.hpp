// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/homeserver/AuthorizedSendJoinAnswer.hpp" // split-shim
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstddef>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// Spec: Server-Server API v1.19, "Checks performed on receipt of a PDU", step 4: each event must pass the
// authorisation rules based on its own auth events. `state` and `auth_chain` have already passed the room filter
// and the signature checks (`filter_verified_send_join_events`).
//
// An event is kept only if every event it names is itself kept, its auth_events are a permitted selection, and the
// auth rules allow it. Everything else is dropped from both arrays: it is never stored, so it stays free to arrive
// later and be judged on its own. Only the answer's own events can authorise, never the store: this runs with
// runtime.mutex released, and without omit_members the answer is complete by the spec's definition.
//
// `refusal` is set when the answer holds no single valid m.room.create in its state, or when the events it keeps do
// not allow `join_event`. The cost is linear in the size of the answer and nothing recurses on its depth.
[[nodiscard]] auto authorize_send_join_answer(canonicaljson::Array const& state, canonicaljson::Array const& auth_chain,
                                              canonicaljson::Value const& join_event,
                                              rooms::RoomVersionPolicy const& policy, std::string_view room_id)
    -> AuthorizedSendJoinAnswer;

} // namespace merovingian::homeserver
