// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <string_view>

namespace merovingian::homeserver
{

// ADR-0301: whether this server's held state for `room_id` is current. It needs the room's create event
// AND a user of `local_server` joined to the room: state kept after the last local user left through a
// federated leave is stale (only a membership row recorded the leave), and no resident sends this server
// the room's later events. The invite handler, `rescind_invite_from_inviter` and the rejection of a remote
// invite (ADR-0294) decide on it, and must agree. Call with `runtime.mutex` held.
[[nodiscard]] auto room_state_is_current(database::PersistentStore const& store, std::string_view room_id,
                                         std::string_view local_server) -> bool;

} // namespace merovingian::homeserver
