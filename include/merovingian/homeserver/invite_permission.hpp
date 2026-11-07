// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"

#include <string_view>

namespace merovingian::homeserver
{

// The Matrix errcode of a refused invite to a user who blocks invites (Client-Server API, "Invite permission").
inline constexpr std::string_view invite_blocked_errcode = "M_INVITE_BLOCKED";

// Whether `user_id` blocks every invite: their global account data `m.invite_permission_config` has
// `default_action` equal to the string "block" (SS7). A missing event, a missing, non-string or other value, or content
// that is not a JSON object means invites as normal. The row is found through the account-data index and never by a
// scan. Call with `runtime.mutex` held.
[[nodiscard]] auto invite_permission_blocks(database::PersistentStore const& store, std::string_view user_id) -> bool;

} // namespace merovingian::homeserver
