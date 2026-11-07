// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"

#include <string>
#include <string_view>
#include <unordered_set>

namespace merovingian::homeserver
{

// The users among `candidates` (remote users) who are joined to a room a user of `local_server` is also joined to,
// by the current membership rows. Only these users' device lists are cached (ADR-0560): for anyone else no update
// reaches this server, so a cached list could not be kept current. Two passes over the membership rows, whatever the
// number of candidates: it runs under `runtime.mutex` on a list a client chose (src/homeserver/AGENTS.md).
[[nodiscard]] auto remote_users_sharing_a_room_with_local_users(database::PersistentStore const& store,
                                                                std::string_view local_server,
                                                                std::unordered_set<std::string_view> const& candidates)
    -> std::unordered_set<std::string>;

} // namespace merovingian::homeserver
