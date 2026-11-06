// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace merovingian::homeserver
{

// ADR-0064 phase B1: joined_members is what callers used before (the user
// IDs found with membership="join" among the ingested state entries);
// state_entries is the full (event_type, state_key) -> event_id map of
// every state event ingested — the room's state immediately BEFORE the
// join event, used by join_room to seed a snapshot state group — with each
// key once, since a state group holds a key at most once.
// recorded_state_events counts every state event of the array that is now
// stored, a repeat included: join_room compares it with the verified array
// to tell a complete snapshot from a failed one.
struct SendJoinStateIngestResult final
{
    std::vector<std::string> joined_members{};
    std::vector<database::PersistentStateGroupStateEntry> state_entries{};
    std::size_t recorded_state_events{0U};
};

} // namespace merovingian::homeserver
