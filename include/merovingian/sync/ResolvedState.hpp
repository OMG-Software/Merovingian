// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// A room's resolved state as of a sync position, rebuilt from its current state and the store's state change log
// (ADR-0827): each key the log shows changed above `position` takes the value its first such change replaced, a key
// with no value then is left out. nullopt when the log does not cover `position` for the room (before this process
// started, or past what it still holds). Reads the room's state rows once, plus its changes above `position`.
[[nodiscard]] auto resolved_state_at(database::PersistentStore const& store, std::string_view room_id,
                                     std::uint64_t position) -> std::optional<std::vector<std::string>>;

// The event (`event_type`, `state_key`) of the room held as of `position`, empty when it held none: the value its first
// change above `position` replaced, else its current one. nullopt when the log does not cover `position`. Costs the
// room's changes above `position`, none when `position` is the newest, and one lookup by key.
[[nodiscard]] auto resolved_state_event_at(database::PersistentStore const& store, std::string_view room_id,
                                           std::string_view event_type, std::string_view state_key,
                                           std::uint64_t position) -> std::optional<std::string>;

// The events that make the room's resolved state at `position` differ from its resolved state at `since`, one per key
// whose value differs and has one at `position` (`state_after`, ADR-0827). Exact for every pair of positions the log
// covers, whatever the event graph: both states are read from the same record, so a key resolution moved back is found
// and a key that changed and changed back is not sent. nullopt when the log does not cover `since`.
//
// Cost: the room's changes above `since`, counted in the log's `rows_examined`, and one state lookup by key for each
// key they name. Nothing for a window with no state change, never a read of the room's whole state.
[[nodiscard]] auto resolved_state_changes(database::PersistentStore const& store, std::string_view room_id,
                                          std::uint64_t since, std::uint64_t position)
    -> std::optional<std::vector<std::string>>;

} // namespace merovingian::sync
