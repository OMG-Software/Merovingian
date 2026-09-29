// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::tests
{

// Helpers for building membership PDUs (send_join/leave/knock bodies) that a
// real server would actually send.
//
// ADR-0064 phase B2 made the membership path run the spec's receipt checks:
// an inbound membership event is authorised against its own auth_events and
// against the state before it, not just against current state. A hand-built
// envelope with empty prev_events and empty auth_events therefore no longer
// passes: with no prev_events the state before it is empty, and with no
// auth_events nothing proves the sender was allowed to join. That is correct
// — a conformant peer never sends such an event — so fixtures must build
// realistic ones. See docs/matrix-v1.19-spec/server-server-api.md,
// "Checks performed on receipt of a PDU" and "Auth events selection".

// The room's forward extremities — what a real sender would put in
// prev_events, obtained the same way our own make_join template does.
[[nodiscard]] inline auto fixture_prev_event_ids(database::PersistentStore const& store, std::string_view room_id)
    -> std::vector<std::string>
{
    return database::find_forward_extremities(store, room_id);
}

// The auth events the spec's selection rules call for, taken from the room's
// current state: the create event (omitted for room versions where the room
// ID implies it), power levels, join rules, and the sender's own membership
// if it has one. `omit_create` mirrors room v12 (MSC4291), where naming the
// create event is forbidden.
[[nodiscard]] inline auto fixture_auth_event_ids(database::PersistentStore const& store, std::string_view room_id,
                                                 std::string_view sender, bool omit_create = false)
    -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const& entry : store.state)
    {
        if (entry.room_id != room_id || entry.event_id.empty())
        {
            continue;
        }
        auto const& type = entry.event_type;
        auto const selected = (type == "m.room.create" && entry.state_key.empty() && !omit_create) ||
                              (type == "m.room.power_levels" && entry.state_key.empty()) ||
                              (type == "m.room.join_rules" && entry.state_key.empty()) ||
                              (type == "m.room.member" && entry.state_key == sender);
        if (selected)
        {
            ids.push_back(entry.event_id);
        }
    }
    return ids;
}

} // namespace merovingian::tests
