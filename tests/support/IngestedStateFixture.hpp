// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"
#include "merovingian/homeserver/StoredRoomVersion.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace merovingian::tests
{

// For a fixture that writes events straight into a PersistentStore and then asks for the state AT an
// event (federation /state and /state_ids, client /context).
//
// Those reads answer from the state this server RECORDED for the event (its ADR-0064 state group,
// ADR-0363), never from a walk of the event graph, so a fixture has to record the state ingestion
// would have. This does exactly what ingestion does for an event whose prev_events are already
// recorded: the state before it is the resolution of their states (`compute_state_before`), the state
// after it is that plus the event itself when it is a state event (`compute_state_after`), unchanged
// for a rejected event, and the result is recorded as the event's group (`record_event_state`).
//
// `event` must already be stored, and so must its prev_events, with their state recorded: call this
// parents first. A `status` of "rejected" or "soft_failed" is honoured as ingestion honours it.
inline auto record_ingested_state(database::PersistentStore& store, database::PersistentEvent const& event) -> void
{
    auto const* policy = homeserver::stored_room_version_policy(store, event.room_id);
    if (policy == nullptr)
    {
        policy = rooms::find_room_version_policy("11");
    }
    REQUIRE(policy != nullptr);
    auto const before = homeserver::compute_state_before(store, event.room_id, *policy, event.prev_event_ids);
    REQUIRE(before.ok);
    auto after = before.state;
    if (event.status != "rejected")
    {
        auto const parsed = canonicaljson::parse_lossless(event.json);
        REQUIRE(parsed.error == canonicaljson::ParseError::none);
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        REQUIRE(object != nullptr);
        auto type = std::string{};
        auto state_key = std::optional<std::string>{};
        for (auto const& member : *object)
        {
            auto const* text = std::get_if<std::string>(&member.value->storage());
            if (text == nullptr)
            {
                continue;
            }
            if (member.key == "type")
            {
                type = *text;
            }
            else if (member.key == "state_key")
            {
                state_key = *text;
            }
        }
        after = homeserver::compute_state_after(before.state, event.event_id, type, state_key);
    }
    REQUIRE(homeserver::record_event_state(store, event.room_id, event.event_id, event.prev_event_ids, after,
                                           event.status == "accepted")
                .has_value());
}

// record_ingested_state for every event stored for `room_id`, in the order they were stored, which
// must put a prev_event before the events that cite it. An event that already has a group keeps it.
inline auto record_ingested_state_for_room(database::PersistentStore& store, std::string_view room_id) -> void
{
    // Index loop: recording state appends to the store's other tables, never to `events`.
    for (auto position = std::size_t{0U}; position < store.events.size(); ++position)
    {
        auto const event = store.events[position];
        if (event.room_id == room_id && !database::find_event_state_group(store, event.event_id).has_value())
        {
            record_ingested_state(store, event);
        }
    }
}

} // namespace merovingian::tests
