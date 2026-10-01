// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::tests
{

// For a fixture that writes events straight into a PersistentStore instead of going through
// the room service.
//
// Every client read path hides an event from a user unless the state recorded for that event
// (ADR-0064 state group) shows the user may see it (`sync::HistoryVisibility`, CSAZ-3), and an
// event stored without a state group is hidden from everyone. This records ONE state group in
// which `user_id` is joined, and maps every event currently stored for `room_id` to it, so a
// user whose visibility is not what the test is about can read the fixture's history.
//
// The joined member event is stored under a separate room ID so it never appears in the
// room's own timeline or changes its event counts.
inline auto record_joined_state_for_room(database::PersistentStore& store, std::string_view room_id,
                                         std::string_view user_id) -> void
{
    auto const member_event_id = std::string{"$fixture_join_"} + std::string{user_id} + std::string{room_id};
    auto member_event = database::PersistentEvent{};
    member_event.event_id = member_event_id;
    member_event.room_id = std::string{"!fixture-state-holder:example.org"};
    member_event.sender_user_id = std::string{user_id};
    member_event.json = std::string{R"({"type":"m.room.member","state_key":")"} + std::string{user_id} +
                        R"(","content":{"membership":"join"}})";
    member_event.stream_ordering = 1U;
    store.events.push_back(std::move(member_event));

    auto const group_id = std::string{"sg:fixture:"} + std::string{room_id} + std::string{user_id};
    auto const group = database::create_or_reuse_state_group(
        store, room_id, group_id, std::nullopt,
        {
            {std::string{}, "m.room.member", std::string{user_id}, member_event_id}
    });
    REQUIRE(group.has_value());
    for (auto const& event : store.events)
    {
        if (event.room_id == room_id)
        {
            REQUIRE(database::set_event_state_group(store, event.event_id, *group));
        }
    }
}

} // namespace merovingian::tests
