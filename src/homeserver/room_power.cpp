// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/room_power.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <string>
#include <variant>

namespace merovingian::homeserver
{

namespace
{

    // The current state event of (`event_type`, "") in the room, parsed; a null
    // Value when the room has none or it cannot be read.
    [[nodiscard]] auto current_state_value(database::PersistentStore const& store, std::string_view room_id,
                                           std::string_view event_type) -> canonicaljson::Value
    {
        auto const state = std::ranges::find_if(store.state, [&](database::PersistentStateEvent const& entry) {
            return entry.room_id == room_id && entry.event_type == event_type && entry.state_key.empty();
        });
        if (state == store.state.end())
        {
            return canonicaljson::Value{};
        }
        auto const event = store.events.find(state->event_id);
        if (event == store.events.end())
        {
            return canonicaljson::Value{};
        }
        auto parsed = canonicaljson::parse_lossless(event->json);
        return parsed.error == canonicaljson::ParseError::none ? std::move(parsed.value) : canonicaljson::Value{};
    }

    // The create event's declared version, through the shared rule (declared_room_version): a
    // create without room_version is room version 1, which has no policy here.
    [[nodiscard]] auto room_version_of(canonicaljson::Value const& create_event) -> std::string
    {
        auto const* root = std::get_if<canonicaljson::Object>(&create_event.storage());
        return root == nullptr ? std::string{} : declared_room_version(*root);
    }

} // namespace

auto may_send_state_event(database::PersistentStore const& store, std::string_view room_id, std::string_view user_id,
                          std::string_view event_type) -> bool
{
    auto const create_event = current_state_value(store, room_id, "m.room.create");
    auto const* policy = rooms::find_room_version_policy(room_version_of(create_event));
    if (policy == nullptr)
    {
        return false;
    }
    auto const power_levels = current_state_value(store, room_id, "m.room.power_levels");
    return events::effective_sender_power(power_levels, user_id, create_event, *policy) >=
           events::required_state_event_power(power_levels, event_type, *policy);
}

} // namespace merovingian::homeserver
