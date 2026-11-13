// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RoomPowerJudge.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/events/Authorization.hpp"
#include "merovingian/homeserver/StoredRoomVersion.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <variant>

namespace merovingian::homeserver
{

namespace
{

    // The ban level a room's power-levels event sets, or the spec's 50 when it sets none.
    constexpr auto default_ban_level = std::int64_t{50};

    // The current state event of (`event_type`, "") in the room, parsed; a null
    // Value when the room has none or it cannot be read.
    [[nodiscard]] auto current_state_value(database::PersistentStore const& store, std::string_view room_id,
                                           std::string_view event_type) -> canonicaljson::Value
    {
        auto const state_event_id = database::find_current_state_event_id(store, room_id, event_type, "");
        if (!state_event_id.has_value())
        {
            return canonicaljson::Value{};
        }
        auto const event = store.events.find(*state_event_id);
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

RoomPowerJudge::RoomPowerJudge(database::PersistentStore const& store, std::string_view room_id)
    : create_event_{current_state_value(store, room_id, "m.room.create")}
{
    policy_ = rooms::find_room_version_policy(room_version_of(create_event_));
    if (policy_ != nullptr)
    {
        power_levels_ = current_state_value(store, room_id, "m.room.power_levels");
    }
}

auto RoomPowerJudge::known() const noexcept -> bool
{
    return policy_ != nullptr;
}

auto RoomPowerJudge::may_send_state_event(std::string_view user_id, std::string_view event_type) const -> bool
{
    return policy_ != nullptr && events::effective_sender_power(power_levels_, user_id, create_event_, *policy_) >=
                                     events::required_state_event_power(power_levels_, event_type, *policy_);
}

auto RoomPowerJudge::holds_room_power(std::string_view user_id) const -> bool
{
    if (policy_ == nullptr)
    {
        return false;
    }
    auto const power = events::effective_sender_power(power_levels_, user_id, create_event_, *policy_);
    return power >= events::required_state_event_power(power_levels_, "m.room.power_levels", *policy_) ||
           power >= events::extract_power_level_key(power_levels_, "ban", default_ban_level,
                                                    events::power_level_encoding(*policy_));
}

} // namespace merovingian::homeserver
