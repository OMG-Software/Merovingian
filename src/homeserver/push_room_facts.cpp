// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/push_room_facts.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto member_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const found = std::ranges::find_if(object, [key](canonicaljson::ObjectMember const& member) {
            return member.key == key;
        });
        return found == object.end() ? nullptr : std::get_if<canonicaljson::Object>(&found->value->storage());
    }

    // The current state event of (`type`, `state_key`) in `room_id`, parsed, or a null Value.
    [[nodiscard]] auto current_state_event(database::PersistentStore const& store, std::string_view room_id,
                                           std::string_view type, std::string_view state_key) -> canonicaljson::Value
    {
        auto const state = std::ranges::find_if(store.state, [&](database::PersistentStateEvent const& row) {
            return row.room_id == room_id && row.event_type == type && row.state_key == state_key;
        });
        if (state == store.state.end())
        {
            return canonicaljson::Value{};
        }
        auto const event = std::ranges::find_if(store.events, [&](database::PersistentEvent const& row) {
            return row.event_id == state->event_id;
        });
        if (event == store.events.end())
        {
            return canonicaljson::Value{};
        }
        auto parsed = canonicaljson::parse_lossless(event->json);
        return parsed.error == canonicaljson::ParseError::none ? std::move(parsed.value) : canonicaljson::Value{};
    }

} // namespace

auto push_room_facts(database::PersistentStore const& store, std::string_view room_id, std::uint64_t member_count)
    -> PushRoomFacts
{
    auto facts = PushRoomFacts{};
    facts.member_count = member_count;
    // A null Value when the room has no power levels: extract_user_power_level then applies every
    // default.
    facts.power_levels = current_state_event(store, room_id, "m.room.power_levels", "");
    // Room versions 1-9 may encode a power level as a string, and 1-5 as a float. Reading such a
    // value as absent would silently apply a default instead of the level the room set, so the
    // room's own version decides how it is read.
    auto const* policy = rooms::find_room_version_policy(stored_room_version(store, room_id).value_or("12"));
    facts.level_encoding =
        policy == nullptr ? events::PowerLevelEncoding::integers_or_strings : events::power_level_encoding(*policy);
    auto const* event = std::get_if<canonicaljson::Object>(&facts.power_levels.storage());
    auto const* content = event == nullptr ? nullptr : member_object(*event, "content");
    auto const* notifications = content == nullptr ? nullptr : member_object(*content, "notifications");
    if (notifications != nullptr)
    {
        for (auto const& member : *notifications)
        {
            if (auto const* level = std::get_if<std::int64_t>(&member.value->storage()); level != nullptr)
            {
                facts.notification_levels[member.key] = *level;
            }
        }
    }
    return facts;
}

auto room_member_display_name(database::PersistentStore const& store, std::string_view room_id, std::string_view member)
    -> std::string
{
    auto const event = current_state_event(store, room_id, "m.room.member", member);
    auto const* root = std::get_if<canonicaljson::Object>(&event.storage());
    auto const* content = root == nullptr ? nullptr : member_object(*root, "content");
    if (content != nullptr)
    {
        auto const name = std::ranges::find_if(*content, [](canonicaljson::ObjectMember const& field) {
            return field.key == "displayname";
        });
        auto const* text = name == content->end() ? nullptr : std::get_if<std::string>(&name->value->storage());
        if (text != nullptr && !text->empty())
        {
            return *text;
        }
    }
    auto const profile = database::find_profile(store, member);
    return profile.has_value() ? profile->displayname : std::string{};
}

auto push_evaluation_context(PushRoomFacts const& facts, std::string_view recipient, std::string recipient_display_name,
                             std::string_view sender) -> push::PushEvaluationContext
{
    auto context = push::PushEvaluationContext{};
    context.receiving_user_id = std::string{recipient};
    context.receiving_user_display_name = std::move(recipient_display_name);
    context.room_member_count = facts.member_count;
    context.sender_power_level = events::extract_user_power_level(facts.power_levels, sender, facts.level_encoding);
    context.notification_power_levels = facts.notification_levels;
    return context;
}

} // namespace merovingian::homeserver
