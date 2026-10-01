// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/room_read_access.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>

namespace merovingian::sync
{

namespace
{

    constexpr auto member_type = std::string_view{"m.room.member"};
    // A user's chain of m.room.member events is one entry per membership change. The bound only
    // has to stop a cycle in corrupt data; a real room does not approach it.
    constexpr auto max_membership_chain = std::size_t{4096U};

    [[nodiscard]] auto membership_of_json(std::string_view event_json) -> std::optional<std::string>
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (event == nullptr)
        {
            return std::nullopt;
        }
        for (auto const& member : *event)
        {
            if (member.key != "content")
            {
                continue;
            }
            auto const* content = std::get_if<canonicaljson::Object>(&member.value->storage());
            if (content == nullptr)
            {
                return std::nullopt;
            }
            for (auto const& field : *content)
            {
                if (field.key == "membership")
                {
                    auto const* text = std::get_if<std::string>(&field.value->storage());
                    return text == nullptr ? std::nullopt : std::optional<std::string>{*text};
                }
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto event_is_withheld(database::PersistentEvent const& event) noexcept -> bool
    {
        return event.status == "rejected" || event.status == "soft_failed";
    }

    // The room's current `m.room.member` state event for the user, if any.
    [[nodiscard]] auto current_member_event_id(database::PersistentStore const& store, std::string_view room_id,
                                               std::string_view user_id) -> std::optional<std::string>
    {
        for (auto const& state : store.state)
        {
            if (state.room_id == room_id && state.event_type == member_type && state.state_key == user_id)
            {
                return state.event_id;
            }
        }
        return std::nullopt;
    }

    // The event that ended the user's most recent join, found by walking the chain of the
    // user's m.room.member events back from their current one (`ending_event_id`) until a
    // join. nullopt when there was no join in the chain or the chain is broken.
    [[nodiscard]] auto find_join_ending_event(database::PersistentStore const& store, std::string_view room_id,
                                              std::string_view user_id, std::string_view ending_event_id)
        -> std::optional<database::PersistentEvent const*>
    {
        auto events_by_id = std::unordered_map<std::string_view, database::PersistentEvent const*>{};
        events_by_id.reserve(store.events.size());
        for (auto const& event : store.events)
        {
            events_by_id.emplace(event.event_id, &event);
        }
        auto const find = [&events_by_id](std::string_view id) -> database::PersistentEvent const* {
            auto const found = events_by_id.find(id);
            return found == events_by_id.end() ? nullptr : found->second;
        };

        auto child = std::string_view{};
        auto current = ending_event_id;
        for (auto step = std::size_t{0U}; step < max_membership_chain; ++step)
        {
            auto const* event = find(current);
            if (event == nullptr || event->room_id != room_id)
            {
                return std::nullopt;
            }
            auto const membership = membership_of_json(event->json);
            if (!membership.has_value())
            {
                return std::nullopt;
            }
            if (step > 0U && *membership == "join" && !event_is_withheld(*event))
            {
                return find(child);
            }
            if (step == 0U && *membership == "join")
            {
                return std::nullopt; // the projection says left but the state says joined
            }
            child = current;
            auto const* transition = database::find_state_transition(store, room_id, member_type, user_id, current);
            if (transition == nullptr || transition->previous_event_id.empty())
            {
                return std::nullopt;
            }
            current = transition->previous_event_id;
        }
        return std::nullopt;
    }

} // namespace

auto room_read_access_for(database::PersistentStore const& store, std::string_view room_id,
                          std::string_view user_id) -> RoomReadAccess
{
    auto found_row = false;
    auto newest_ordering = std::uint64_t{0U};
    auto membership = std::string_view{};
    for (auto const& row : store.memberships)
    {
        if (row.room_id != room_id || row.user_id != user_id)
        {
            continue;
        }
        if (!found_row || row.stream_ordering >= newest_ordering)
        {
            found_row = true;
            newest_ordering = row.stream_ordering;
            membership = row.membership;
        }
    }

    auto const member_event_id = current_member_event_id(store, room_id, user_id);
    if (!found_row)
    {
        // The projection row is gone: `/forget` deletes it, and some tests clear it. Only a
        // current join in the room's state still counts; a forgotten room grants nothing.
        if (!member_event_id.has_value())
        {
            return {};
        }
        for (auto const& event : store.events)
        {
            if (event.event_id == *member_event_id)
            {
                if (!event_is_withheld(event) && membership_of_json(event.json) == std::optional<std::string>{"join"})
                {
                    return {RoomReadKind::current, {}, 0U};
                }
                return {};
            }
        }
        return {};
    }

    if (membership == "join")
    {
        return {RoomReadKind::current, {}, 0U};
    }
    if ((membership != "leave" && membership != "ban") || !member_event_id.has_value())
    {
        return {};
    }
    auto const boundary = find_join_ending_event(store, room_id, user_id, *member_event_id);
    if (!boundary.has_value() || *boundary == nullptr)
    {
        return {};
    }
    return {RoomReadKind::as_of, (*boundary)->event_id, (*boundary)->stream_ordering};
}

auto room_state_event_ids(database::PersistentStore const& store, std::string_view room_id,
                          RoomReadAccess const& access,
                          std::optional<std::uint64_t> at) -> std::optional<std::vector<std::string>>
{
    if (access.kind == RoomReadKind::none)
    {
        return std::nullopt;
    }
    if (access.kind == RoomReadKind::current && !at.has_value())
    {
        auto ids = std::vector<std::string>{};
        for (auto const& state : store.state)
        {
            if (state.room_id == room_id)
            {
                ids.push_back(state.event_id);
            }
        }
        return ids;
    }

    auto limit = at.value_or(std::numeric_limits<std::uint64_t>::max());
    if (access.kind == RoomReadKind::as_of)
    {
        limit = std::min(limit, access.boundary_ordering);
    }
    database::PersistentEvent const* newest = nullptr;
    for (auto const& event : store.events)
    {
        if (event.room_id != room_id || event.stream_ordering > limit || event_is_withheld(event))
        {
            continue;
        }
        if (newest == nullptr || event.stream_ordering > newest->stream_ordering)
        {
            newest = &event;
        }
    }
    if (newest == nullptr)
    {
        return std::vector<std::string>{}; // before the room's first event there is no state
    }
    auto const group_id = database::find_event_state_group(store, newest->event_id);
    if (!group_id.has_value())
    {
        return std::nullopt;
    }
    auto const full_state = database::read_state_group_full_state(store, *group_id);
    if (!full_state.has_value())
    {
        return std::nullopt;
    }
    auto ids = std::vector<std::string>{};
    ids.reserve(full_state->size());
    for (auto const& entry : *full_state)
    {
        ids.push_back(entry.event_id);
    }
    return ids;
}

} // namespace merovingian::sync
