// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/stored_room_version.hpp"

#include "merovingian/canonicaljson/parser.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace merovingian::homeserver
{

namespace
{

    [[nodiscard]] auto member_of(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

} // namespace

auto declared_room_version(canonicaljson::Object const& create_event) -> std::string
{
    auto const* content_value = member_of(create_event, "content");
    auto const* content =
        content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
    if (content == nullptr)
    {
        // Nothing usable is declared. Treat it as version 1, as an absent room_version is: never
        // an empty string, which some parsers would turn into their own default.
        return "1";
    }
    auto const* version_value = member_of(*content, "room_version");
    if (version_value == nullptr)
    {
        // Spec (client-server-api.md, m.room.create): room_version "Defaults to \"1\" if the key
        // does not exist".
        return "1";
    }
    auto const* version = std::get_if<std::string>(&version_value->storage());
    // Rule 1.3 rejects a room_version that is not a string, or empty; one that reached the store
    // anyway declares nothing usable, so it too is version 1.
    return version == nullptr || version->empty() ? std::string{"1"} : *version;
}

auto stored_create_room_version(std::string_view create_event_json) -> std::string
{
    auto const parsed = canonicaljson::parse_lossless(create_event_json);
    auto const* object = parsed.error == canonicaljson::ParseError::none
                             ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                             : nullptr;
    return object == nullptr ? std::string{"1"} : declared_room_version(*object);
}

auto stored_room_version(database::PersistentStore const& store, std::string_view room_id) -> std::optional<std::string>
{
    for (auto const& state : store.state)
    {
        if (state.room_id != room_id || state.event_type != "m.room.create" || !state.state_key.empty())
        {
            continue;
        }
        for (auto const& event : store.events.with_id(state.event_id))
        {
            return stored_create_room_version(event.json);
        }
        // The create row names an event that is not stored: nothing usable is declared.
        return std::string{"1"};
    }
    return std::nullopt;
}

auto stored_room_version_policy(database::PersistentStore const& store, std::string_view room_id)
    -> rooms::RoomVersionPolicy const*
{
    auto const version = stored_room_version(store, room_id);
    return version.has_value() ? rooms::find_room_version_policy(*version) : nullptr;
}

} // namespace merovingian::homeserver
