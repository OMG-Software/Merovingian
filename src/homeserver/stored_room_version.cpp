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
        return {};
    }
    auto const* version_value = member_of(*content, "room_version");
    if (version_value == nullptr)
    {
        // Spec (client-server-api.md, m.room.create): room_version "Defaults to \"1\" if the key
        // does not exist".
        return "1";
    }
    auto const* version = std::get_if<std::string>(&version_value->storage());
    return version == nullptr ? std::string{} : *version;
}

auto stored_room_version(database::PersistentStore const& store, std::string_view room_id) -> std::optional<std::string>
{
    for (auto const& state : store.state)
    {
        if (state.room_id != room_id || state.event_type != "m.room.create" || !state.state_key.empty())
        {
            continue;
        }
        for (auto const& event : store.events)
        {
            if (event.event_id != state.event_id)
            {
                continue;
            }
            auto const parsed = canonicaljson::parse_lossless(event.json);
            auto const* object = parsed.error == canonicaljson::ParseError::none
                                     ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                     : nullptr;
            return object == nullptr ? std::string{} : declared_room_version(*object);
        }
        // The create row names an event that is not stored: nothing usable is declared.
        return std::string{};
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
