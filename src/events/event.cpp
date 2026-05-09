// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/events/event.hpp>

#include <string_view>
#include <variant>

namespace merovingian::events
{
namespace
{

[[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
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

[[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::string const*
{
    auto const* value = object_member(object, key);
    if (value == nullptr)
    {
        return nullptr;
    }
    return std::get_if<std::string>(&value->storage());
}

[[nodiscard]] auto integer_member(canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::int64_t const*
{
    auto const* value = object_member(object, key);
    if (value == nullptr)
    {
        return nullptr;
    }
    return std::get_if<std::int64_t>(&value->storage());
}

[[nodiscard]] auto contains_no_control_or_space(std::string_view value) noexcept -> bool
{
    for (auto const character : value)
    {
        auto const byte = static_cast<unsigned char>(character);
        if (byte <= 0x20U || byte == 0x7FU)
        {
            return false;
        }
    }

    return true;
}

} // namespace

auto matrix_id_is_valid(std::string_view id, char sigil) noexcept -> bool
{
    return id.size() >= 3U && id.front() == sigil && id.find(':') != std::string_view::npos
        && contains_no_control_or_space(id);
}

auto event_type_is_valid(std::string_view type) noexcept -> bool
{
    return !type.empty() && type.size() <= 255U && contains_no_control_or_space(type);
}

auto parse_event_envelope(canonicaljson::Value const& json) -> EventParseResult
{
    auto const* object = std::get_if<canonicaljson::Object>(&json.storage());
    if (object == nullptr)
    {
        return {{}, "event must be an object"};
    }

    auto const* room_id = string_member(*object, "room_id");
    auto const* type = string_member(*object, "type");
    auto const* sender = string_member(*object, "sender");
    auto const* origin_server_ts = integer_member(*object, "origin_server_ts");
    if (room_id == nullptr || type == nullptr || sender == nullptr || origin_server_ts == nullptr)
    {
        return {{}, "event missing required fields"};
    }
    if (!matrix_id_is_valid(*room_id, '!'))
    {
        return {{}, "invalid room_id"};
    }
    if (!matrix_id_is_valid(*sender, '@'))
    {
        return {{}, "invalid sender"};
    }
    if (!event_type_is_valid(*type))
    {
        return {{}, "invalid event type"};
    }
    if (*origin_server_ts < 0)
    {
        return {{}, "invalid origin_server_ts"};
    }

    auto event = EventEnvelope{};
    event.json = json;
    event.room_id = *room_id;
    event.event_type = *type;
    event.sender = *sender;
    event.origin_server_ts = *origin_server_ts;

    if (auto const* state_key = string_member(*object, "state_key"); state_key != nullptr)
    {
        event.state_key = *state_key;
    }

    return {std::move(event), {}};
}

} // namespace merovingian::events
