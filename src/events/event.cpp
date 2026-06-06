// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/event.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace merovingian::events
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("event", event, std::move(fields)));
    }

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

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Object>(&value->storage());
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

    [[nodiscard]] auto parse_event_signatures(canonicaljson::Object const& object) -> std::vector<EventSignature>
    {
        auto const* signatures = object_member_as_object(object, "signatures");
        if (signatures == nullptr)
        {
            return {};
        }

        auto parsed = std::vector<EventSignature>{};
        for (auto const& server_member : *signatures)
        {
            auto const* server_signatures = std::get_if<canonicaljson::Object>(&server_member.value->storage());
            if (server_signatures == nullptr)
            {
                continue;
            }
            for (auto const& key_member : *server_signatures)
            {
                auto const* signature = std::get_if<std::string>(&key_member.value->storage());
                if (signature != nullptr)
                {
                    parsed.push_back({server_member.key, key_member.key, *signature});
                }
            }
        }
        return parsed;
    }

} // namespace

auto matrix_id_is_valid(std::string_view id, char sigil) noexcept -> bool
{
    // MSC4291 (room v12): room IDs are !<base64-hash> with no :server suffix.
    // User IDs (@) and event IDs ($) still require a colon. Room IDs (!) may
    // omit the colon when the ID is a hash-derived v12 room identifier.
    auto const requires_colon = sigil != '!';
    return id.size() >= 3U && id.front() == sigil &&
           (!requires_colon || id.find(':') != std::string_view::npos) &&
           contains_no_control_or_space(id);
}

auto event_type_is_valid(std::string_view type) noexcept -> bool
{
    return !type.empty() && type.size() <= 255U && contains_no_control_or_space(type);
}

auto parse_event_envelope(canonicaljson::Value const& json) -> EventParseResult
{
    auto result = [&]() -> EventParseResult {
        auto const* object = std::get_if<canonicaljson::Object>(&json.storage());
        if (object == nullptr)
        {
            return {{}, "event must be an object"};
        }

        auto const* type = string_member(*object, "type");
        auto const* sender = string_member(*object, "sender");
        auto const* origin_server_ts = integer_member(*object, "origin_server_ts");
        auto const* room_id = string_member(*object, "room_id");

        // Spec: Room Version 12 (MSC4291) — m.room.create MUST NOT have a room_id
        // field; the room ID is derived from the create event's reference hash.
        // All other event types MUST have a room_id.
        auto const is_create_event = (type != nullptr && *type == "m.room.create");
        if (type == nullptr || sender == nullptr || origin_server_ts == nullptr)
        {
            return {{}, "event missing required fields"};
        }
        if (!is_create_event && room_id == nullptr)
        {
            return {{}, "event missing required fields"};
        }
        if (room_id != nullptr && !matrix_id_is_valid(*room_id, '!'))
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
        // room_id is absent for v12 create events; the caller derives it from
        // the reference hash and populates event.room_id after this call.
        if (room_id != nullptr)
        {
            event.room_id = *room_id;
        }
        event.event_type = *type;
        event.sender = *sender;
        event.origin_server_ts = *origin_server_ts;
        event.signatures = parse_event_signatures(*object);

        if (auto const* state_key = string_member(*object, "state_key"); state_key != nullptr)
        {
            event.state_key = *state_key;
        }

        return {std::move(event), {}};
    }();
    if (result.error.empty())
    {
        log_diagnostic("envelope.parsed",
                       {{"room_id",    result.event.room_id,    false},
                        {"event_type", result.event.event_type, false},
                        {"sender",     result.event.sender,     false}});
    }
    else
    {
        log_diagnostic("envelope.rejected", {{"reason", result.error, false}});
    }
    return result;
}

} // namespace merovingian::events
