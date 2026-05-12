// SPDX-License-Identifier: GPL-3.0-or-later

#include "local_services.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

#include <merovingian/homeserver/vertical_slice.hpp>
#include <merovingian/trust_safety/policy_engine.hpp>

namespace merovingian::homeserver
{
namespace
{

    struct LocalStateFields final
    {
        std::string event_type{};
        std::string state_key{};
    };

    [[nodiscard]] auto find_room(LocalDatabase& database, std::string_view room_id) -> LocalRoom*
    {
        auto const iterator = std::ranges::find_if(database.rooms, [room_id](LocalRoom const& room) {
            return room.room_id == room_id;
        });
        return iterator == database.rooms.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto find_room(LocalDatabase const& database, std::string_view room_id) -> LocalRoom const*
    {
        auto const iterator = std::ranges::find_if(database.rooms, [room_id](LocalRoom const& room) {
            return room.room_id == room_id;
        });
        return iterator == database.rooms.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto room_has_member(LocalRoom const& room, std::string_view user_id) noexcept -> bool
    {
        return std::ranges::any_of(room.members, [user_id](std::string const& member) {
            return member == user_id;
        });
    }

    [[nodiscard]] auto make_event_id(HomeserverRuntime& runtime) -> std::string
    {
        auto const sequence = runtime.database.next_event_id++;
        return "$event" + std::to_string(sequence) + ":" + runtime.config.server().server_name;
    }

    [[nodiscard]] auto is_json_space(char value) noexcept -> bool
    {
        return value == ' ' || value == '\n' || value == '\r' || value == '\t';
    }

    auto skip_json_space(std::string_view input, std::size_t& cursor) noexcept -> void
    {
        while (cursor < input.size() && is_json_space(input[cursor]))
        {
            ++cursor;
        }
    }

    [[nodiscard]] auto parse_json_string(std::string_view input, std::size_t& cursor) -> std::optional<std::string>
    {
        if (cursor >= input.size() || input[cursor] != '"')
        {
            return std::nullopt;
        }
        ++cursor;
        auto output = std::string{};
        while (cursor < input.size())
        {
            auto const character = input[cursor++];
            if (character == '"')
            {
                return output;
            }
            if (character == '\\')
            {
                if (cursor >= input.size())
                {
                    return std::nullopt;
                }
                auto const escaped = input[cursor++];
                if (escaped == '"' || escaped == '\\' || escaped == '/')
                {
                    output.push_back(escaped);
                }
                else if (escaped == 'n')
                {
                    output.push_back('\n');
                }
                else if (escaped == 'r')
                {
                    output.push_back('\r');
                }
                else if (escaped == 't')
                {
                    output.push_back('\t');
                }
                else
                {
                    return std::nullopt;
                }
            }
            else
            {
                output.push_back(character);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto top_level_json_string_field(std::string_view json, std::string_view field_name)
        -> std::optional<std::string>
    {
        auto cursor = std::size_t{0U};
        skip_json_space(json, cursor);
        if (cursor >= json.size() || json[cursor] != '{')
        {
            return std::nullopt;
        }
        ++cursor;
        while (cursor < json.size())
        {
            skip_json_space(json, cursor);
            if (cursor < json.size() && json[cursor] == '}')
            {
                return std::nullopt;
            }
            auto const key = parse_json_string(json, cursor);
            if (!key.has_value())
            {
                return std::nullopt;
            }
            skip_json_space(json, cursor);
            if (cursor >= json.size() || json[cursor] != ':')
            {
                return std::nullopt;
            }
            ++cursor;
            skip_json_space(json, cursor);
            if (*key == field_name)
            {
                return parse_json_string(json, cursor);
            }
            if (!parse_json_string(json, cursor).has_value())
            {
                return std::nullopt;
            }
            skip_json_space(json, cursor);
            if (cursor < json.size() && json[cursor] == ',')
            {
                ++cursor;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto state_fields_from_event(std::string_view event_json) -> std::optional<LocalStateFields>
    {
        auto const event_type = top_level_json_string_field(event_json, "type");
        auto const state_key = top_level_json_string_field(event_json, "state_key");
        if (!event_type.has_value() || !state_key.has_value())
        {
            return std::nullopt;
        }
        return LocalStateFields{*event_type, *state_key};
    }

} // namespace

[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    auto const room_id =
        "!room" + std::to_string(runtime.database.rooms.size() + 1U) + ":" + runtime.config.server().server_name;
    auto const room_decision = trust_safety::evaluate_room_policy({room_id, false, false, {}});
    if (!room_decision.allowed)
    {
        return make_operation_result(false, {}, room_decision.reason.code);
    }

    if (!database::store_room(runtime.database.persistent_store, {room_id, *user_id}) ||
        !database::store_membership(runtime.database.persistent_store, {room_id, *user_id}))
    {
        return make_operation_result(false, {}, "room persistence failed", 500U);
    }
    runtime.database.rooms.push_back({room_id, *user_id, {*user_id}, {}});
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.created", *user_id, room_id,
                       "created");
    return make_operation_result(true, room_id);
}

[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        if (!database::store_membership(runtime.database.persistent_store, {std::string{room_id}, *user_id}))
        {
            return make_operation_result(false, {}, "membership persistence failed", 500U);
        }
        room->members.push_back(*user_id);
    }

    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.joined", *user_id, room_id,
                       "joined");
    return make_operation_result(true, std::string{room_id});
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
[[nodiscard]] auto send_event(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view event_json) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "not joined");
    }
    if (event_json.empty())
    {
        return make_operation_result(false, {}, "empty event");
    }

    auto const event_id = make_event_id(runtime);
    if (!database::store_event(runtime.database.persistent_store,
                               {event_id, std::string{room_id}, *user_id, std::string{event_json}}))
    {
        return make_operation_result(false, {}, "event persistence failed", 500U);
    }
    if (auto const state_fields = state_fields_from_event(event_json); state_fields.has_value())
    {
        if (!database::store_state(runtime.database.persistent_store,
                                   {std::string{room_id}, state_fields->event_type, state_fields->state_key, event_id}))
        {
            return make_operation_result(false, {}, "state persistence failed", 500U);
        }
    }
    room->events.push_back(std::string{event_json});
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.event_sent", *user_id, room_id,
                       "stored");
    return make_operation_result(true, event_id);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

[[nodiscard]] auto fetch_room_state(HomeserverRuntime const& runtime, std::string_view access_token,
                                    std::string_view room_id) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    auto const* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "not joined");
    }

    return make_operation_result(true, "room_id=" + room->room_id + " members=" + std::to_string(room->members.size()) +
                                           " events=" + std::to_string(room->events.size()));
}

[[nodiscard]] auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t
{
    return runtime.database.audit_events.size();
}

} // namespace merovingian::homeserver
