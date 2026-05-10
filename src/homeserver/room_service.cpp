// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/homeserver/vertical_slice.hpp>

#include "local_services.hpp"

#include <merovingian/trust_safety/policy_engine.hpp>

#include <algorithm>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{
namespace
{

[[nodiscard]] auto find_room(LocalDatabase& database, std::string_view room_id) -> LocalRoom*
{
    auto const iterator = std::ranges::find_if(database.rooms, [room_id](LocalRoom const& room) { return room.room_id == room_id; });
    return iterator == database.rooms.end() ? nullptr : &(*iterator);
}

[[nodiscard]] auto find_room(LocalDatabase const& database, std::string_view room_id) -> LocalRoom const*
{
    auto const iterator = std::ranges::find_if(database.rooms, [room_id](LocalRoom const& room) { return room.room_id == room_id; });
    return iterator == database.rooms.end() ? nullptr : &(*iterator);
}

[[nodiscard]] auto room_has_member(LocalRoom const& room, std::string_view user_id) noexcept -> bool
{
    return std::ranges::any_of(room.members, [user_id](std::string const& member) { return member == user_id; });
}

[[nodiscard]] auto make_event_id(HomeserverRuntime& runtime) -> std::string
{
    auto const sequence = runtime.database.next_event_id++;
    return "$event" + std::to_string(sequence) + ":" + runtime.config.server().server_name;
}

} // namespace

[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    auto const room_id = "!room" + std::to_string(runtime.database.rooms.size() + 1U) + ":" + runtime.config.server().server_name;
    auto const room_decision = trust_safety::evaluate_room_policy({room_id, false, false, {}});
    if (!room_decision.allowed)
    {
        return make_operation_result(false, {}, room_decision.reason.code);
    }

    runtime.database.rooms.push_back({room_id, *user_id, {*user_id}, {}});
    (void)database::store_room(runtime.database.persistent_store, {room_id, *user_id});
    (void)database::store_membership(runtime.database.persistent_store, {room_id, *user_id});
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.created", *user_id, room_id, "created");
    return make_operation_result(true, room_id);
}

[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id) -> OperationResult
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
        room->members.push_back(*user_id);
        (void)database::store_membership(runtime.database.persistent_store, {std::string{room_id}, *user_id});
    }

    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.joined", *user_id, room_id, "joined");
    return make_operation_result(true, std::string{room_id});
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
[[nodiscard]] auto send_event(
    HomeserverRuntime& runtime,
    std::string_view access_token,
    std::string_view room_id,
    std::string_view event_json
) -> OperationResult
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
    room->events.push_back(std::string{event_json});
    (void)database::store_event(runtime.database.persistent_store, {event_id, std::string{room_id}, *user_id, std::string{event_json}});
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.event_sent", *user_id, room_id, "stored");
    return make_operation_result(true, event_id);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

[[nodiscard]] auto fetch_room_state(
    HomeserverRuntime const& runtime,
    std::string_view access_token,
    std::string_view room_id
) -> OperationResult
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

    return make_operation_result(true, "room_id=" + room->room_id + " members=" + std::to_string(room->members.size()) + " events=" + std::to_string(room->events.size()));
}

[[nodiscard]] auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t
{
    return runtime.database.audit_events.size();
}

} // namespace merovingian::homeserver
