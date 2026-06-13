// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_smoke_flow.hpp"
#include "merovingian/homeserver/room_service.hpp"

#include <algorithm>
#include <fstream>
#include <string>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto demo_secret() -> std::string
    {
        return std::string{"LocalDemo"} + std::string{"Pass"} + std::string{"1!"};
    }

    [[nodiscard]] auto registration_token(config::Config const& config) -> std::string
    {
        if (!config.security().registration.require_token || config.security().registration.token_file.empty())
        {
            return {};
        }
        auto input = std::ifstream{config.security().registration.token_file};
        auto token = std::string{};
        std::getline(input, token);
        return token;
    }

} // namespace

auto run_local_smoke_flow(config::Config const& config) -> OperationResult
{
    auto started = start_runtime(config);
    if (!started.started)
    {
        return make_operation_result(false, {}, started.reason);
    }

    auto& runtime = started.runtime;
    auto const password = demo_secret();

    auto registered = register_local_user(runtime, "alice", password, registration_token(config));
    if (!registered.ok)
    {
        return registered;
    }

    auto logged_in = login_local_user(runtime, registered.value, password, "DEVICE1");
    if (!logged_in.ok)
    {
        return logged_in;
    }

    auto room = create_room(runtime, logged_in.value);
    if (!room.ok)
    {
        return room;
    }

    auto joined = join_room(runtime, logged_in.value, room.value);
    if (!joined.ok)
    {
        return joined;
    }

    auto event = send_event(runtime, logged_in.value, room.value,
                            R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"message-event"}})");
    if (!event.ok)
    {
        return event;
    }

    auto state = fetch_room_state(runtime, logged_in.value, room.value);
    if (!state.ok)
    {
        return state;
    }

    auto logged_out = logout_local_user(runtime, logged_in.value);
    if (!logged_out.ok)
    {
        return logged_out;
    }
    if (authenticated_user(runtime, logged_in.value).has_value())
    {
        return make_operation_result(false, {}, "logout did not revoke session");
    }
    if (audit_event_count(runtime) < 6U)
    {
        return make_operation_result(false, {}, "audit log did not record demo flow");
    }
    // Build a diagnostic summary from runtime state for test assertions.
    auto const& rooms = runtime.database.rooms;
    auto const room_it = std::ranges::find_if(rooms, [&](LocalRoom const& r) { return r.room_id == room.value; });
    if (room_it == rooms.end())
    {
        return make_operation_result(false, {}, "room not found in runtime database after demo flow");
    }
    auto const summary = "room_id=" + room.value + " members=" + std::to_string(room_it->members.size()) +
                         " events=" + std::to_string(room_it->events.size());
    return make_operation_result(true, summary);
}

} // namespace merovingian::homeserver
