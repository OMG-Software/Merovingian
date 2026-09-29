// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <string_view>

namespace merovingian::federation
{

// Outcome of a room-scoped federation read (`/event`, `/state`, `/state_ids`,
// `/get_missing_events`). `forbidden` means the requesting server is not in the
// room and the room is not world readable (FED-2); the inbound handler answers
// it with 403 M_FORBIDDEN and no room data.
enum class RoomReadStatus : unsigned char
{
    ok,
    forbidden,
    not_found,
    malformed,
};

struct RoomReadResult final
{
    RoomReadStatus status{RoomReadStatus::not_found};
    // The canonical-JSON response body. Non-empty only when `status` is `ok`.
    std::string body{};
};

// Wire names for the worker -> main relay of `/event` (worker_event_loop.cpp,
// worker_pool.cpp). An unrecognised or missing name reads as `not_found`, so a
// frame that lost its status can never be mistaken for a served response.
[[nodiscard]] constexpr auto room_read_status_name(RoomReadStatus status) noexcept -> std::string_view
{
    switch (status)
    {
    case RoomReadStatus::ok:
        return "ok";
    case RoomReadStatus::forbidden:
        return "forbidden";
    case RoomReadStatus::malformed:
        return "malformed";
    case RoomReadStatus::not_found:
        break;
    }
    return "not_found";
}

[[nodiscard]] constexpr auto room_read_status_from_name(std::string_view name) noexcept -> RoomReadStatus
{
    if (name == "ok")
    {
        return RoomReadStatus::ok;
    }
    if (name == "forbidden")
    {
        return RoomReadStatus::forbidden;
    }
    if (name == "malformed")
    {
        return RoomReadStatus::malformed;
    }
    return RoomReadStatus::not_found;
}

} // namespace merovingian::federation
