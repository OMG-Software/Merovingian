// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// The room version an m.room.create event declares. A create event with no `room_version` is room
// version 1 ("1"; client-server-api.md, m.room.create), which this server does not support
// (ADR-0076). An event with no content object, or a `room_version` that is not a string, declares
// nothing usable: "", which is never a supported version. Never substitute a default version here.
[[nodiscard]] auto declared_room_version(canonicaljson::Object const& create_event) -> std::string;

// The version of a room as its stored m.room.create declares it, through declared_room_version.
// nullopt only when no m.room.create is stored for the room (an unknown room): a caller decides
// what that means for it. A create row whose event is missing or unparseable yields "".
//
// This is the one place the stored version is derived. Components that each read the create
// event with their own default ("10", "12") judged one room by different rule sets (security
// audit run-1).
[[nodiscard]] auto stored_room_version(database::PersistentStore const& store, std::string_view room_id)
    -> std::optional<std::string>;

// The policy for stored_room_version, or nullptr when the room is unknown or its version is not
// supported. A caller refuses the room on nullptr.
[[nodiscard]] auto stored_room_version_policy(database::PersistentStore const& store, std::string_view room_id)
    -> rooms::RoomVersionPolicy const*;

} // namespace merovingian::homeserver
