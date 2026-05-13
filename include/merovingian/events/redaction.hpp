// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <string>

namespace merovingian::events
{

struct RedactionResult final
{
    canonicaljson::Value event{};
    std::string error{};
};

[[nodiscard]] auto redact_event(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> RedactionResult;

} // namespace merovingian::events
