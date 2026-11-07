// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/RedactionResult.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <string>

namespace merovingian::events
{

[[nodiscard]] auto redact_event(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> RedactionResult;

} // namespace merovingian::events
