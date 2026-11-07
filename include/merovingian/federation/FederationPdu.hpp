// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/EventSignature.hpp"

#include <string>
#include <vector>

namespace merovingian::federation
{

struct FederationPdu final
{
    std::string event_id{};
    std::string room_id{};
    std::string event_type{};
    std::string sender{};
    std::vector<events::EventSignature> signatures{};
    std::string json{};
    // Room version resolved from the room's m.room.create state. Populated by
    // parse_federation_pdu when a room_version_resolver is provided; falls back
    // to "12" when the room is unknown or no resolver is wired.
    std::string room_version{"12"};
};

} // namespace merovingian::federation
