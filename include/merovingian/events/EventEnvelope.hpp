// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/EventSignature.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::events
{

struct EventEnvelope final
{
    canonicaljson::Value json{};
    std::string room_id{};
    std::string event_type{};
    std::string sender{};
    std::string state_key{};
    std::int64_t origin_server_ts{0};
    std::vector<EventSignature> signatures{};
};

} // namespace merovingian::events
