// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/StateKey.hpp"

#include <cstdint>
#include <string>

namespace merovingian::events
{

struct StateEventReference final
{
    StateKey key{};
    std::string event_id{};
    std::string sender{};
    std::int64_t origin_server_ts{0};
    std::uint64_t depth{0};
    canonicaljson::Value event_json{};
    // Trusted receipt metadata, never read from event JSON. Rejected events
    // remain available to auth-chain walks but cannot supply own-auth fallback.
    bool rejected{false};
};

} // namespace merovingian::events
