// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/event.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::database
{

// One row of the `events` table, with its prev/auth edges and signatures. Held in memory by
// `EventTable` (event_table.hpp).
struct PersistentEvent final
{
    std::string event_id{};
    std::string room_id{};
    std::string sender_user_id{};
    std::string json{};
    std::uint64_t depth{0U};
    std::uint64_t stream_ordering{0U};
    std::vector<std::string> prev_event_ids{};
    std::vector<std::string> auth_event_ids{};
    std::vector<events::EventSignature> signatures{};
    // ADR-0064 receipt-order status: "accepted" | "soft_failed" | "rejected" |
    // "outlier". Appended as the last member (default "accepted") so every
    // pre-existing brace-init call site that does not mention it keeps
    // compiling. See database::set_event_status/find_event_status.
    std::string status{"accepted"};
};

} // namespace merovingian::database
