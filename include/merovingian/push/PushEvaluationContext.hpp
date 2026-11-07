// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace merovingian::push
{

// Contextual facts the evaluator needs beyond the event and ruleset, all of
// which the caller must already have computed (room state, member count,
// power levels) before calling evaluate_push_rules — this module never reads
// a database or does I/O.
struct PushEvaluationContext final
{
    std::string receiving_user_id{};
    std::string receiving_user_display_name{};
    std::uint64_t room_member_count{0U};
    std::int64_t sender_power_level{0};
    // Power level required to trigger a notification of a given
    // `sender_notification_permission` key (from the room's
    // m.room.power_levels `content.notifications` map). A key absent here
    // falls back to `default_notification_power_level`.
    std::unordered_map<std::string, std::int64_t> notification_power_levels{};
    std::int64_t default_notification_power_level{50};
};

} // namespace merovingian::push
