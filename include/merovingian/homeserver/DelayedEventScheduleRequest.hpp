// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

// A request to schedule a delayed event (MSC4140), after the route has parsed it. `content_json` is the serialised
// JSON object the event will carry. `state_key` is set for a state event (an empty value is the empty state key).
// `txn_id` is empty for the legacy state form, which has none. `device_id` is the scheduling request's device, empty
// when its token has none. `via_appservice` is set when an application service asserted the sender (the send passes
// it on). `stable_errcode` selects the errcode of a too-large delay: `M_DELAY_TOO_LARGE` when set,
// `ORG.MATRIX.MSC4140_DELAY_TOO_LARGE` otherwise.
struct DelayedEventScheduleRequest final
{
    std::string user_id{};
    std::string device_id{};
    std::string room_id{};
    std::string event_type{};
    std::optional<std::string> state_key{};
    std::string content_json{};
    std::string txn_id{};
    std::uint64_t delay_ms{0U};
    bool via_appservice{false};
    bool stable_errcode{false};
};

} // namespace merovingian::homeserver
