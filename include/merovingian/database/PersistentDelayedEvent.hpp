// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/DelayedEventStatus.hpp"

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Migration 003 (ADR-0824): one delayed event (`delayed_events`), an event a user scheduled to be sent later
// (MSC4140). `device_id` is the scheduling request's device, empty when its token had none; `txn_id` is empty for
// the legacy state form, which has none; `via_appservice` records that an application service scheduled it, which the
// send passes on. `delayed_since_ms` is when the timer last started: the event is due at `delayed_since_ms +
// delay_ms`. `finalised_at_ms` is 0 while scheduled; `event_id` is empty unless sent; `error_json` is empty unless
// failed and then holds the standard error object. Times are wall-clock milliseconds since the Unix epoch. A row
// never changes except through `DelayedEventTable`.
struct PersistentDelayedEvent final
{
    std::string delay_id{};
    std::string user_id{};
    std::string device_id{};
    std::string room_id{};
    std::string event_type{};
    bool is_state{false};
    std::string state_key{};
    std::string content_json{};
    std::string txn_id{};
    bool via_appservice{false};
    std::uint64_t delay_ms{0U};
    std::uint64_t delayed_since_ms{0U};
    DelayedEventStatus status{DelayedEventStatus::scheduled};
    std::uint64_t finalised_at_ms{0U};
    std::string event_id{};
    std::string error_json{};
};

} // namespace merovingian::database
