// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Migration 004 (ADR-0832): one delegation (`livekit_delegations`) of a delayed `m.rtc.member` leave event to the
// LiveKit token service (MSC4195 `delegate_delayed_leave`). While the user's LiveKit participant is connected the
// server keeps the delayed event (`delay_id`, a `delayed_events.delay_id`) alive. One row per (user, room, slot,
// member). `created_ms` is wall-clock milliseconds since the Unix epoch. A row never changes except through
// `LiveKitDelegationTable`.
struct PersistentLiveKitDelegation final
{
    std::string delay_id{};
    std::string user_id{};
    std::string room_id{};
    std::string slot_id{};
    std::string member_id{};
    std::uint64_t created_ms{0U};
};

} // namespace merovingian::database
