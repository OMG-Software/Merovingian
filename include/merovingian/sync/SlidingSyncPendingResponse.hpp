// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncList.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::sync
{

// State produced for a response but not yet acknowledged by a later request.
// A retry can carry the same position as both this response and its request,
// so request_pos distinguishes that retry from a genuine acknowledgement.
struct SlidingSyncPendingResponse final
{
    std::string request_pos{};
    std::string response_pos{};
    std::map<std::string, std::vector<std::string>> list_prev_windows{};
    std::unordered_map<std::string, std::uint64_t> rooms_seen{};
    // Candidate lazy-loaded ("$LAZY") member user_ids per room; see
    // SlidingSyncConnectionState::lazy_members_sent.
    std::unordered_map<std::string, std::unordered_set<std::string>> lazy_members_sent{};
    // See SlidingSyncConnectionState::room_timeline_limits and list_configs.
    std::unordered_map<std::string, std::uint64_t> room_timeline_limits{};
    std::map<std::string, SlidingSyncList> list_configs{};
    // Rooms whose grown timeline_limit this response answered at once instead of long-polling,
    // with the limit it answered. A request carrying the same pos as this response's request may
    // be a retry, so the expansion is still built from the committed state, but it does not skip
    // the long-poll a second time; otherwise a pos that no stream advanced would spin the client.
    std::unordered_map<std::string, std::uint64_t> expansions_answered{};
    std::uint64_t last_event_ordering{0U};
    std::uint64_t last_sync_stream_id{0U};
};

} // namespace merovingian::sync
