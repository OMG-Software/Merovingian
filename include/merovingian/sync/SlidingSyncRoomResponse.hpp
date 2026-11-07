// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncHero.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace merovingian::sync
{

// MSC4186 §rooms[roomId] — per-room data included in the response.
struct SlidingSyncRoomResponse final
{
    std::optional<std::string> name{};
    std::optional<std::string> avatar{};
    // True the first time this room appears in a response for this connection.
    bool initial{false};
    bool is_dm{false};
    std::optional<std::uint64_t> joined_count{};
    std::optional<std::uint64_t> invited_count{};
    std::optional<std::uint64_t> notification_count{};
    std::optional<std::uint64_t> highlight_count{};
    // Number of trailing timeline events newer than the connection's last send of the room; 0 for
    // a room's first send, whose events are all historical to the connection.
    std::uint64_t num_live{0U};
    // MSC4186 `limited`: older events exist that the timeline does not hold, so the client must
    // paginate (`prev_batch`) to show them. Serialised only when true ("Absence means false").
    bool limited{false};
    // MSC4186 `prev_batch`: the `from` for /rooms/{roomId}/messages?dir=b that returns the events
    // just before the timeline — a plain stream ordering, as /v3/sync's prev_batch.
    std::optional<std::string> prev_batch{};
    // MSC4186 `expanded_timeline`: the timeline resends events from before the connection's last
    // send of the room because the timeline_limit grew. Serialised only when true.
    bool expanded_timeline{false};
    // origin_server_ts of the most recent event; 0 if unknown.
    std::uint64_t timestamp{0U};
    std::vector<SlidingSyncHero> heroes{};
    // Pre-serialised state event JSON objects matching required_state.
    std::vector<std::string> required_state_json{};
    // Pre-serialised timeline event JSON objects (chronological order).
    std::vector<std::string> timeline_json{};
    // Set for invited rooms in place of timeline/state: a pre-serialised JSON array of the
    // invite's stripped state events, emitted as `invite_state`.
    std::optional<std::string> invite_state_json{};
    // User IDs whose m.room.member event was included in required_state_json
    // because required_state named ["m.room.member","$LAZY"] and that user is
    // relevant to this response (sent or is the subject of a timeline event
    // returned this call). Server-internal bookkeeping only — never
    // serialised to the client. The caller merges this into the connection's
    // committed lazy_members_sent[room_id] so a later response for the same
    // member doesn't bypass the delta floor again.
    std::unordered_set<std::string> lazy_members_included{};
};

} // namespace merovingian::sync
