// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/Config.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::homeserver
{

// What a resident's answer to PUT /send_join holds, as event IDs, and how big it will be (F-23).
// Planned BEFORE the join is stored, so a join whose answer cannot be delivered is refused with
// nothing stored and nothing sent on; the events themselves are copied out only once the join is
// accepted (`collect_send_join_answer`).
struct SendJoinAnswerPlan final
{
    // The `state` of the answer: the room's resolved state before the join. With `omit_members`,
    // membership events are left out except the heroes' (below).
    std::vector<std::string> state_event_ids{};
    // The `auth_chain`: every event the joining event's auth events and the returned state events
    // are authorised by. Without `omit_members` it also repeats the state events themselves (as
    // this server has always answered); with it, "any events that are returned in `state` may be
    // omitted from `auth_chain`", and are.
    std::vector<std::string> auth_chain_event_ids{};
    // True when `omit_members` was requested and a membership event was left out of `state`.
    bool members_omitted{false};
    // "A list of the servers active in the room (ie, those with joined members) before the
    // join." Required, and filled, only when `members_omitted`.
    std::vector<std::string> servers_in_room{};
    // The events of the two lists that this server holds (an ID it holds no JSON for is skipped,
    // as it always was) and the bytes of their JSON.
    std::size_t event_count{0U};
    std::uint64_t event_json_bytes{0U};
    // Bytes of the HTTP response body this answer becomes, and of the largest IPC frame it
    // crosses: main's `membership_ingest_result`, in which each event is a JSON string. A string
    // at most doubles (every byte of a canonical event can be a `"` or a `\`), so the frame is
    // projected at twice the event bytes. Upper bounds, headroom included.
    std::uint64_t projected_body_bytes{0U};
    std::uint64_t projected_frame_bytes{0U};
};

} // namespace merovingian::homeserver
