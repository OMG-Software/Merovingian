// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_state_group.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{
struct PersistentStore;
} // namespace merovingian::database

namespace merovingian::homeserver
{

struct HomeserverRuntime;

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

// The caps a send_join answer has to fit: `join_response_max_size` for the body, the size an
// operator accepts a join response at (and the size this server accepts when IT joins), and the
// frame cap of the channel to the federation workers.
struct SendJoinAnswerLimits final
{
    std::uint64_t max_body_bytes{0U};
    std::uint64_t max_frame_bytes{0U};
};

[[nodiscard]] auto send_join_answer_limits(config::Config const& config) -> SendJoinAnswerLimits;

// The room's current state, from the rows of that room alone (ADR-0344): what a join accepted now
// is answered with.
[[nodiscard]] auto current_room_state_entries(database::PersistentStore const& store, std::string_view room_id)
    -> std::vector<database::PersistentStateGroupStateEntry>;

// Plans the answer to a send_join for `joining_user` into `room_id`, from this server's state
// (`runtime.mutex` held). `state` is the resolved room state before the join. `join_auth_event_ids`
// are the auth events of the join event, whose chain the answer must carry. With `omit_members`
// (server-server-api.md PUT /send_join, query parameter): the state leaves out `m.room.member`
// events, except, when the room has no `m.room.name` and no `m.room.canonical_alias`, those of
// the heroes (the first five joined members other than the joiner, in the roster's order), whose
// auth chains the answer carries too. Cost: the room's own state entries and its auth DAG; nothing
// that grows with other rooms.
[[nodiscard]] auto plan_send_join_answer(HomeserverRuntime const& runtime, std::string_view room_id,
                                         std::string_view joining_user,
                                         std::vector<database::PersistentStateGroupStateEntry> const& state,
                                         std::span<std::string const> join_auth_event_ids, bool omit_members)
    -> SendJoinAnswerPlan;

// Whether the planned answer fits both caps.
[[nodiscard]] auto send_join_answer_fits(SendJoinAnswerPlan const& plan, SendJoinAnswerLimits const& limits) noexcept
    -> bool;

// The JSON of the events a plan names, in the plan's order, copied once each.
struct SendJoinAnswerEvents final
{
    std::vector<std::string> state_json{};
    std::vector<std::string> auth_chain_json{};
};

[[nodiscard]] auto collect_send_join_answer(database::PersistentStore const& store, std::string_view room_id,
                                            SendJoinAnswerPlan const& plan) -> SendJoinAnswerEvents;

// The reason a send_join is refused (503) when its answer would not fit. It says how a caller that
// can accept a reduced answer gets one.
inline constexpr std::string_view send_join_answer_too_large_reason{
    "the answer to this join is larger than this server can send; retry with omit_members=true"};

// Heroes in a send_join answer: at most this many members' events are added to a reduced state.
inline constexpr std::size_t max_send_join_heroes{5U};

} // namespace merovingian::homeserver
