// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/Config.hpp"
#include "merovingian/database/PersistentStateGroupStateEntry.hpp"
#include "merovingian/homeserver/SendJoinAnswerEvents.hpp"
#include "merovingian/homeserver/SendJoinAnswerLimits.hpp"
#include "merovingian/homeserver/SendJoinAnswerPlan.hpp"
#include "merovingian/homeserver/SendJoinResend.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
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

[[nodiscard]] auto send_join_answer_limits(config::Config const& config) -> SendJoinAnswerLimits;

// The room's current state, from the rows of that room alone (ADR-0344): what a join accepted now
// is answered with.
[[nodiscard]] auto current_room_state_entries(database::PersistentStore const& store, std::string_view room_id)
    -> std::vector<database::PersistentStateGroupStateEntry>;

// What a join already stored is answered with when it is sent again (ADR-0372): the room's current
// state, as the first answer was, so the answer is never older than the first. The joiner's own
// membership goes back to `state_before_join` only where the join itself is the current row: a row
// that is not the join (a ban that soft-failed it, a later leave) stays. `runtime.mutex` held.
[[nodiscard]] auto resent_send_join_state(
    database::PersistentStore const& store, std::string_view room_id, std::string_view joining_user,
    std::string_view join_event_id, std::vector<database::PersistentStateGroupStateEntry> const& state_before_join)
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

// The plan the acceptor uses (ADR-0624): the same answer as `plan_send_join_answer` over current state, or for a
// `resend` over `resent_send_join_state`, with the room-wide part taken from `runtime.send_join_plan_cache`, so
// a request pays only for what it changes. An answer that does not fit comes back with its sizes and empty lists.
// `runtime.mutex` held.
[[nodiscard]] auto plan_send_join_answer_cached(HomeserverRuntime const& runtime, std::string_view room_id,
                                                std::string_view joining_user,
                                                std::optional<SendJoinResend> const& resend,
                                                std::span<std::string const> join_auth_event_ids, bool omit_members,
                                                SendJoinAnswerLimits const& limits) -> SendJoinAnswerPlan;

// True when the cache already knows the room's answer cannot fit, whoever asks. Lets a resend be refused before it
// looks for the state before its join. `runtime.mutex` held.
[[nodiscard]] auto send_join_answer_known_not_to_fit(HomeserverRuntime const& runtime, std::string_view room_id,
                                                     bool omit_members, SendJoinAnswerLimits const& limits) -> bool;

// Whether the planned answer fits both caps.
[[nodiscard]] auto send_join_answer_fits(SendJoinAnswerPlan const& plan, SendJoinAnswerLimits const& limits) noexcept
    -> bool;

[[nodiscard]] auto collect_send_join_answer(database::PersistentStore const& store, std::string_view room_id,
                                            SendJoinAnswerPlan const& plan) -> SendJoinAnswerEvents;

// The reason a send_join is refused (503) when its answer would not fit. It says how a caller that
// can accept a reduced answer gets one.
inline constexpr std::string_view send_join_answer_too_large_reason{
    "the answer to this join is larger than this server can send; retry with omit_members=true"};

// Heroes in a send_join answer: at most this many members' events are added to a reduced state.
inline constexpr std::size_t max_send_join_heroes{5U};

} // namespace merovingian::homeserver
