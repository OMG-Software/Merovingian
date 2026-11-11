// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

// The part of a send_join answer that depends only on the room's state, not on who is joining (ADR-0624). Building it
// walks the room's state and auth DAG; `SendJoinAnswer.cpp` then turns it into one request's plan by looking only at
// what that request changes (its join's own auth events, a resent join's own state row, the heroes).
struct SendJoinPlanBase final
{
    bool omit_members{false};
    // True when the answer cannot fit whatever the request adds or takes away. The lists below are then empty: only the
    // verdict is kept, so a room whose answer is refused costs almost nothing to remember.
    bool sizes_only{false};

    // The state entries returned, in row order. With omit_members, without the membership events.
    std::vector<std::string> state_event_ids{};
    // Membership events the state held, counted only with omit_members.
    std::size_t omitted_members{0U};
    // The auth chain: the events the auth walk reached from `state_event_ids` that this server holds JSON for, in the
    // order it reached them. With omit_members, without the events of `state_event_ids`.
    std::vector<std::string> chain_event_ids{};
    // Every event the walk reached and its JSON size: 0 for an event this server holds no JSON for.
    std::unordered_map<std::string, std::uint64_t> known{};
    // The events that an event of the walk names in its `auth_events`.
    std::unordered_set<std::string> cited{};
    // Events the walk named and this server does not hold. The base goes stale if one arrives.
    std::vector<std::string> missing{};

    // Bytes and counts of the events in `state_event_ids` and `chain_event_ids`, leaving out those with no JSON. With
    // `sizes_only`, `state_bytes` and `state_entries` hold the least the answer can come to.
    std::uint64_t state_bytes{0U};
    std::uint64_t state_entries{0U};
    std::uint64_t chain_bytes{0U};
    std::uint64_t chain_entries{0U};

    // From the room's roster, with omit_members only.
    bool room_on_roster{false};
    bool room_is_named{false};
    // The first roster members, enough for the heroes after skipping the joiner, and the membership rows of those
    // members as (user, event ID), in row order.
    std::vector<std::string> first_members{};
    std::vector<std::pair<std::string, std::string>> hero_candidates{};
    // The servers of the roster's members, in first-seen order, and how many members each has.
    std::vector<std::string> servers{};
    std::unordered_map<std::string, std::size_t> server_members{};
    std::uint64_t servers_bytes{0U};

    // A rough size of what this holds, for the cache's byte budget.
    [[nodiscard]] auto estimated_bytes() const noexcept -> std::uint64_t
    {
        constexpr auto per_id = std::uint64_t{160U};
        return per_id * (state_event_ids.size() + chain_event_ids.size() + known.size() + cited.size() +
                         missing.size() + (2U * servers.size()) + first_members.size() + hero_candidates.size() + 1U);
    }
};

} // namespace merovingian::homeserver
