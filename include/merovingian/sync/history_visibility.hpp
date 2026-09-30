// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::sync
{

// The four values of `m.room.history_visibility`'s `history_visibility`.
enum class HistoryVisibilityValue
{
    world_readable,
    shared,
    invited,
    joined,
};

// Maps the wire value to the enum. Spec (client-server-api.md, "Room History Visibility",
// server behaviour): "if no `history_visibility` is set, or if the value is not understood,
// the visibility is assumed to be `shared`", so anything unrecognised is `shared`.
[[nodiscard]] auto parse_history_visibility(std::string_view value) noexcept -> HistoryVisibilityValue;

// The room's CURRENT visibility, read from the current-state table. `shared` when the room
// has no `m.room.history_visibility` event. Only for gating who may reach a read endpoint at
// all (peeking a `world_readable` room); it never decides whether one event is visible.
[[nodiscard]] auto current_history_visibility(database::PersistentStore const& store,
                                              std::string_view room_id) -> HistoryVisibilityValue;

// True when the room's current visibility is `world_readable`.
[[nodiscard]] auto room_is_world_readable(database::PersistentStore const& store, std::string_view room_id) -> bool;

// Decides, for one requesting user, which room events that user may see. This is THE rule
// every client read path that returns room events applies (ADR-0084); do not re-derive it.
//
// Spec (client-server-api.md, "Room History Visibility", server behaviour): the rules depend
// on the state of the room AT the event.
//   1. `world_readable`: allow.
//   2. the user's membership was `join`: allow.
//   3. `shared`, and the user joined at any point after the event was sent: allow.
//   4. the user's membership was `invite` and the visibility was `invited`: allow.
//   5. otherwise deny.
// Two special cases: an `m.room.history_visibility` event is visible if the visibility before
// OR after it allows, and the user's own `m.room.member` event is visible if their membership
// before OR after it allows.
//
// "State at the event" is the state group recorded for the event (ADR-0064), i.e. the state
// immediately after it. "Before" for the two special cases is the predecessor recorded in
// `state_transitions`. "After the event" is stream ordering.
//
// One instance serves one request: it caches per state group, so a page of events costs one
// state lookup per distinct group rather than one per event, and it builds its indexes over
// the store lazily on first use. It is not thread-safe and must not outlive the store
// reference or the runtime lock the caller holds.
//
// An event with NO state group (history stored before ADR-0064) cannot have its visibility at
// the time proved, so only rule 2 applies, from the user's own membership timeline: it is
// visible when their latest membership at or before the event was `join`. Rule 2 allows an event
// under every visibility, so this only ever shows a subset of what the spec allows. Events that
// have a state group get the full check.
//
// It fails closed: an event with a broken group chain, whose membership or visibility event
// cannot be found, or (with no state group) whose user's membership timeline cannot be followed,
// is not visible.
class HistoryVisibility final
{
public:
    HistoryVisibility(database::PersistentStore const& store, std::string_view user_id);

    // True when the user may see `event`.
    [[nodiscard]] auto can_see(database::PersistentEvent const& event) -> bool;

    // True when `event_id` names a stored event the user may see; false for an unknown ID.
    [[nodiscard]] auto can_see_event_id(std::string_view event_id) -> bool;

private:
    struct GroupView final
    {
        bool valid{false};
        HistoryVisibilityValue visibility{HistoryVisibilityValue::shared};
        std::string membership{};
    };

    enum class Lookup
    {
        found,
        absent,
        broken,
    };

    struct LookupResult final
    {
        Lookup outcome{Lookup::broken};
        std::string_view event_id{};
    };

    [[nodiscard]] auto find_event(std::string_view event_id) -> database::PersistentEvent const*;
    [[nodiscard]] auto state_group_of(std::string_view event_id) -> std::optional<std::string_view>;
    [[nodiscard]] auto lookup_in_group(std::string_view group_id, std::string_view event_type,
                                       std::string_view state_key) -> LookupResult;
    [[nodiscard]] auto view_of_group(std::string_view group_id) -> GroupView const&;
    [[nodiscard]] auto content_string(std::string_view event_id, std::string_view key) -> std::optional<std::string>;
    [[nodiscard]] auto max_join_ordering(std::string_view room_id) -> std::optional<std::uint64_t>;
    // One entry of the user's own membership in a room: the stream ordering of an
    // m.room.member event of theirs and the membership it set.
    struct MembershipStep final
    {
        std::uint64_t ordering{0U};
        std::string membership{};
    };
    // The user's membership timeline in `room_id`, oldest first, from the chain of their
    // m.room.member events; nullopt when the chain cannot be followed.
    [[nodiscard]] auto membership_timeline(std::string_view room_id)
        -> std::optional<std::vector<MembershipStep>> const&;
    // Rule 2 alone, for an event with no state group: was the user's latest membership at or
    // before the event's position `join`?
    [[nodiscard]] auto joined_when_sent(database::PersistentEvent const& event) -> bool;
    [[nodiscard]] auto allows(HistoryVisibilityValue visibility, std::string_view membership,
                              database::PersistentEvent const& event) -> bool;
    auto ensure_event_index() -> void;
    auto ensure_event_group_index() -> void;
    auto ensure_group_index() -> void;

    database::PersistentStore const& store_;
    std::string user_id_;

    bool event_index_built_{false};
    std::unordered_map<std::string_view, database::PersistentEvent const*> events_by_id_{};
    bool event_group_index_built_{false};
    std::unordered_map<std::string_view, std::string_view> group_by_event_{};
    bool group_index_built_{false};
    std::unordered_map<std::string_view, database::PersistentStateGroup const*> groups_by_id_{};
    std::unordered_map<std::string_view, std::vector<database::PersistentStateGroupStateEntry const*>>
        entries_by_group_{};

    std::unordered_map<std::string, GroupView> group_views_{};
    std::unordered_map<std::string, std::optional<std::string>> content_cache_{};
    std::unordered_map<std::string, std::optional<std::uint64_t>> join_orderings_{};
    std::unordered_map<std::string, std::optional<std::vector<MembershipStep>>> membership_timelines_{};
};

} // namespace merovingian::sync
