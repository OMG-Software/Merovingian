// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/StateBookkeeping.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/FederationStateResolutionConfig.hpp"
#include "merovingian/database/ResolvedStateMemo.hpp"
#include "merovingian/events/Authorization.hpp"
#include "merovingian/events/StateEventReference.hpp"
#include "merovingian/events/StateKey.hpp"
#include "merovingian/events/StateResolutionRequest.hpp"
#include "merovingian/events/Limits.hpp"
#include "merovingian/events/StateResolution.hpp"
#include "merovingian/homeserver/CurrentStateRecompute.hpp"
#include "merovingian/homeserver/CurrentStateRecomputeStatus.hpp"
#include "merovingian/homeserver/EventBookkeeping.hpp"
#include "merovingian/homeserver/NewEventBasis.hpp"
#include "merovingian/homeserver/StateBeforeResult.hpp"
#include "merovingian/homeserver/StoredWithBookkeeping.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace merovingian::homeserver
{

auto state_resolution_limits(config::FederationStateResolutionConfig const& config) -> events::StateResolutionLimits
{
    auto limits = events::StateResolutionLimits{};
    limits.max_state_groups = static_cast<std::size_t>(config.max_state_groups);
    limits.max_events_per_state_group = static_cast<std::size_t>(config.max_events_per_state_group);
    limits.max_conflicted_state_keys = static_cast<std::size_t>(config.max_conflicted_state_keys);
    limits.max_mainline_auth_chain_depth = static_cast<std::size_t>(config.max_mainline_auth_chain_depth);
    limits.max_auth_chain_walk_events = static_cast<std::size_t>(config.max_auth_chain_walk_events);
    limits.max_total_state_events = static_cast<std::size_t>(config.max_total_state_events);
    limits.max_state_tips_per_server = static_cast<std::size_t>(config.max_state_tips_per_server);
    return limits;
}

namespace
{

    [[nodiscard]] auto find_string_member(canonicaljson::Object const& object, std::string_view key)
        -> std::string const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return std::get_if<std::string>(&member.value->storage());
            }
        }
        return nullptr;
    }

    // Parses `json` and builds the events::StateEventReference the state-res v2
    // auth-chain walk expects.
    [[nodiscard]] auto parse_state_event_reference(std::string_view event_id, std::string_view json,
                                                   std::uint64_t depth) -> std::optional<events::StateEventReference>
    {
        auto const parsed = canonicaljson::parse_lossless(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (obj == nullptr)
        {
            return std::nullopt;
        }
        auto const* type = find_string_member(*obj, "type");
        auto const* state_key = find_string_member(*obj, "state_key");
        if (type == nullptr || state_key == nullptr)
        {
            return std::nullopt; // not a state event
        }
        auto const* sender = find_string_member(*obj, "sender");

        auto ref = events::StateEventReference{};
        ref.key = events::StateKey{*type, *state_key};
        ref.event_id = std::string{event_id};
        ref.sender = sender != nullptr ? *sender : std::string{};
        ref.origin_server_ts = 0;
        for (auto const& member : *obj)
        {
            if (member.key == "origin_server_ts")
            {
                if (auto const* ts = std::get_if<std::int64_t>(&member.value->storage()); ts != nullptr)
                {
                    ref.origin_server_ts = *ts;
                }
                break;
            }
        }
        ref.depth = depth;
        ref.event_json = parsed.value;
        return ref;
    }

    // Converts a state group's stored entries (event_type/state_key -> event_id
    // rows) into the events::StateEventReference list resolve_state_v2 expects,
    // using `lookup` to fetch each referenced event's own JSON. Fails closed
    // (nullopt) if any entry's event cannot be resolved: a partial state group
    // must never be handed to the resolver as if it were complete.
    [[nodiscard]] auto to_state_event_references(std::vector<database::PersistentStateGroupStateEntry> const& entries,
                                                 events::EventLookupFn const& lookup)
        -> std::optional<std::vector<events::StateEventReference>>
    {
        auto refs = std::vector<events::StateEventReference>{};
        refs.reserve(entries.size());
        for (auto const& entry : entries)
        {
            auto ref = lookup(entry.event_id);
            if (!ref.has_value())
            {
                return std::nullopt;
            }
            refs.push_back(std::move(*ref));
        }
        return refs;
    }

    using ParsedEvents = std::unordered_map<std::string, std::optional<events::StateEventReference>>;

    // `lookup`, parsing each event at most once however many state groups name it. The result refers to `parsed`,
    // which must outlive it: one resolution, never longer, since a stored event can be redacted between resolutions.
    [[nodiscard]] auto parse_once(events::EventLookupFn lookup, ParsedEvents& parsed) -> events::EventLookupFn
    {
        return
            [lookup = std::move(lookup), &parsed](std::string_view id) -> std::optional<events::StateEventReference> {
                auto const key = std::string{id};
                if (auto const held = parsed.find(key); held != parsed.end())
                {
                    return held->second;
                }
                return parsed.emplace(key, lookup(id)).first->second;
            };
    }

    [[nodiscard]] auto to_state_group_entries(std::vector<events::StateEventReference> const& refs)
        -> std::vector<database::PersistentStateGroupStateEntry>
    {
        auto entries = std::vector<database::PersistentStateGroupStateEntry>{};
        entries.reserve(refs.size());
        for (auto const& ref : refs)
        {
            entries.push_back({{}, ref.key.event_type, ref.key.state_key, ref.event_id});
        }
        return entries;
    }

    // Defined below, with the extremity memo it was first written for.
    [[nodiscard]] auto resolution_context(rooms::RoomVersionPolicy const& policy,
                                          events::StateResolutionLimits const& limits) -> std::string;

    [[nodiscard]] auto add_state_group_budget(std::size_t state_size, events::StateResolutionLimits const& limits,
                                              std::size_t& total_state_events) -> bool
    {
        if (state_size > limits.max_events_per_state_group || total_state_events > limits.max_total_state_events ||
            state_size > limits.max_total_state_events - total_state_events)
        {
            return false;
        }
        total_state_events += state_size;
        return true;
    }

} // namespace

auto make_store_event_lookup(database::PersistentStore const& store) -> events::EventLookupFn
{
    // EventTable::find is a hash lookup (ADR-0215), so nothing is built per resolution: the lookup
    // costs the events it is asked for, however many the server stores. It reads `store` on every
    // call, so the store must outlive it.
    return [&store](std::string_view event_id) -> std::optional<events::StateEventReference> {
        auto const found = store.events.find(event_id);
        if (found == store.events.end())
        {
            return std::nullopt;
        }
        store.state_events_parsed.add(1U);
        auto ref = parse_state_event_reference(found->event_id, found->json, found->depth);
        if (ref.has_value())
        {
            ref->rejected = found->status == "rejected";
        }
        return ref;
    };
}

auto compute_state_before(database::PersistentStore const& store, std::string_view room_id,
                          rooms::RoomVersionPolicy const& policy, std::vector<std::string> const& prev_event_ids,
                          events::StateResolutionLimits const& limits) -> StateBeforeResult
{
    if (prev_event_ids.empty())
    {
        return {true, {}};
    }
    if (prev_event_ids.size() > 1U && prev_event_ids.size() > limits.max_state_groups)
    {
        return {false, {}, "more prev_events than the state-resolution budget allows"};
    }

    // An event builds on its own room only (ADR-0583). Every path that resolves state before an event comes
    // through here, so a foreign prev_event or group cannot lend its state to this room whatever a caller checked.
    if (auto const foreign = database::find_event_in_other_room(store, room_id, prev_event_ids); foreign.has_value())
    {
        return {false, {}, "prev_event " + *foreign + " belongs to another room"};
    }
    for (auto const& prev_event_id : prev_event_ids)
    {
        auto const group_id = database::find_event_state_group(store, prev_event_id);
        if (!group_id.has_value())
        {
            continue; // The reads below report it.
        }
        auto const group = database::find_state_group(store, *group_id);
        if (group.has_value() && group->room_id != room_id)
        {
            return {false, {}, "state group " + *group_id + " belongs to another room"};
        }
    }

    auto total_state_events = std::size_t{0U};
    if (prev_event_ids.size() == 1U)
    {
        auto const group_id = database::find_event_state_group(store, prev_event_ids.front());
        if (!group_id.has_value())
        {
            return {false, {}, "prev_event " + prev_event_ids.front() + " has no recorded state"};
        }
        auto full_state = database::read_state_group_full_state(store, *group_id);
        if (!full_state.has_value())
        {
            return {false, {}, "state group " + *group_id + " could not be read"};
        }
        return {true, std::move(*full_state)};
    }

    // Each prev_event's group, read once however many prev_events name it. The budget is still charged once per
    // prev_event, as resolving every copy was, so what is refused does not change (ADR-0694).
    auto full_states = std::unordered_map<std::string, std::vector<database::PersistentStateGroupStateEntry>>{};
    auto distinct_group_ids = std::vector<std::string>{};
    for (auto const& prev_event_id : prev_event_ids)
    {
        auto const group_id = database::find_event_state_group(store, prev_event_id);
        if (!group_id.has_value())
        {
            return {false, {}, "prev_event " + prev_event_id + " has no recorded state"};
        }
        auto held = full_states.find(*group_id);
        if (held == full_states.end())
        {
            auto full_state = database::read_state_group_full_state(store, *group_id);
            if (!full_state.has_value())
            {
                return {false, {}, "state group " + *group_id + " could not be read"};
            }
            held = full_states.emplace(*group_id, std::move(*full_state)).first;
            distinct_group_ids.push_back(*group_id);
        }
        if (!add_state_group_budget(held->second.size(), limits, total_state_events))
        {
            return {false, {}, "state groups exceed the state-resolution budget"};
        }
    }
    std::ranges::sort(distinct_group_ids);

    // Every prev_event names one group: resolving copies of one state set gives that set back (nothing conflicts and
    // the auth difference is empty), so it is the state before, as with one prev_event.
    if (distinct_group_ids.size() == 1U)
    {
        auto only = std::move(full_states.begin()->second);
        return {true, std::move(only), {}, distinct_group_ids.front()};
    }

    // An earlier event named exactly these groups, and the group it stored its state before in holds what resolving
    // them gives: groups are immutable, and anything that changes an event they name forgets the room (ADR-0694).
    auto context = resolution_context(policy, limits);
    if (auto const* remembered = store.state_before_memo.find(room_id, context, distinct_group_ids);
        remembered != nullptr)
    {
        if (auto state = database::read_state_group_full_state(store, *remembered); state.has_value())
        {
            return {true, std::move(*state), {}, *remembered};
        }
    }

    auto parsed = ParsedEvents{};
    auto const lookup = parse_once(make_store_event_lookup(store), parsed);
    auto groups = std::vector<events::StateGroup>{};
    groups.reserve(distinct_group_ids.size());
    for (auto const& group_id : distinct_group_ids)
    {
        auto refs = to_state_event_references(full_states.at(group_id), lookup);
        if (!refs.has_value())
        {
            return {false, {}, "state group " + group_id + " names an event missing from the store"};
        }
        groups.push_back(events::StateGroup{group_id, std::move(*refs)});
    }

    auto request = events::StateResolutionRequest{};
    request.room_version = std::string{policy.id};
    request.state_groups = std::move(groups);
    request.event_lookup = lookup;
    request.room_id = std::string{room_id};
    request.limits = limits;

    auto const result = events::resolve_state_v2(request, policy);
    if (!result.resolved)
    {
        return {false, {}, "state resolution failed: " + result.reason};
    }
    return {true,
            to_state_group_entries(result.resolved_state),
            {},
            std::nullopt,
            std::move(distinct_group_ids),
            std::move(context)};
}

auto compute_state_after(std::vector<database::PersistentStateGroupStateEntry> const& state_before,
                         std::string_view event_id, std::string_view event_type,
                         std::optional<std::string> const& state_key)
    -> std::vector<database::PersistentStateGroupStateEntry>
{
    auto after = state_before;
    if (!state_key.has_value())
    {
        return after;
    }
    auto const existing = std::ranges::find_if(after, [&](database::PersistentStateGroupStateEntry const& entry) {
        return entry.event_type == event_type && entry.state_key == *state_key;
    });
    if (existing != after.end())
    {
        existing->event_id = std::string{event_id};
    }
    else
    {
        after.push_back({{}, std::string{event_type}, *state_key, std::string{event_id}});
    }
    return after;
}

auto record_event_state_with_parent(database::PersistentStore& store, std::string_view room_id,
                                    std::string_view event_id,
                                    std::vector<std::string> const& prev_event_ids_for_extremities,
                                    std::optional<std::string> const& parent_group_id,
                                    std::vector<database::PersistentStateGroupStateEntry> const& state_after,
                                    bool accepted) -> std::optional<std::string>
{
    auto const new_group_id = "sg:" + std::string{event_id};
    auto const group_id =
        database::create_or_reuse_state_group(store, room_id, new_group_id, parent_group_id, state_after);
    if (!group_id.has_value())
    {
        return std::nullopt;
    }
    if (!database::set_event_state_group(store, event_id, *group_id))
    {
        return std::nullopt;
    }
    if (!database::update_forward_extremities(store, room_id, event_id, prev_event_ids_for_extremities, accepted))
    {
        return std::nullopt;
    }
    return group_id;
}

auto record_event_state(database::PersistentStore& store, std::string_view room_id, std::string_view event_id,
                        std::vector<std::string> const& prev_event_ids,
                        std::vector<database::PersistentStateGroupStateEntry> const& state_after, bool accepted)
    -> std::optional<std::string>
{
    // By the time this is called, compute_state_before has already
    // succeeded for every id in prev_event_ids, so the first one (if any)
    // is guaranteed to have a state group — this is just picking a delta
    // chain parent, not re-validating.
    auto const parent = prev_event_ids.empty() ? std::optional<std::string>{}
                                               : database::find_event_state_group(store, prev_event_ids.front());
    return record_event_state_with_parent(store, room_id, event_id, prev_event_ids, parent, state_after, accepted);
}

namespace
{

    // The delta parent for a freshly resolved state before: the first resolved group that holds no key the resolution
    // dropped, since a delta cannot record a deletion and a dropped key would force a full snapshot; else the first
    // resolved group. Each group is read once.
    [[nodiscard]] auto state_before_parent(database::PersistentStore const& store, StateBeforeResult const& before)
        -> std::optional<std::string>
    {
        auto keys = std::unordered_set<std::string>{};
        keys.reserve(before.state.size());
        for (auto const& entry : before.state)
        {
            keys.insert(entry.event_type + '\0' + entry.state_key);
        }
        for (auto const& group_id : before.resolved_group_ids)
        {
            auto const full_state = database::read_state_group_full_state(store, group_id);
            if (full_state.has_value() &&
                std::ranges::all_of(*full_state, [&keys](database::PersistentStateGroupStateEntry const& entry) {
                    return keys.contains(entry.event_type + '\0' + entry.state_key);
                }))
            {
                return group_id;
            }
        }
        return before.resolved_group_ids.empty() ? std::optional<std::string>{}
                                                 : std::optional<std::string>{before.resolved_group_ids.front()};
    }

} // namespace

auto record_event_state(database::PersistentStore& store, std::string_view room_id, std::string_view event_id,
                        std::vector<std::string> const& prev_event_ids, StateBeforeResult const& state_before,
                        std::vector<database::PersistentStateGroupStateEntry> const& state_after, bool accepted)
    -> std::optional<std::string>
{
    auto parent = state_before.state_group_id;
    if (!parent.has_value() && !state_before.resolved_group_ids.empty())
    {
        // A fresh resolution: keep its result as a group of its own, once, and remember it for the groups resolved,
        // so the next event naming them reads it rather than resolving and storing it again.
        parent = database::create_or_reuse_state_group(store, room_id, "sb:" + std::string{event_id},
                                                       state_before_parent(store, state_before), state_before.state);
        if (!parent.has_value())
        {
            return std::nullopt;
        }
        store.state_before_memo.remember(room_id, state_before.resolution_context, state_before.resolved_group_ids,
                                         *parent);
    }
    if (!parent.has_value())
    {
        return record_event_state(store, room_id, event_id, prev_event_ids, state_after, accepted);
    }
    return record_event_state_with_parent(store, room_id, event_id, prev_event_ids, parent, state_after, accepted);
}

namespace
{

    // An extremity's after-state, and the group that holds it.
    struct ExtremityState final
    {
        std::string state_group_id{};
        std::vector<database::PersistentStateGroupStateEntry> entries{};
    };
    using ExtremityStateFn = std::function<std::optional<ExtremityState>(std::string const& extremity)>;
    // The id of the group that holds an extremity's after-state: a lookup, no state read.
    using ExtremityGroupFn = std::function<std::optional<std::string>(std::string const& extremity)>;

    [[nodiscard]] auto recorded_extremity_state(database::PersistentStore const& store, std::string const& extremity)
        -> std::optional<ExtremityState>
    {
        auto const group_id = database::find_event_state_group(store, extremity);
        if (!group_id.has_value())
        {
            return std::nullopt;
        }
        auto full_state = database::read_state_group_full_state(store, *group_id);
        if (!full_state.has_value())
        {
            return std::nullopt;
        }
        return ExtremityState{*group_id, std::move(*full_state)};
    }

    // What resolving a room's forward extremities came to.
    struct ExtremityResolution final
    {
        // The resolved state; empty when there is nothing to resolve or the resolution was refused.
        std::vector<database::PersistentStateGroupStateEntry> entries{};
        // Why the extremities could not be resolved (F-49); nullopt when they were, or when there
        // were none.
        std::optional<std::string> refusal{};
        // What a fresh resolution is to be remembered under (ADR-0600); empty when nothing was resolved, or when
        // the result came from the memo. The caller remembers it once what it resolved is what the store holds.
        std::vector<std::string> sorted_group_ids{};
    };

    [[nodiscard]] auto refused_resolution(std::string reason) -> ExtremityResolution
    {
        return {{}, std::move(reason), {}};
    }

    // Everything besides the state groups that can change what a resolution comes to (ADR-0600).
    [[nodiscard]] auto resolution_context(rooms::RoomVersionPolicy const& policy,
                                          events::StateResolutionLimits const& limits) -> std::string
    {
        auto context = std::string{policy.id};
        for (auto const limit :
             {limits.max_state_groups, limits.max_events_per_state_group, limits.max_conflicted_state_keys,
              limits.max_mainline_auth_chain_depth, limits.max_auth_chain_walk_events, limits.max_total_state_events})
        {
            context.push_back('|');
            context.append(std::to_string(limit));
        }
        return context;
    }

    // The resolution of the extremities' after-states, which current state is a
    // cache of. A refusal (F-49) means leave the cache as it is: an extremity with
    // no readable state, more distinct states than the limit, the work budget, or a
    // resolution that fails closed. No extremity is not a refusal: nothing to
    // resolve. `make_lookup` is called only when there is something to resolve.
    //
    // Extremities held in one state group are one state (ADR-0374): a message adds
    // no state, so it shares its prev_event's group, and a thousand forks of
    // messages resolve as one state, not a thousand.
    //
    // State groups are immutable, so the same distinct groups come to the same result, and `memo` answers
    // for them (ADR-0600). Only a success is ever remembered.
    [[nodiscard]] auto resolve_extremity_states(database::ResolvedStateMemo& memo, std::string_view room_id,
                                                rooms::RoomVersionPolicy const& policy,
                                                events::StateResolutionLimits const& limits,
                                                std::vector<std::string> const& extremities,
                                                ExtremityGroupFn const& group_of, ExtremityStateFn const& state_of,
                                                std::function<events::EventLookupFn()> const& make_lookup)
        -> ExtremityResolution
    {
        auto distinct = std::vector<std::string>{};
        auto seen_groups = std::unordered_set<std::string>{};
        for (auto const& extremity : extremities)
        {
            auto group_id = group_of(extremity);
            if (!group_id.has_value())
            {
                return refused_resolution("extremity " + extremity + " has no readable state");
            }
            if (seen_groups.insert(std::move(*group_id)).second)
            {
                distinct.push_back(extremity);
            }
        }
        if (distinct.empty())
        {
            return {};
        }
        if (distinct.size() == 1U)
        {
            auto state = state_of(distinct.front());
            if (!state.has_value())
            {
                return refused_resolution("extremity " + distinct.front() + " has no readable state");
            }
            return {std::move(state->entries), std::nullopt, {}};
        }
        if (distinct.size() > limits.max_state_groups)
        {
            return refused_resolution(std::to_string(distinct.size()) + " distinct extremity states, more than the " +
                                      std::to_string(limits.max_state_groups) + " that can be resolved");
        }
        auto sorted_group_ids = std::vector<std::string>(seen_groups.begin(), seen_groups.end());
        std::ranges::sort(sorted_group_ids);
        if (auto const* remembered = memo.find(room_id, resolution_context(policy, limits), sorted_group_ids);
            remembered != nullptr)
        {
            return {*remembered, std::nullopt, {}};
        }
        auto parsed = ParsedEvents{};
        auto const lookup = parse_once(make_lookup(), parsed);
        auto total_state_events = std::size_t{0U};
        auto groups = std::vector<events::StateGroup>{};
        groups.reserve(distinct.size());
        for (auto const& extremity : distinct)
        {
            auto state = state_of(extremity);
            if (!state.has_value())
            {
                return refused_resolution("extremity " + extremity + " has no readable state");
            }
            if (!add_state_group_budget(state->entries.size(), limits, total_state_events))
            {
                return refused_resolution("the extremities' states exceed the state-resolution budget");
            }
            auto refs = to_state_event_references(state->entries, lookup);
            if (!refs.has_value())
            {
                return refused_resolution("the state of extremity " + extremity +
                                          " names an event missing from the store");
            }
            groups.push_back(events::StateGroup{state->state_group_id, std::move(*refs)});
        }

        auto request = events::StateResolutionRequest{};
        request.room_version = std::string{policy.id};
        request.state_groups = std::move(groups);
        request.event_lookup = lookup;
        request.room_id = std::string{room_id};
        request.limits = limits;
        auto const result = events::resolve_state_v2(request, policy);
        if (!result.resolved)
        {
            return refused_resolution("state resolution failed: " + result.reason);
        }
        return {to_state_group_entries(result.resolved_state), std::nullopt, std::move(sorted_group_ids)};
    }

    void log_refused_resolution(std::string_view room_id, std::string_view reason)
    {
        observability::log_diagnostic(
            "rooms", "state.current.refused",
            {
                {"room_id", std::string{room_id}, false},
                {"reason",  std::string{reason},  false}
        },
            observability::LogEventSeverity::warning);
    }

    // The room's cached current state as state-group entries, in one pass over the room's rows.
    [[nodiscard]] auto current_state_entries(database::PersistentStore const& store, std::string_view room_id)
        -> std::vector<database::PersistentStateGroupStateEntry>
    {
        auto entries = std::vector<database::PersistentStateGroupStateEntry>{};
        database::for_each_room_state_row(store, room_id, [&entries](database::PersistentStateEvent const& row) {
            entries.push_back({{}, row.event_type, row.state_key, row.event_id});
        });
        return entries;
    }

    [[nodiscard]] auto state_entry_key(std::string_view event_type, std::string_view state_key) -> std::string
    {
        auto key = std::string{event_type};
        key.push_back('\0');
        key.append(state_key);
        return key;
    }

    // The rows of `room_id` whose key the resolution does not hold and that came from the room's graph (ADR-0615). A
    // row whose event has no state group came from the graph only if a tip's state names it, as a snapshot's events do;
    // otherwise it is an outlier invite or leave the resolution cannot speak to.
    [[nodiscard]] auto rows_the_resolution_dropped(database::PersistentStore const& store, std::string_view room_id,
                                                   std::vector<std::string> const& extremities,
                                                   std::unordered_set<std::string> const& resolved_keys)
        -> std::vector<database::PersistentStateEvent>
    {
        auto dropped = std::vector<database::PersistentStateEvent>{};
        auto without_group = std::vector<database::PersistentStateEvent>{};
        if (extremities.empty())
        {
            return dropped;
        }
        database::for_each_room_state_row(store, room_id, [&](database::PersistentStateEvent const& row) {
            if (resolved_keys.contains(state_entry_key(row.event_type, row.state_key)))
            {
                return;
            }
            (database::find_event_state_group(store, row.event_id).has_value() ? dropped : without_group)
                .push_back(row);
        });
        if (without_group.empty())
        {
            return dropped;
        }

        auto unnamed = std::unordered_set<std::string>{};
        for (auto const& row : without_group)
        {
            unnamed.insert(row.event_id);
        }
        auto named = std::unordered_set<std::string>{};
        auto groups_read = std::unordered_set<std::string>{};
        for (auto const& extremity : extremities)
        {
            auto const group = database::find_event_state_group(store, extremity);
            if (!group.has_value() || !groups_read.insert(*group).second)
            {
                continue;
            }
            auto const state = database::read_state_group_full_state(store, *group);
            if (!state.has_value())
            {
                continue;
            }
            for (auto const& entry : *state)
            {
                if (unnamed.erase(entry.event_id) != 0U)
                {
                    named.insert(entry.event_id);
                }
            }
            if (unnamed.empty())
            {
                break;
            }
        }
        std::ranges::copy_if(without_group, std::back_inserter(dropped),
                             [&named](database::PersistentStateEvent const& row) {
                                 return named.contains(row.event_id);
                             });
        return dropped;
    }

    // The stored event's content.membership, or nullopt.
    [[nodiscard]] auto membership_of_stored_event(database::PersistentEvent const& event) -> std::optional<std::string>
    {
        auto const parsed = canonicaljson::parse_lossless(event.json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto membership = events::extract_content_membership(parsed.value);
        return membership.empty() ? std::nullopt : std::optional<std::string>{std::move(membership)};
    }

    // What the row of a member key this recomputation moved from `previous_event_id` to `resolved_event_id` becomes, if
    // anything; an empty `resolved_event_id` is a key removed. A row that says other than `join` and is newer than both
    // events was written with no state behind it (an invite, a federated leave) and stays, as in
    // reconcile_memberships_with_current_state.
    [[nodiscard]] auto membership_correction(database::PersistentStore const& store, std::string_view room_id,
                                             std::string const& user_id, std::string_view previous_event_id,
                                             std::string_view resolved_event_id, std::uint64_t causing_stream_ordering)
        -> std::optional<database::MembershipProjection>
    {
        auto const* row = database::find_membership_row(store, room_id, user_id);
        auto membership = std::optional<std::string>{"leave"};
        auto newest_event = std::uint64_t{0U};
        if (resolved_event_id.empty())
        {
            if (row == nullptr)
            {
                return std::nullopt;
            }
        }
        else
        {
            auto const resolved = store.events.find(resolved_event_id);
            if (resolved == store.events.end())
            {
                return std::nullopt;
            }
            membership = membership_of_stored_event(*resolved);
            newest_event = resolved->stream_ordering;
        }
        if (!membership.has_value())
        {
            return std::nullopt;
        }
        if (auto const previous = store.events.find(previous_event_id); previous != store.events.end())
        {
            newest_event = std::max(newest_event, previous->stream_ordering);
        }
        if (row != nullptr &&
            (row->membership == *membership || (row->membership != "join" && row->stream_ordering > newest_event)))
        {
            return std::nullopt;
        }
        auto const row_ordering = row == nullptr ? newest_event : row->stream_ordering;
        return database::MembershipProjection{user_id, std::move(*membership),
                                              std::max(row_ordering, causing_stream_ordering), std::nullopt};
    }

} // namespace

auto recompute_current_state(database::PersistentStore& store, std::string_view room_id,
                             rooms::RoomVersionPolicy const& policy, events::StateResolutionLimits const& limits,
                             std::uint64_t causing_stream_ordering) -> CurrentStateRecompute
{
    auto const extremities = database::find_forward_extremities(store, room_id);
    auto resolution = resolve_extremity_states(
        store.resolved_state_memo, room_id, policy, limits, extremities,
        [&store](std::string const& extremity) {
            return database::find_event_state_group(store, extremity);
        },
        [&store](std::string const& extremity) {
            return recorded_extremity_state(store, extremity);
        },
        [&store] {
            return make_store_event_lookup(store);
        });
    if (resolution.refusal.has_value())
    {
        // F-49: leave the cached current state untouched, and say so.
        log_refused_resolution(room_id, *resolution.refusal);
        return {CurrentStateRecomputeStatus::refused, std::move(*resolution.refusal), {}};
    }
    if (!resolution.sorted_group_ids.empty())
    {
        store.resolved_state_memo.remember(room_id, resolution_context(policy, limits),
                                           std::move(resolution.sorted_group_ids), resolution.entries);
    }

    // The room's current state in one pass over the room's rows, so each resolved entry is a lookup and
    // not a pass of its own.
    auto current = std::unordered_map<std::string, std::string>{};
    database::for_each_room_state_row(store, room_id, [&current](database::PersistentStateEvent const& row) {
        current[state_entry_key(row.event_type, row.state_key)] = row.event_id;
    });
    auto corrections = std::vector<database::MembershipProjection>{};
    auto const correct_membership = [&](std::string const& user_id, std::string_view previous_event_id,
                                        std::string_view resolved_event_id) {
        if (auto correction = membership_correction(store, room_id, user_id, previous_event_id, resolved_event_id,
                                                    causing_stream_ordering);
            correction.has_value())
        {
            corrections.push_back(std::move(*correction));
        }
    };
    auto resolved_keys = std::unordered_set<std::string>{};
    resolved_keys.reserve(resolution.entries.size());
    for (auto const& entry : resolution.entries)
    {
        auto key = state_entry_key(entry.event_type, entry.state_key);
        auto const held = current.find(key);
        if (held == current.end() || held->second != entry.event_id)
        {
            if (!database::store_state(store,
                                       {std::string{room_id}, entry.event_type, entry.state_key, entry.event_id}))
            {
                return {CurrentStateRecomputeStatus::write_failed, {}, {}};
            }
            if (entry.event_type == "m.room.member")
            {
                correct_membership(entry.state_key, held == current.end() ? std::string_view{} : held->second,
                                   entry.event_id);
            }
        }
        resolved_keys.insert(std::move(key));
    }

    auto removed_keys = std::vector<std::pair<std::string, std::string>>{};
    for (auto& row : rows_the_resolution_dropped(store, room_id, extremities, resolved_keys))
    {
        if (row.event_type == "m.room.member")
        {
            correct_membership(row.state_key, row.event_id, {});
        }
        removed_keys.emplace_back(std::move(row.event_type), std::move(row.state_key));
    }
    if ((!removed_keys.empty() || !corrections.empty()) &&
        !database::remove_current_state_rows(store, room_id, removed_keys, corrections))
    {
        return {CurrentStateRecomputeStatus::write_failed, {}, {}};
    }
    return {CurrentStateRecomputeStatus::resolved, {}, std::move(corrections)};
}

auto forward_extremities_stay_bounded(database::PersistentStore const& store, std::string_view room_id,
                                      std::vector<std::string> const& prev_event_ids,
                                      events::StateResolutionLimits const& limits) -> bool
{
    // An event that cites a tip takes its place and the set does not grow.
    return std::ranges::any_of(prev_event_ids,
                               [&store, room_id](std::string const& prev_event_id) {
                                   return store.forward_extremities.contains(room_id, prev_event_id);
                               }) ||
           store.forward_extremities.count_for_room(room_id) < limits.max_state_groups;
}

auto event_may_become_forward_extremity(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view sender_user_id, std::vector<std::string> const& prev_event_ids,
                                        bool is_state_event, events::StateResolutionLimits const& limits) -> bool
{
    auto const& tips = store.forward_extremities;
    if (std::ranges::any_of(prev_event_ids, [&tips, room_id](std::string const& prev_event_id) {
            return tips.contains(room_id, prev_event_id);
        }))
    {
        return true; // It replaces a tip, and the set does not grow.
    }
    if (!is_state_event && !forward_extremities_stay_bounded(store, room_id, prev_event_ids, limits))
    {
        return false;
    }
    if (tips.count_for_sender_server(room_id, sender_user_id) < limits.max_state_tips_per_server)
    {
        return true;
    }
    if (is_state_event || prev_event_ids.size() != 1U)
    {
        return false;
    }
    // A message past the cap stays a tip only in a state group a tip already holds: then it adds nothing to resolve,
    // and it cannot be the way round the cap (ADR-0602). Hash lookups, and only on this path.
    auto const group = store.event_state_groups.state_group_of(prev_event_ids.front());
    return group.has_value() &&
           std::ranges::any_of(tips.tips_of_room(room_id), [&store, group](std::string const& tip) {
               return store.event_state_groups.state_group_of(tip) == group;
           });
}

auto forward_extremities_for_new_event(database::PersistentStore const& store, std::string_view room_id)
    -> std::vector<std::string>
{
    auto extremities = database::find_forward_extremities(store, room_id);
    if (extremities.size() <= events::max_prev_events_per_event)
    {
        return extremities;
    }
    // Cap at the spec limit, keeping the highest-depth extremities (the
    // most recent tips). PersistentForwardExtremity does not itself carry
    // depth, so look each one up in store.events.
    auto with_depth = std::vector<std::pair<std::uint64_t, std::string>>{};
    with_depth.reserve(extremities.size());
    for (auto& id : extremities)
    {
        auto const it = store.events.find(id);
        auto const depth = it != store.events.end() ? it->depth : 0U;
        with_depth.emplace_back(depth, std::move(id));
    }
    std::ranges::sort(with_depth, std::greater{}, [](auto const& pair) {
        return pair.first;
    });
    with_depth.resize(events::max_prev_events_per_event);
    auto result = std::vector<std::string>{};
    result.reserve(with_depth.size());
    for (auto& entry : with_depth)
    {
        result.push_back(std::move(entry.second));
    }
    return result;
}

auto depth_after_prev_events(database::PersistentStore const& store, std::vector<std::string> const& prev_event_ids)
    -> std::uint64_t
{
    auto deepest = std::uint64_t{0U};
    for (auto const& prev_event_id : prev_event_ids)
    {
        if (auto const prev_event = store.events.find(prev_event_id); prev_event != store.events.end())
        {
            deepest = std::max(deepest, prev_event->depth);
        }
    }
    return deepest >= events::max_event_depth ? events::max_event_depth : deepest + 1U;
}

auto basis_for_new_event(database::PersistentStore const& store, std::string_view room_id,
                         rooms::RoomVersionPolicy const& policy, events::StateResolutionLimits const& limits)
    -> NewEventBasis
{
    auto extremities = forward_extremities_for_new_event(store, room_id);
    auto all = compute_state_before(store, room_id, policy, extremities, limits);
    if (all.ok)
    {
        return {true, std::move(extremities), std::move(all.state), {}, {}};
    }

    // ADR-0225: the state across every extremity cannot be computed, so cite
    // one alone, the newest this server stored, and retire the rest. Every
    // later local event would otherwise fail on the same resolution.
    //
    // ADR-0373 (F-40): the event's state before is the room's cached current
    // state, not that extremity's own. The extremity is chosen by stream order,
    // which the sender of a fork influences, and a fork that predates a ban or a
    // demotion has the old state; the retired tips may hold the revocation, and
    // current state still does. The state group recorded for the event, and
    // every recompute of a single extremity after it, then keep the revocation.
    if (extremities.size() > 1U)
    {
        auto newest_first = std::vector<std::pair<std::uint64_t, std::string>>{};
        newest_first.reserve(extremities.size());
        for (auto const& extremity : extremities)
        {
            auto const event = store.events.find(extremity);
            newest_first.emplace_back(event == store.events.end() ? 0U : event->stream_ordering, extremity);
        }
        std::ranges::sort(newest_first, std::greater{}, [](auto const& entry) {
            return entry.first;
        });
        for (auto const& entry : newest_first)
        {
            auto const& candidate = entry.second;
            auto alone = compute_state_before(store, room_id, policy, {candidate}, limits);
            if (!alone.ok)
            {
                continue;
            }
            auto retired = database::find_forward_extremities(store, room_id);
            std::erase(retired, candidate);
            // A room with no current state row is degenerate (every room has its create event);
            // the extremity's own state is all there is to build on.
            auto state_before = current_state_entries(store, room_id);
            auto const from_current_state = !state_before.empty();
            if (!from_current_state)
            {
                state_before = std::move(alone.state);
            }
            observability::log_diagnostic(
                "rooms", "event.prev_events.fallback",
                {
                    {"room_id",      std::string{room_id},                                false},
                    {"extremities",  std::to_string(extremities.size()),                  false},
                    {"prev_event",   candidate,                                           false},
                    {"retired",      std::to_string(retired.size()),                      false},
                    {"state_before", from_current_state ? "current_state" : "prev_event", false},
                    {"reason",       all.reason,                                          false}
            },
                observability::LogEventSeverity::warning);
            return {true, {candidate}, std::move(state_before), std::move(retired), {}};
        }
    }

    observability::log_diagnostic("rooms", "event.prev_events.unresolvable",
                                  {
                                      {"room_id",     std::string{room_id},               false},
                                      {"extremities", std::to_string(extremities.size()), false},
                                      {"reason",      all.reason,                         false}
    },
                                  observability::LogEventSeverity::warning);
    return {false, std::move(extremities), {}, {}, std::move(all.reason)};
}

auto store_event_with_bookkeeping(database::PersistentStore& store, rooms::RoomVersionPolicy const& policy,
                                  database::PersistentEvent event, std::optional<database::PersistentStateEvent> state,
                                  std::optional<database::MembershipProjection> membership,
                                  EventBookkeeping const& bookkeeping, events::StateResolutionLimits const& limits)
    -> StoredWithBookkeeping
{
    auto const room_id = event.room_id;
    auto const event_id = event.event_id;

    // ADR-0228: every write below is prepared first and committed in one
    // transaction, then mirrored in memory. A failure at any point leaves the
    // store as it was: no event, no membership, no state group, no tip.
    auto prepared_event =
        database::prepare_store_event_with_state(store, std::move(event), std::move(state), std::move(membership));
    if (!prepared_event.has_value())
    {
        return {false, "event", "the event, its state row or its membership was refused"};
    }
    auto const prepared_group = database::prepare_state_group(
        store, room_id, "sg:" + event_id, bookkeeping.parent_state_group_id, bookkeeping.state_after);
    if (!prepared_group.has_value())
    {
        return {false, "state_group", "the parent of the event's after-state group could not be read"};
    }
    auto mapping = database::prepare_event_state_group(event_id, prepared_group->state_group_id);
    if (!mapping.has_value())
    {
        return {false, "state_group", "the event could not be mapped to its after-state group"};
    }

    // The room's forward extremities once the event is stored, and the
    // resolution of their states, with the event standing in for itself: it
    // is in neither store.events nor any recorded group until the commit.
    auto extremities_after = database::find_forward_extremities(store, room_id);
    std::erase_if(extremities_after, [&bookkeeping](std::string const& extremity) {
        return std::ranges::find(bookkeeping.replaced_extremities, extremity) != bookkeeping.replaced_extremities.end();
    });
    if (std::ranges::find(extremities_after, event_id) == extremities_after.end())
    {
        extremities_after.push_back(event_id);
    }
    auto const& pending = prepared_event->event;
    auto resolution = resolve_extremity_states(
        store.resolved_state_memo, room_id, policy, limits, extremities_after,
        [&](std::string const& extremity) -> std::optional<std::string> {
            if (extremity == event_id)
            {
                return prepared_group->state_group_id;
            }
            return database::find_event_state_group(store, extremity);
        },
        [&](std::string const& extremity) -> std::optional<ExtremityState> {
            if (extremity == event_id)
            {
                return ExtremityState{prepared_group->state_group_id, bookkeeping.state_after};
            }
            return recorded_extremity_state(store, extremity);
        },
        [&store, &pending] {
            return events::EventLookupFn{[base = make_store_event_lookup(store),
                                          &pending](std::string_view id) -> std::optional<events::StateEventReference> {
                if (id == pending.event_id)
                {
                    return parse_state_event_reference(pending.event_id, pending.json, pending.depth);
                }
                return base(id);
            }};
        });

    // Current state as it will be once the event's own row is written, so the
    // diff below writes only what the resolution changes beyond it.
    auto current = std::unordered_map<std::string, std::string>{};
    database::for_each_room_state_row(store, room_id, [&current](database::PersistentStateEvent const& row) {
        current[state_entry_key(row.event_type, row.state_key)] = row.event_id;
    });
    if (prepared_event->state.has_value())
    {
        current[state_entry_key(prepared_event->state->event_type, prepared_event->state->state_key)] = event_id;
    }
    auto current_state_changes = std::vector<database::PreparedCurrentState>{};
    for (auto const& entry : resolution.entries)
    {
        auto const key = state_entry_key(entry.event_type, entry.state_key);
        auto const existing = current.find(key);
        if (existing != current.end() && existing->second == entry.event_id)
        {
            continue;
        }
        auto row = database::PersistentStateEvent{room_id, entry.event_type, entry.state_key, entry.event_id};
        if (entry.event_id != event_id && !database::state_matches_stored_event(store, row))
        {
            return {false, "current_state", "the resolved state names " + entry.event_id + ", which is not stored"};
        }
        current_state_changes.push_back(database::prepare_current_state(
            std::move(row), existing == current.end() ? std::string{} : existing->second));
        current[key] = entry.event_id;
    }

    auto statements = prepared_event->statements;
    statements.insert(statements.end(), prepared_group->statements.begin(), prepared_group->statements.end());
    statements.push_back(*mapping);
    auto extremity_statements =
        database::prepare_forward_extremities_update(room_id, event_id, bookkeeping.replaced_extremities);
    statements.insert(statements.end(), extremity_statements.begin(), extremity_statements.end());
    for (auto const& change : current_state_changes)
    {
        statements.insert(statements.end(), change.statements.begin(), change.statements.end());
    }
    if (!database::commit_persistent_transaction(store, statements))
    {
        return {false, "commit", "the event and its bookkeeping were not committed"};
    }

    // Before the event is applied: applying a redaction overwrites its target and forgets the room, and what was
    // resolved here read the target as it was (ADR-0600).
    if (!resolution.sorted_group_ids.empty())
    {
        store.resolved_state_memo.remember(room_id, resolution_context(policy, limits),
                                           std::move(resolution.sorted_group_ids), std::move(resolution.entries));
    }

    // The event's own current_state row first, then what the resolution
    // changes beyond it.
    database::apply_store_event_with_state(store, *prepared_event);
    database::apply_state_group(store, *prepared_group);
    database::apply_event_state_group(store, event_id, prepared_group->state_group_id);
    database::apply_forward_extremities_update(store, room_id, event_id, bookkeeping.replaced_extremities);
    for (auto const& change : current_state_changes)
    {
        database::apply_current_state(store, change);
    }
    if (resolution.refusal.has_value())
    {
        // F-49: the event is stored, and current state holds only its own row beyond what it held.
        log_refused_resolution(room_id, *resolution.refusal);
        return {true, {}, {}, true, *resolution.refusal};
    }
    return {true, {}, {}, false, {}};
}

auto store_local_event(database::PersistentStore& store, rooms::RoomVersionPolicy const& policy,
                       database::PersistentEvent event, std::optional<database::PersistentStateEvent> state,
                       NewEventBasis const& basis, events::StateResolutionLimits const& limits,
                       std::optional<database::MembershipProjection> membership) -> bool
{
    auto const room_id = event.room_id;
    auto const event_id = event.event_id;
    auto const failed = [&room_id, &event_id](std::string_view step, std::string reason) {
        observability::log_diagnostic("rooms", "event.store.failed",
                                      {
                                          {"room_id",  room_id,           false},
                                          {"event_id", event_id,          false},
                                          {"step",     std::string{step}, false},
                                          {"reason",   std::move(reason), false}
        },
                                      observability::LogEventSeverity::warning);
        return false;
    };

    // A local event's state before was resolved while its prev_events were
    // chosen (basis_for_new_event); without one it is never stored.
    if (!basis.ok)
    {
        return failed("state_before", basis.reason);
    }
    if (event.prev_event_ids != basis.prev_event_ids)
    {
        return failed("state_before", "prev_events differ from the ones the state before was resolved for");
    }

    auto const event_type = state.has_value() ? state->event_type : std::string{};
    auto const state_key =
        state.has_value() ? std::optional<std::string>{state->state_key} : std::optional<std::string>{};

    auto bookkeeping = EventBookkeeping{};
    bookkeeping.state_after = compute_state_after(basis.state_before, event_id, event_type, state_key);
    bookkeeping.parent_state_group_id = basis.prev_event_ids.empty()
                                            ? std::optional<std::string>{}
                                            : database::find_event_state_group(store, basis.prev_event_ids.front());
    bookkeeping.replaced_extremities = basis.prev_event_ids;
    bookkeeping.replaced_extremities.insert(bookkeeping.replaced_extremities.end(), basis.retired_extremities.begin(),
                                            basis.retired_extremities.end());
    auto const stored = store_event_with_bookkeeping(store, policy, std::move(event), std::move(state),
                                                     std::move(membership), bookkeeping, limits);
    if (!stored.ok)
    {
        return failed(stored.step, stored.reason);
    }
    return true;
}

} // namespace merovingian::homeserver
