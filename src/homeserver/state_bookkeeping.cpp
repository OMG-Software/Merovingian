// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/state_bookkeeping.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/events/limits.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <functional>
#include <memory>
#include <tuple>
#include <unordered_map>
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
    // Index once per resolution rather than per lookup: resolve_state_v2's
    // auth-chain walk can call this many times for one PDU.
    auto index = std::make_shared<std::unordered_map<std::string, std::size_t>>();
    index->reserve(store.events.size());
    for (std::size_t i = 0U; i < store.events.size(); ++i)
    {
        (*index)[store.events[i].event_id] = i;
    }
    return [&store, index](std::string_view event_id) -> std::optional<events::StateEventReference> {
        auto const it = index->find(std::string{event_id});
        if (it == index->end() || it->second >= store.events.size())
        {
            return std::nullopt;
        }
        auto const& evt = store.events[it->second];
        auto ref = parse_state_event_reference(evt.event_id, evt.json, evt.depth);
        if (ref.has_value())
        {
            ref->rejected = evt.status == "rejected";
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

    auto const lookup = make_store_event_lookup(store);
    auto groups = std::vector<events::StateGroup>{};
    groups.reserve(prev_event_ids.size());
    for (auto const& prev_event_id : prev_event_ids)
    {
        auto const group_id = database::find_event_state_group(store, prev_event_id);
        if (!group_id.has_value())
        {
            return {false, {}, "prev_event " + prev_event_id + " has no recorded state"};
        }
        auto full_state = database::read_state_group_full_state(store, *group_id);
        if (!full_state.has_value())
        {
            return {false, {}, "state group " + *group_id + " could not be read"};
        }
        if (!add_state_group_budget(full_state->size(), limits, total_state_events))
        {
            return {false, {}, "state groups exceed the state-resolution budget"};
        }
        auto refs = to_state_event_references(*full_state, lookup);
        if (!refs.has_value())
        {
            return {false, {}, "state group " + *group_id + " names an event missing from the store"};
        }
        groups.push_back(events::StateGroup{*group_id, std::move(*refs)});
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
    return {true, to_state_group_entries(result.resolved_state), {}};
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

    // An extremity's after-state, and the group that holds it.
    struct ExtremityState final
    {
        std::string state_group_id{};
        std::vector<database::PersistentStateGroupStateEntry> entries{};
    };
    using ExtremityStateFn = std::function<std::optional<ExtremityState>(std::string const& extremity)>;

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

    // The resolution of the extremities' after-states, which current state is a
    // cache of. nullopt means leave the cache as it is: no extremity, an
    // extremity with no readable state, the work budget, or a resolution that
    // fails closed. `make_lookup` is called only when there is something to
    // resolve, since building it indexes every stored event.
    [[nodiscard]] auto resolve_extremity_states(std::string_view room_id, rooms::RoomVersionPolicy const& policy,
                                                events::StateResolutionLimits const& limits,
                                                std::vector<std::string> const& extremities,
                                                ExtremityStateFn const& state_of,
                                                std::function<events::EventLookupFn()> const& make_lookup)
        -> std::optional<std::vector<database::PersistentStateGroupStateEntry>>
    {
        if (extremities.empty())
        {
            return std::nullopt;
        }
        if (extremities.size() == 1U)
        {
            auto state = state_of(extremities.front());
            if (!state.has_value())
            {
                return std::nullopt;
            }
            return std::move(state->entries);
        }
        if (extremities.size() > limits.max_state_groups)
        {
            return std::nullopt;
        }
        auto const lookup = make_lookup();
        auto total_state_events = std::size_t{0U};
        auto groups = std::vector<events::StateGroup>{};
        groups.reserve(extremities.size());
        for (auto const& extremity : extremities)
        {
            auto state = state_of(extremity);
            if (!state.has_value() || !add_state_group_budget(state->entries.size(), limits, total_state_events))
            {
                return std::nullopt;
            }
            auto refs = to_state_event_references(state->entries, lookup);
            if (!refs.has_value())
            {
                return std::nullopt;
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
            return std::nullopt;
        }
        return to_state_group_entries(result.resolved_state);
    }

    [[nodiscard]] auto state_entry_key(std::string_view event_type, std::string_view state_key) -> std::string
    {
        auto key = std::string{event_type};
        key.push_back('\0');
        key.append(state_key);
        return key;
    }

} // namespace

auto recompute_current_state(database::PersistentStore& store, std::string_view room_id,
                             rooms::RoomVersionPolicy const& policy, events::StateResolutionLimits const& limits)
    -> bool
{
    auto const resolved = resolve_extremity_states(
        room_id, policy, limits, database::find_forward_extremities(store, room_id),
        [&store](std::string const& extremity) {
            return recorded_extremity_state(store, extremity);
        },
        [&store] {
            return make_store_event_lookup(store);
        });
    if (!resolved.has_value())
    {
        return true; // leave the cached current state untouched
    }

    for (auto const& entry : *resolved)
    {
        auto const current = std::ranges::find_if(store.state, [&](database::PersistentStateEvent const& state) {
            return state.room_id == room_id && state.event_type == entry.event_type &&
                   state.state_key == entry.state_key;
        });
        if (current != store.state.end() && current->event_id == entry.event_id)
        {
            continue; // unchanged
        }
        if (!database::store_state(store, {std::string{room_id}, entry.event_type, entry.state_key, entry.event_id}))
        {
            return false;
        }
    }
    return true;
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
    for (auto& [depth, id] : with_depth)
    {
        std::ignore = depth;
        result.push_back(std::move(id));
    }
    return result;
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

    // ADR-0225: the state across every extremity cannot be computed, so build
    // on one alone, the newest this server stored, and retire the rest. Every
    // later local event would otherwise fail on the same resolution.
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
        for (auto const& [stream_ordering, candidate] : newest_first)
        {
            std::ignore = stream_ordering;
            auto alone = compute_state_before(store, room_id, policy, {candidate}, limits);
            if (!alone.ok)
            {
                continue;
            }
            auto retired = database::find_forward_extremities(store, room_id);
            std::erase(retired, candidate);
            observability::log_diagnostic("rooms", "event.prev_events.fallback",
                                          {
                                              {"room_id",     std::string{room_id},               false},
                                              {"extremities", std::to_string(extremities.size()), false},
                                              {"prev_event",  candidate,                          false},
                                              {"retired",     std::to_string(retired.size()),     false},
                                              {"reason",      all.reason,                         false}
            },
                                          observability::LogEventSeverity::warning);
            return {true, {candidate}, std::move(alone.state), std::move(retired), {}};
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
    auto const resolved = resolve_extremity_states(
        room_id, policy, limits, extremities_after,
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
    for (auto const& row : store.state)
    {
        if (row.room_id == room_id)
        {
            current[state_entry_key(row.event_type, row.state_key)] = row.event_id;
        }
    }
    if (prepared_event->state.has_value())
    {
        current[state_entry_key(prepared_event->state->event_type, prepared_event->state->state_key)] = event_id;
    }
    auto current_state_changes = std::vector<database::PreparedCurrentState>{};
    for (auto const& entry : resolved.value_or(std::vector<database::PersistentStateGroupStateEntry>{}))
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
    return {true, {}, {}};
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
