// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/state_bookkeeping.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/limits.hpp"

#include <algorithm>
#include <functional>
#include <memory>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace merovingian::homeserver
{

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
    // auth-chain walk expects. Mirrors the parsing the (unchanged,
    // still-unwired) state_conflict_resolver lookup in local_http_router.cpp
    // does, kept separate per that function's own comment.
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
        return parse_state_event_reference(evt.event_id, evt.json, evt.depth);
    };
}

auto compute_state_before(database::PersistentStore const& store, std::string_view room_id,
                          rooms::RoomVersionPolicy const& policy, std::vector<std::string> const& prev_event_ids)
    -> StateBeforeResult
{
    std::ignore = room_id;
    if (prev_event_ids.empty())
    {
        return {true, {}};
    }

    if (prev_event_ids.size() == 1U)
    {
        auto const group_id = database::find_event_state_group(store, prev_event_ids.front());
        if (!group_id.has_value())
        {
            return {false, {}};
        }
        auto full_state = database::read_state_group_full_state(store, *group_id);
        if (!full_state.has_value())
        {
            return {false, {}};
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
            return {false, {}};
        }
        auto full_state = database::read_state_group_full_state(store, *group_id);
        if (!full_state.has_value())
        {
            return {false, {}};
        }
        auto refs = to_state_event_references(*full_state, lookup);
        if (!refs.has_value())
        {
            return {false, {}};
        }
        groups.push_back(events::StateGroup{*group_id, std::move(*refs)});
    }

    auto request = events::StateResolutionRequest{};
    request.room_version = std::string{policy.id};
    request.state_groups = std::move(groups);
    request.event_lookup = lookup;

    auto const result = events::resolve_state_v2(request, policy);
    if (!result.resolved)
    {
        return {false, {}};
    }
    return {true, to_state_group_entries(result.resolved_state)};
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

auto recompute_current_state(database::PersistentStore& store, std::string_view room_id,
                             rooms::RoomVersionPolicy const& policy) -> bool
{
    auto const extremities = database::find_forward_extremities(store, room_id);
    if (extremities.empty())
    {
        return true;
    }

    auto resolved = std::vector<database::PersistentStateGroupStateEntry>{};
    if (extremities.size() == 1U)
    {
        auto const group_id = database::find_event_state_group(store, extremities.front());
        if (!group_id.has_value())
        {
            return true; // defensive: no state recorded yet for this extremity
        }
        auto full_state = database::read_state_group_full_state(store, *group_id);
        if (!full_state.has_value())
        {
            return true;
        }
        resolved = std::move(*full_state);
    }
    else
    {
        auto const lookup = make_store_event_lookup(store);
        auto groups = std::vector<events::StateGroup>{};
        groups.reserve(extremities.size());
        for (auto const& extremity : extremities)
        {
            auto const group_id = database::find_event_state_group(store, extremity);
            if (!group_id.has_value())
            {
                return true; // defensive: leave the cache untouched
            }
            auto full_state = database::read_state_group_full_state(store, *group_id);
            if (!full_state.has_value())
            {
                return true;
            }
            auto refs = to_state_event_references(*full_state, lookup);
            if (!refs.has_value())
            {
                return true;
            }
            groups.push_back(events::StateGroup{*group_id, std::move(*refs)});
        }

        auto request = events::StateResolutionRequest{};
        request.room_version = std::string{policy.id};
        request.state_groups = std::move(groups);
        request.event_lookup = lookup;

        auto const result = events::resolve_state_v2(request, policy);
        if (!result.resolved)
        {
            return true; // fail closed on the resolution, not on the cache
        }
        resolved = to_state_group_entries(result.resolved_state);
    }

    for (auto const& entry : resolved)
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
        auto const it = std::ranges::find_if(store.events, [&](database::PersistentEvent const& event) {
            return event.event_id == id;
        });
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

auto store_local_event(database::PersistentStore& store, rooms::RoomVersionPolicy const& policy,
                       database::PersistentEvent event, std::optional<database::PersistentStateEvent> state) -> bool
{
    auto const room_id = event.room_id;
    auto const event_id = event.event_id;
    auto const prev_event_ids = event.prev_event_ids;

    auto const state_before = compute_state_before(store, room_id, policy, prev_event_ids);
    if (!state_before.ok)
    {
        // A local event's own prev_events were just chosen from this same
        // room's recorded forward extremities (forward_extremities_for_new_event),
        // so this should always resolve; a failure here is real corruption,
        // not a legitimate gap — fail the whole request rather than store an
        // event with no usable state.
        return false;
    }

    auto const event_type = state.has_value() ? state->event_type : std::string{};
    auto const state_key =
        state.has_value() ? std::optional<std::string>{state->state_key} : std::optional<std::string>{};

    if (!database::store_event_with_state(store, event, state))
    {
        return false;
    }

    auto const state_after = compute_state_after(state_before.state, event_id, event_type, state_key);
    auto const group = record_event_state(store, room_id, event_id, prev_event_ids, state_after);
    if (!group.has_value())
    {
        return false;
    }
    return recompute_current_state(store, room_id, policy);
}

} // namespace merovingian::homeserver
