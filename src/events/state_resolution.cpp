// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/state_resolution.hpp"

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/limits.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::events
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("state_resolution", event, fields, severity);
    }

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }

        return nullptr;
    }

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto value_is_object(canonicaljson::Value const& value) noexcept -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&value.storage());
    }

    [[nodiscard]] auto array_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Array const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Array>(&value->storage());
    }

    // Extract the event id from one auth_events entry. v3+ rooms use plain
    // event-id strings; v1/v2 rooms use [event_id, hash] pairs.
    [[nodiscard]] auto auth_entry_event_id(canonicaljson::Value const& entry) noexcept -> std::string const*
    {
        if (auto const* id = std::get_if<std::string>(&entry.storage()); id != nullptr)
        {
            return id;
        }
        if (auto const* pair = std::get_if<canonicaljson::Array>(&entry.storage()); pair != nullptr && !pair->empty())
        {
            return std::get_if<std::string>(&pair->front().storage());
        }
        return nullptr;
    }

    [[nodiscard]] auto value_has_content(canonicaljson::Value const& value) noexcept -> bool
    {
        return !std::holds_alternative<std::nullptr_t>(value.storage());
    }

    [[nodiscard]] auto select_v1_winner(StateEventReference const& existing,
                                        StateEventReference const& candidate) noexcept -> StateEventReference const&
    {
        if (candidate.depth != existing.depth)
        {
            return candidate.depth > existing.depth ? candidate : existing;
        }
        return candidate.event_id < existing.event_id ? candidate : existing;
    }

    // Fetches event JSON by id for the auth-chain walk (auth difference,
    // conflicted state subgraph, and the iterative auth checks' own-auth-events
    // fallback), backed first by the events already present in the submitted
    // state groups and, for anything else, by
    // StateResolutionRequest::event_lookup. Fetched events are cached in a
    // deque so references stay valid for the lifetime of the resolution
    // (std::deque never invalidates references to existing elements on
    // push_back) and so repeated walks over the same ancestor do not re-invoke
    // the caller's lookup.
    //
    // Two lookup modes:
    //   - find_required: the auth-chain walk cannot safely continue without
    //     this event. A miss sets missing() and the whole resolution fails
    //     closed. Spec (Required design): "if any event needed for an auth
    //     chain walk is missing, resolution must NOT proceed with partial
    //     information."
    //   - find_optional: a best-effort lookup (e.g. "does this event have a
    //     power_levels ancestor") where absence is a normal, defined outcome,
    //     not an error. Never sets missing().
    // Both share one cache and one lookup budget (max_auth_chain_walk_events)
    // so the combined cost of a resolution is bounded regardless of which
    // caller drives the walk; this code is reachable from untrusted
    // federation input (a hostile remote proposing a state fork).
    class AuthChainEventSource final
    {
    public:
        AuthChainEventSource(EventJsonIndex const& known, EventLookupFn const& lookup, std::size_t budget) noexcept
            : known_{known}
            , lookup_{lookup}
            , budget_{budget}
        {
        }

        [[nodiscard]] auto find_required(std::string_view event_id) -> canonicaljson::Value const*
        {
            auto const* found = fetch(event_id);
            if (found == nullptr)
            {
                missing_ = true;
            }
            return found;
        }

        [[nodiscard]] auto find_optional(std::string_view event_id) -> canonicaljson::Value const*
        {
            return fetch(event_id);
        }

        [[nodiscard]] auto missing() const noexcept -> bool
        {
            return missing_;
        }

    private:
        static constexpr std::size_t not_found = static_cast<std::size_t>(-1);

        [[nodiscard]] auto fetch(std::string_view event_id) -> canonicaljson::Value const*
        {
            if (auto it = known_.find(std::string{event_id}); it != known_.end())
            {
                return &it->second.get();
            }
            if (auto it = fetched_index_.find(std::string{event_id}); it != fetched_index_.end())
            {
                return it->second == not_found ? nullptr : &fetched_.at(it->second).event_json;
            }
            if (!lookup_ || used_ >= budget_)
            {
                fetched_index_.emplace(std::string{event_id}, not_found);
                return nullptr;
            }
            ++used_;
            auto fetched = lookup_(event_id);
            if (!fetched.has_value())
            {
                fetched_index_.emplace(std::string{event_id}, not_found);
                return nullptr;
            }
            fetched_.push_back(std::move(*fetched));
            auto const index = fetched_.size() - 1U;
            fetched_index_.emplace(std::string{event_id}, index);
            return &fetched_.back().event_json;
        }

        EventJsonIndex const& known_;
        EventLookupFn const& lookup_;
        std::size_t budget_;
        std::size_t used_{0U};
        bool missing_{false};
        std::deque<StateEventReference> fetched_{};
        std::unordered_map<std::string, std::size_t> fetched_index_{};
    };

    struct PowerLevelsAncestor final
    {
        bool valid{false};
        std::optional<std::string> event_id{};
    };

    // Resolve every auth_events reference before concluding that no older
    // power_levels event exists. Mainline ordering is defined by repeated
    // auth_events lookups, including events absent from the submitted state
    // groups; a missing/malformed ancestor makes the ordering incomplete.
    [[nodiscard]] auto power_levels_auth_ancestor(canonicaljson::Object const& event_json, AuthChainEventSource& source)
        -> PowerLevelsAncestor
    {
        auto const* auth = array_member(event_json, "auth_events");
        if (auth == nullptr || auth->size() > max_auth_events_per_event)
        {
            return {};
        }

        auto result = PowerLevelsAncestor{true, std::nullopt};
        for (auto const& entry : *auth)
        {
            auto const* id = auth_entry_event_id(entry);
            if (id == nullptr || id->empty())
            {
                return {};
            }
            auto const* json = source.find_required(*id);
            auto const* object = json != nullptr ? value_is_object(*json) : nullptr;
            auto const* type = object != nullptr ? string_member(*object, "type") : nullptr;
            auto const* state_key = object != nullptr ? string_member(*object, "state_key") : nullptr;
            if (object == nullptr || type == nullptr || state_key == nullptr)
            {
                return {};
            }
            if (*type == "m.room.power_levels")
            {
                if (!state_key->empty() || result.event_id.has_value())
                {
                    return {};
                }
                result.event_id = *id;
            }
        }
        return result;
    }

    // Build [P0, P1, …, Pn] by repeatedly resolving the power-level event in
    // each predecessor's auth_events. Both a cycle and a truncated walk make
    // the ordering unusable and therefore fail closed.
    [[nodiscard]] auto collect_mainline_power_events(std::string const& head_event_id,
                                                     canonicaljson::Value const& power_levels_event,
                                                     AuthChainEventSource& source, std::size_t max_depth)
        -> std::optional<std::vector<std::string>>
    {
        auto result = std::vector<std::string>{};
        auto visited = std::unordered_set<std::string>{};
        auto current_id = head_event_id;
        auto const* current = value_is_object(power_levels_event);
        if (current == nullptr || current_id.empty())
        {
            return std::nullopt;
        }

        while (result.size() < max_depth)
        {
            if (!visited.insert(current_id).second)
            {
                return std::nullopt;
            }
            result.push_back(current_id);
            auto const ancestor = power_levels_auth_ancestor(*current, source);
            if (!ancestor.valid)
            {
                return std::nullopt;
            }
            if (!ancestor.event_id.has_value())
            {
                return result;
            }
            if (result.size() == max_depth)
            {
                return std::nullopt;
            }
            current_id = *ancestor.event_id;
            auto const* json = source.find_required(current_id);
            current = json != nullptr ? value_is_object(*json) : nullptr;
            auto const* type = current != nullptr ? string_member(*current, "type") : nullptr;
            auto const* state_key = current != nullptr ? string_member(*current, "state_key") : nullptr;
            if (type == nullptr || *type != "m.room.power_levels" || state_key == nullptr || !state_key->empty())
            {
                return std::nullopt;
            }
        }

        return std::nullopt;
    }

    // BFS over `start_json`'s auth_events, following ancestors transitively via
    // `source`. Returns the chain (excluding the starting event itself) or
    // nullopt if an ancestor could not be fetched (source.missing() is then
    // true) or the walk exceeded `cap` distinct events.
    // Spec: rooms/v10.md — Definitions, "Auth chain": "the set containing all
    // of E's auth events, all of their auth events, and so on recursively".
    [[nodiscard]] auto walk_auth_chain(canonicaljson::Value const& start_json, AuthChainEventSource& source,
                                       std::size_t cap) -> std::optional<std::unordered_set<std::string>>
    {
        auto chain = std::unordered_set<std::string>{};
        auto const* start_obj = value_is_object(start_json);
        if (start_obj == nullptr)
        {
            return chain;
        }
        auto const* start_auth = array_member(*start_obj, "auth_events");
        if (start_auth == nullptr)
        {
            return chain;
        }

        auto frontier = std::vector<std::string>{};
        for (auto const& entry : *start_auth)
        {
            if (auto const* id = auth_entry_event_id(entry); id != nullptr)
            {
                frontier.push_back(*id);
            }
        }

        while (!frontier.empty())
        {
            auto id = std::move(frontier.back());
            frontier.pop_back();
            if (!chain.insert(id).second)
            {
                continue; // already visited
            }
            if (chain.size() > cap)
            {
                return std::nullopt;
            }
            auto const* json = source.find_required(id);
            if (json == nullptr)
            {
                return std::nullopt;
            }
            auto const* obj = value_is_object(*json);
            if (obj == nullptr)
            {
                continue;
            }
            auto const* auth = array_member(*obj, "auth_events");
            if (auth == nullptr)
            {
                continue;
            }
            for (auto const& entry : *auth)
            {
                if (auto const* nid = auth_entry_event_id(entry); nid != nullptr && !chain.contains(*nid))
                {
                    frontier.push_back(*nid);
                }
            }
        }
        return chain;
    }

    // Full auth chain of a state group: the union of the auth chains of every
    // event in the group's state. Spec: rooms/v10.md — Definitions, "Auth
    // difference": "the full auth chain for each state Si, that is the union
    // of the auth chains for each event in Si".
    [[nodiscard]] auto full_auth_chain_of_group(StateGroup const& group, AuthChainEventSource& source, std::size_t cap)
        -> std::optional<std::unordered_set<std::string>>
    {
        auto result = std::unordered_set<std::string>{};
        for (auto const& event : group.state)
        {
            if (!value_has_content(event.event_json))
            {
                continue;
            }
            auto chain = walk_auth_chain(event.event_json, source, cap);
            if (!chain.has_value())
            {
                return std::nullopt;
            }
            result.insert(chain->begin(), chain->end());
            if (result.size() > cap)
            {
                return std::nullopt;
            }
        }
        return result;
    }

    // Auth difference = ∪Ci − ∩Ci, where Ci is the full auth chain of state
    // group i. Spec: rooms/v10.md — Definitions, "Auth difference".
    [[nodiscard]] auto compute_auth_difference(std::vector<StateGroup> const& groups, AuthChainEventSource& source,
                                               std::size_t cap) -> std::optional<std::unordered_set<std::string>>
    {
        auto chains = std::vector<std::unordered_set<std::string>>{};
        chains.reserve(groups.size());
        for (auto const& group : groups)
        {
            auto chain = full_auth_chain_of_group(group, source, cap);
            if (!chain.has_value())
            {
                return std::nullopt;
            }
            chains.push_back(std::move(*chain));
        }
        if (chains.empty())
        {
            return std::unordered_set<std::string>{};
        }

        auto union_set = std::unordered_set<std::string>{};
        for (auto const& chain : chains)
        {
            union_set.insert(chain.begin(), chain.end());
        }
        auto intersection = chains.front();
        for (std::size_t i = 1U; i < chains.size(); ++i)
        {
            std::erase_if(intersection, [&chains, i](std::string const& id) {
                return !chains[i].contains(id);
            });
        }

        auto difference = std::move(union_set);
        for (auto const& id : intersection)
        {
            difference.erase(id);
        }
        return difference;
    }

    // Conflicted state subgraph (room v12 / state-res v2.1 only): the union of
    // every path along auth_events edges between any pair of events in the
    // conflicted state set, endpoints included.
    // Spec: rooms/v12.md — Definitions, "Conflicted state subgraph".
    [[nodiscard]] auto compute_conflicted_state_subgraph(std::unordered_set<std::string> const& conflicted_ids,
                                                         AuthChainEventSource& source, std::size_t cap)
        -> std::optional<std::unordered_set<std::string>>
    {
        auto graph = std::unordered_map<std::string, std::vector<std::string>>{};
        graph.reserve(std::min(cap, conflicted_ids.size() * 2U));
        auto pending = std::deque<std::string>{};
        for (auto const& id : conflicted_ids)
        {
            if (id.empty())
            {
                return std::nullopt;
            }
            pending.push_back(id);
        }

        while (!pending.empty())
        {
            auto id = std::move(pending.front());
            pending.pop_front();
            if (graph.contains(id))
            {
                continue;
            }
            if (graph.size() >= cap)
            {
                return std::nullopt;
            }
            auto const* json = source.find_required(id);
            auto const* object = json != nullptr ? value_is_object(*json) : nullptr;
            auto const* auth = object != nullptr ? array_member(*object, "auth_events") : nullptr;
            if (auth == nullptr || auth->size() > max_auth_events_per_event)
            {
                return std::nullopt;
            }

            auto neighbours = std::vector<std::string>{};
            neighbours.reserve(auth->size());
            auto unique_neighbours = std::unordered_set<std::string>{};
            for (auto const& entry : *auth)
            {
                auto const* ancestor_id = auth_entry_event_id(entry);
                if (ancestor_id == nullptr || ancestor_id->empty() || !unique_neighbours.insert(*ancestor_id).second)
                {
                    return std::nullopt;
                }
                neighbours.push_back(*ancestor_id);
                pending.push_back(*ancestor_id);
            }
            graph.emplace(std::move(id), std::move(neighbours));
        }

        // Reject cycles in the reachable auth graph with Kahn's algorithm.
        // The graph is bounded by distinct events and each event has at most
        // max_auth_events_per_event outgoing edges.
        auto indegree = std::unordered_map<std::string, std::size_t>{};
        auto reverse = std::unordered_map<std::string, std::vector<std::string>>{};
        indegree.reserve(graph.size());
        reverse.reserve(graph.size());
        for (auto const& [id, ancestors] : graph)
        {
            indegree.try_emplace(id, 0U);
            for (auto const& ancestor_id : ancestors)
            {
                if (!graph.contains(ancestor_id))
                {
                    return std::nullopt;
                }
                ++indegree[ancestor_id];
                reverse[ancestor_id].push_back(id);
            }
        }
        auto ready = std::deque<std::string>{};
        for (auto const& [id, degree] : indegree)
        {
            if (degree == 0U)
            {
                ready.push_back(id);
            }
        }
        auto processed = std::size_t{0U};
        while (!ready.empty())
        {
            auto id = std::move(ready.front());
            ready.pop_front();
            ++processed;
            for (auto const& ancestor_id : graph[id])
            {
                auto& degree = indegree[ancestor_id];
                if (--degree == 0U)
                {
                    ready.push_back(ancestor_id);
                }
            }
        }
        if (processed != graph.size())
        {
            return std::nullopt;
        }

        // Every graph vertex is reachable from a conflicted endpoint by
        // construction. The desired union of paths between conflicted events
        // is exactly the subset that can also reach an endpoint.
        auto subgraph = std::unordered_set<std::string>{};
        auto reaches_endpoint = std::deque<std::string>{};
        for (auto const& id : conflicted_ids)
        {
            subgraph.insert(id); // paths include their endpoints
            reaches_endpoint.push_back(id);
        }
        while (!reaches_endpoint.empty())
        {
            auto id = std::move(reaches_endpoint.front());
            reaches_endpoint.pop_front();
            for (auto const& predecessor : reverse[id])
            {
                if (subgraph.insert(predecessor).second)
                {
                    reaches_endpoint.push_back(predecessor);
                }
            }
        }
        return subgraph;
    }

    // Materializes a StateEventReference for an auth-chain-only event (one
    // discovered via the auth difference or conflicted state subgraph, not
    // present in any submitted state group). Every valid auth_events target is
    // itself a state event (m.room.create/power_levels/join_rules/member/
    // third_party_invite are the only permitted auth event types), so `type`
    // and `state_key` are always expected; a malformed ancestor is treated as
    // a fetch failure (fail closed) rather than silently skipped.
    [[nodiscard]] auto materialize_ref(std::string const& event_id, AuthChainEventSource& source)
        -> std::optional<StateEventReference>
    {
        auto const* json = source.find_required(event_id);
        if (json == nullptr)
        {
            return std::nullopt;
        }
        auto const* obj = value_is_object(*json);
        if (obj == nullptr)
        {
            return std::nullopt;
        }
        auto const* type = string_member(*obj, "type");
        auto const* state_key = string_member(*obj, "state_key");
        if (type == nullptr || state_key == nullptr)
        {
            return std::nullopt;
        }
        auto const* sender = string_member(*obj, "sender");
        auto origin_server_ts = std::int64_t{0};
        if (auto const* ts = object_member(*obj, "origin_server_ts"); ts != nullptr)
        {
            if (auto const* ts_int = std::get_if<std::int64_t>(&ts->storage()); ts_int != nullptr)
            {
                origin_server_ts = *ts_int;
            }
        }

        auto ref = StateEventReference{};
        ref.key = StateKey{*type, *state_key};
        ref.event_id = event_id;
        ref.sender = sender != nullptr ? *sender : std::string{};
        ref.origin_server_ts = origin_server_ts;
        ref.depth = 0U;
        ref.event_json = *json;
        return ref;
    }

    // The m.room.power_levels and m.room.create events found among
    // `event_json`'s own auth_events (not the running resolved state, and not
    // a shared "unconflicted" snapshot — see power_level_from_event below for
    // why that distinction matters). Either field is left null when no event
    // of that type appears in `event_json`'s auth_events at all — a normal
    // outcome (the spec's default power-level rules then apply), distinct
    // from an auth_events entry that exists but could not be fetched, which
    // is a fail-closed condition (nullopt).
    struct AuthAncestorContext final
    {
        canonicaljson::Value power_levels{};
        canonicaljson::Value create{};
    };

    // Every valid auth_events entry is itself a state event, so determining
    // whether a given entry is "the" power_levels (or create) ancestor
    // requires fetching it to read its type — there is no way to rule an
    // entry out without resolving it. An entry that cannot be resolved is
    // therefore always fail-closed here (find_required), never skipped:
    // skipping it could silently treat a real, unfetched power-levels
    // ancestor as absent, defaulting the sender's power in a way the actual
    // room state would not support.
    [[nodiscard]] auto find_auth_ancestor_context(canonicaljson::Value const& event_json, AuthChainEventSource& source,
                                                  rooms::RoomVersionPolicy const& policy)
        -> std::optional<AuthAncestorContext>
    {
        auto result = AuthAncestorContext{};
        auto const* obj = value_is_object(event_json);
        if (obj == nullptr)
        {
            return result;
        }
        // Room v12 treats the create event as an implicit auth event derived
        // from room_id. Keep each candidate's explicit power-level ancestor,
        // but resolve creator privileges from that room's immutable create.
        if (policy.create_event_is_room_id)
        {
            if (auto const* room_id = string_member(*obj, "room_id"); room_id != nullptr)
            {
                if (room_id->size() < 2U || room_id->front() != '!')
                {
                    return std::nullopt;
                }
                auto const create_id = "$" + room_id->substr(1);
                auto const* create = source.find_required(create_id);
                if (create == nullptr)
                {
                    return std::nullopt;
                }
                auto const* create_obj = value_is_object(*create);
                if (create_obj == nullptr)
                {
                    return std::nullopt;
                }
                auto const* type = string_member(*create_obj, "type");
                auto const* state_key = string_member(*create_obj, "state_key");
                if (type == nullptr || *type != "m.room.create" || state_key == nullptr || !state_key->empty())
                {
                    return std::nullopt;
                }
                result.create = *create;
            }
        }
        auto const* auth = array_member(*obj, "auth_events");
        if (auth == nullptr)
        {
            return result;
        }
        for (auto const& entry : *auth)
        {
            auto const* id = auth_entry_event_id(entry);
            if (id == nullptr)
            {
                continue;
            }
            auto const* fetched = source.find_required(*id);
            if (fetched == nullptr)
            {
                return std::nullopt;
            }
            auto const* fetched_obj = value_is_object(*fetched);
            if (fetched_obj == nullptr)
            {
                continue;
            }
            auto const* type = string_member(*fetched_obj, "type");
            if (type == nullptr)
            {
                continue;
            }
            if (*type == "m.room.power_levels" && !value_has_content(result.power_levels))
            {
                result.power_levels = *fetched;
            }
            else if (*type == "m.room.create" && !value_has_content(result.create))
            {
                result.create = *fetched;
            }
        }
        return result;
    }

    // A conflicted event's sender power for the reverse topological power
    // ordering. Spec (rooms/v10.md — Definitions, "Reverse topological power
    // ordering", rule 1): "x's sender has greater power level than y's
    // sender, when looking at their respective auth_events" — the power MUST
    // come from the power_levels event in the
    // candidate's OWN auth_events, never from the candidate's own new
    // content (a self-elevating m.room.power_levels event would otherwise
    // rank itself by the level it grants itself, not the level it actually
    // holds) and never from a shared "unconflicted" or "resolved" map (an
    // event's auth_events may reference a different power_levels event than
    // whatever happens to be unconflicted at resolution time). Reuses
    // events::effective_sender_power (authorization.cpp) so this ordering
    // and the auth rules agree on every default: MSC4289 creator-infinite
    // power (decided from the implicit create event derived from room_id,
    // per MSC4289 — sender plus content.additional_creators), the pre-v12
    // content.creator default of 100, and 0 otherwise.
    // Returns nullopt (fail closed, per ADR-0063) when an auth_events entry
    // needed to answer the question could not be fetched.
    [[nodiscard]] auto power_level_from_event(StateEventReference const& event, AuthChainEventSource& source,
                                              rooms::RoomVersionPolicy const& policy) -> std::optional<std::int64_t>
    {
        auto const context = find_auth_ancestor_context(event.event_json, source, policy);
        if (!context.has_value())
        {
            return std::nullopt;
        }
        return effective_sender_power(context->power_levels, event.sender, context->create, policy);
    }

    // Finds the state event of type/state_key `wanted` among `event_obj`'s own
    // auth_events entries. Used by the iterative auth checks' fallback: "If a
    // (event_type, state_key) key that is required for checking the
    // authorisation rules is not present in the state, then the appropriate
    // state event from the event's auth_events is used if the auth event is
    // not rejected." (rooms/v10.md — Definitions, "Iterative auth checks".)
    // Uses the soft/optional lookup: an ancestor this event doesn't actually
    // need (it's just one of several auth_events entries being scanned) being
    // unreachable should not fail the whole resolution — only this one
    // event's own auth check degrades (as if the key were simply absent),
    // exactly as it already did before this fallback existed.
    [[nodiscard]] auto find_own_auth_event(canonicaljson::Object const& event_obj, AuthChainEventSource& source,
                                           StateKey const& wanted, std::string& found_event_id) -> canonicaljson::Value
    {
        auto const* auth = array_member(event_obj, "auth_events");
        if (auth == nullptr)
        {
            return {};
        }
        for (auto const& entry : *auth)
        {
            auto const* id = auth_entry_event_id(entry);
            if (id == nullptr)
            {
                continue;
            }
            auto const* candidate = source.find_optional(*id);
            if (candidate == nullptr)
            {
                continue;
            }
            auto const* obj = value_is_object(*candidate);
            if (obj == nullptr)
            {
                continue;
            }
            auto const* type = string_member(*obj, "type");
            auto const* state_key = string_member(*obj, "state_key");
            auto const key_type = type != nullptr ? *type : std::string{};
            auto const key_state_key = state_key != nullptr ? *state_key : std::string{};
            if (key_type == wanted.event_type && key_state_key == wanted.state_key)
            {
                found_event_id = *id;
                return *candidate;
            }
        }
        return {};
    }

    [[nodiscard]] auto find_own_auth_event(canonicaljson::Object const& event_obj, AuthChainEventSource& source,
                                           StateKey const& wanted) -> canonicaljson::Value
    {
        auto ignored_event_id = std::string{};
        return find_own_auth_event(event_obj, source, wanted, ignored_event_id);
    }

    [[nodiscard]] auto build_auth_event_map_from_state(canonicaljson::Value const& event, StateMap const& current_state,
                                                       AuthChainEventSource& source) -> AuthEventMap
    {
        auto result = AuthEventMap{};
        auto const* obj = value_is_object(event);
        if (obj == nullptr)
        {
            return result;
        }
        auto const* event_type = string_member(*obj, "type");
        auto const* sender = string_member(*obj, "sender");
        auto const* state_key = string_member(*obj, "state_key");

        // Spec (rooms/v10.md — Definitions, "Iterative auth checks"): "If a
        // (event_type, state_key) key that is required for checking the
        // authorisation rules is not present in the state, then the
        // appropriate state event from the event's auth_events is used if
        // the auth event is not rejected." `resolved` (`current_state`) is
        // tried first for every slot below; `find_own_auth_event` is the
        // fallback for whichever slots it leaves unset. This matters most
        // for room v12 (state-res v2.1), where the iterative auth checks
        // start from an empty map, so almost nothing is present in
        // `current_state` on the first pass.
        if (auto it = current_state.find(StateKey{"m.room.create", ""}); it != current_state.end())
        {
            result.create = it->second.event_json;
            result.create_event_id = it->second.event_id;
        }
        else
        {
            result.create = find_own_auth_event(*obj, source, StateKey{"m.room.create", ""}, result.create_event_id);
        }
        if (auto it = current_state.find(StateKey{"m.room.power_levels", ""}); it != current_state.end())
        {
            result.power_levels = it->second.event_json;
        }
        else
        {
            result.power_levels = find_own_auth_event(*obj, source, StateKey{"m.room.power_levels", ""});
        }
        if (auto it = current_state.find(StateKey{"m.room.join_rules", ""}); it != current_state.end())
        {
            result.join_rules = it->second.event_json;
        }
        else
        {
            result.join_rules = find_own_auth_event(*obj, source, StateKey{"m.room.join_rules", ""});
        }
        if (sender != nullptr)
        {
            if (auto it = current_state.find(StateKey{"m.room.member", *sender}); it != current_state.end())
            {
                result.sender_member = it->second.event_json;
            }
            else
            {
                result.sender_member = find_own_auth_event(*obj, source, StateKey{"m.room.member", *sender});
            }
        }
        if (state_key != nullptr && event_type != nullptr && *event_type == "m.room.member")
        {
            if (auto it = current_state.find(StateKey{"m.room.member", *state_key}); it != current_state.end())
            {
                result.target_member = it->second.event_json;
            }
            else
            {
                result.target_member = find_own_auth_event(*obj, source, StateKey{"m.room.member", *state_key});
            }

            // Spec: rooms/v11.md rule 4.3.1.5 — 3PID-token invites are authorized
            // against the m.room.third_party_invite event named by content's token.
            auto const* content = object_member_as_object(*obj, "content");
            auto const* third_party_invite =
                content == nullptr ? nullptr : object_member_as_object(*content, "third_party_invite");
            auto const* signed_obj =
                third_party_invite == nullptr ? nullptr : object_member_as_object(*third_party_invite, "signed");
            auto const* token = signed_obj == nullptr ? nullptr : string_member(*signed_obj, "token");
            if (token != nullptr)
            {
                if (auto it = current_state.find(StateKey{"m.room.third_party_invite", *token});
                    it != current_state.end())
                {
                    result.third_party_invite = it->second.event_json;
                }
                else
                {
                    result.third_party_invite =
                        find_own_auth_event(*obj, source, StateKey{"m.room.third_party_invite", *token});
                }
            }

            // Spec: server-server-api.md § Auth events selection — "If membership
            // is join, content.join_authorised_via_users_server is present, and
            // the room version supports restricted rooms, then the m.room.member
            // event with state_key matching content.join_authorised_via_users_server".
            // Auth rule 4.3.5.2 rejects the restricted join without it, so state
            // resolution has to offer it or every restricted join in the conflicted
            // set fails auth and room state diverges across servers. No room-version
            // gate is needed here: the only rule that reads this member event is the
            // restricted/knock_restricted join branch, which no pre-v8 room can reach.
            auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
            auto const* authorising_user =
                content == nullptr ? nullptr : string_member(*content, "join_authorised_via_users_server");
            if (membership != nullptr && *membership == "join" && authorising_user != nullptr &&
                !authorising_user->empty())
            {
                if (auto it = current_state.find(StateKey{"m.room.member", *authorising_user});
                    it != current_state.end())
                {
                    result.authorising_user_member = it->second.event_json;
                }
                else
                {
                    result.authorising_user_member =
                        find_own_auth_event(*obj, source, StateKey{"m.room.member", *authorising_user});
                }
            }
        }
        return result;
    }

    [[nodiscard]] auto mainline_order_with_source(std::vector<StateEventReference>& events, StateMap const& resolved,
                                                  AuthChainEventSource& source, StateResolutionLimits const& limits)
        -> bool
    {
        auto const pl_key = StateKey{"m.room.power_levels", ""};
        auto mainline = std::vector<std::string>{};
        if (auto const it = resolved.find(pl_key); it != resolved.end() && value_has_content(it->second.event_json))
        {
            auto collected = collect_mainline_power_events(it->second.event_id, it->second.event_json, source,
                                                           limits.max_mainline_auth_chain_depth);
            if (!collected.has_value())
            {
                return false;
            }
            mainline = std::move(*collected);
        }

        auto mainline_depth = std::unordered_map<std::string, std::size_t>{};
        mainline_depth.reserve(mainline.size());
        for (std::size_t i = 0; i < mainline.size(); ++i)
        {
            mainline_depth.emplace(mainline[i], i);
        }

        auto const infinity = std::numeric_limits<std::size_t>::max();
        auto position_by_event_id = std::unordered_map<std::string, std::size_t>{};
        position_by_event_id.reserve(events.size());
        for (auto const& event : events)
        {
            auto position = infinity;
            if (!mainline.empty())
            {
                auto const* current = value_is_object(event.event_json);
                if (current == nullptr)
                {
                    return false;
                }
                auto visited = std::unordered_set<std::string>{};
                auto found_position = false;
                for (std::size_t hop = 0; hop < limits.max_mainline_auth_chain_depth; ++hop)
                {
                    auto const ancestor = power_levels_auth_ancestor(*current, source);
                    if (!ancestor.valid)
                    {
                        return false;
                    }
                    if (!ancestor.event_id.has_value())
                    {
                        found_position = true;
                        break;
                    }
                    if (auto const position_it = mainline_depth.find(*ancestor.event_id);
                        position_it != mainline_depth.end())
                    {
                        position = position_it->second;
                        found_position = true;
                        break;
                    }
                    if (!visited.insert(*ancestor.event_id).second)
                    {
                        return false;
                    }
                    auto const* json = source.find_required(*ancestor.event_id);
                    auto const* object = json != nullptr ? value_is_object(*json) : nullptr;
                    auto const* type = object != nullptr ? string_member(*object, "type") : nullptr;
                    auto const* state_key = object != nullptr ? string_member(*object, "state_key") : nullptr;
                    if (object == nullptr || type == nullptr || *type != "m.room.power_levels" ||
                        state_key == nullptr || !state_key->empty())
                    {
                        return false;
                    }
                    current = object;
                }
                if (!found_position)
                {
                    return false;
                }
            }
            position_by_event_id.emplace(event.event_id, position);
        }

        auto const compare = [&position_by_event_id](StateEventReference const& a,
                                                     StateEventReference const& b) -> bool {
            auto const pos_a = position_by_event_id.at(a.event_id);
            auto const pos_b = position_by_event_id.at(b.event_id);
            if (pos_a != pos_b)
            {
                return pos_a > pos_b;
            }
            if (a.origin_server_ts != b.origin_server_ts)
            {
                return a.origin_server_ts < b.origin_server_ts;
            }
            return a.event_id < b.event_id;
        };
        std::stable_sort(events.begin(), events.end(), compare);
        return !source.missing();
    }

} // namespace

auto state_key_matches(StateKey const& left, StateKey const& right) noexcept -> bool
{
    return left.event_type == right.event_type && left.state_key == right.state_key;
}

auto state_group_contains(StateGroup const& group, StateKey const& key) noexcept -> bool
{
    return state_group_event(group, key) != nullptr;
}

auto state_group_event(StateGroup const& group, StateKey const& key) noexcept -> StateEventReference const*
{
    for (auto const& event : group.state)
    {
        if (state_key_matches(event.key, key))
        {
            return &event;
        }
    }

    return nullptr;
}

// Validate request size against public resource caps. Returns an explicit error
// instead of starting the O(N log N) or O(N^2) work on an adversarial payload.
[[nodiscard]] auto validate_state_resolution_request(StateResolutionRequest const& request)
    -> std::optional<std::string>
{
    auto const& limits = request.limits;
    if (request.state_groups.size() > limits.max_state_groups)
    {
        return "too many state groups";
    }

    auto total_events = std::size_t{0U};
    for (auto const& group : request.state_groups)
    {
        if (group.state.size() > limits.max_events_per_state_group)
        {
            return "too many events in state group";
        }
        // Keep the subtraction guarded so no untrusted input can overflow the
        // aggregate count while checking the configured ceiling.
        if (total_events > limits.max_total_state_events ||
            group.state.size() > limits.max_total_state_events - total_events)
        {
            return "too many total state events";
        }
        total_events += group.state.size();
    }
    return std::nullopt;
}

auto resolve_state(StateResolutionRequest const& request) -> StateResolutionResult
{
    auto result = [&]() -> StateResolutionResult {
        if (request.room_version.empty())
        {
            return {false, {}, "room version is required"};
        }
        if (auto error = validate_state_resolution_request(request); error.has_value())
        {
            return {false, {}, *error};
        }
        if (request.state_groups.empty())
        {
            return {true, {}, {}};
        }

        auto resolved = StateMap{};
        for (auto const& group : request.state_groups)
        {
            for (auto const& event : group.state)
            {
                if (event.event_id.empty())
                {
                    return {false, {}, "state event id is required"};
                }

                auto const existing = resolved.find(event.key);
                if (existing == resolved.end())
                {
                    resolved.emplace(event.key, event);
                    continue;
                }
                if (existing->second.event_id == event.event_id)
                {
                    continue;
                }

                existing->second = select_v1_winner(existing->second, event);
            }
        }

        auto resolved_state = std::vector<StateEventReference>{};
        resolved_state.reserve(resolved.size());
        for (auto const& [key, event] : resolved)
        {
            resolved_state.push_back(event);
        }
        return {true, std::move(resolved_state), {}};
    }();
    log_diagnostic(result.resolved ? "resolve_state.resolved" : "resolve_state.failed",
                   {
                       {"room_version", request.room_version,                         false},
                       {"events",       std::to_string(result.resolved_state.size()), false},
                       {"reason",       result.reason,                                false}
    });
    return result;
}

auto partition_conflicted_state(std::vector<StateGroup> const& groups, StateResolutionLimits const& limits)
    -> std::pair<StateMap, StateMap>
{
    // Spec (rooms/v10.md — Definitions, "Unconflicted state map and
    // conflicted state set"): "If a given key K is present in every Si with
    // the same value V in each state map, then the pair (K, V) belongs to the
    // unconflicted state map. Otherwise, V belongs to the conflicted state
    // set." A key is therefore unconflicted only when EVERY group holds it
    // AND every group holds the same single event. The decision is taken per
    // key from the complete tally below, never incrementally while walking
    // the groups: an incremental decision lets a later group that repeats an
    // earlier value re-admit a key that another group already disputed.
    struct KeyTally final
    {
        StateEventReference first_event{};
        std::unordered_set<std::string> event_ids{};
        std::size_t groups_containing{0};
        std::size_t last_group_counted{0};
    };

    auto total_events = std::size_t{0U};
    if (groups.size() > limits.max_state_groups)
    {
        return {};
    }
    for (auto const& group : groups)
    {
        if (group.state.size() > limits.max_events_per_state_group || total_events > limits.max_total_state_events ||
            group.state.size() > limits.max_total_state_events - total_events)
        {
            return {};
        }
        total_events += group.state.size();
    }

    auto tallies = std::unordered_map<StateKey, KeyTally, StateKeyHash>{};
    tallies.reserve(groups.size() * 8U);

    for (std::size_t group_index = 0; group_index < groups.size(); ++group_index)
    {
        for (auto const& event : groups[group_index].state)
        {
            auto [it, inserted] = tallies.try_emplace(event.key);
            auto& tally = it->second;
            if (tallies.size() > limits.max_conflicted_state_keys)
            {
                // Fail fast: too many distinct state keys to resolve safely.
                return {};
            }
            if (inserted)
            {
                tally.first_event = event;
            }
            // A group counts once per key however many entries it holds for
            // it (a group holding two different events for one key is itself
            // a disagreement and shows up as two distinct event ids).
            if (inserted || tally.last_group_counted != group_index)
            {
                ++tally.groups_containing;
                tally.last_group_counted = group_index;
            }
            tally.event_ids.insert(event.event_id);
        }
    }

    auto unconflicted = StateMap{};
    auto conflicted = StateMap{};
    for (auto& [key, tally] : tallies)
    {
        if (tally.groups_containing == groups.size() && tally.event_ids.size() == 1U)
        {
            unconflicted.emplace(key, std::move(tally.first_event));
        }
        else
        {
            // `conflicted` is a key index: one representative event per
            // conflicted key. The full conflicted set (every distinct value
            // of each key) is gathered from the groups by the caller.
            conflicted.emplace(key, std::move(tally.first_event));
        }
    }

    return {std::move(unconflicted), std::move(conflicted)};
}

auto reverse_topological_power_sort(std::vector<StateEventReference> const& conflicted,
                                    EventJsonIndex const& known_events, EventLookupFn const& event_lookup,
                                    rooms::RoomVersionPolicy const& policy, StateResolutionLimits const& limits)
    -> std::optional<std::vector<StateEventReference>>
{
    // Powers are computed once up front, rather than inside the sort
    // comparator, for two reasons: a strict weak ordering comparator has no
    // clean way to report a fail-closed condition (a missing auth_events
    // ancestor — see power_level_from_event), and recomputing per comparison
    // would re-walk the same auth_events on every comparator call.
    if (conflicted.size() > limits.max_conflicted_state_keys)
    {
        return std::nullopt;
    }
    auto source = AuthChainEventSource{known_events, event_lookup, limits.max_auth_chain_walk_events};
    auto power_by_id = std::unordered_map<std::string, std::int64_t>{};
    power_by_id.reserve(conflicted.size());
    for (auto const& event : conflicted)
    {
        auto const power = power_level_from_event(event, source, policy);
        if (!power.has_value())
        {
            return std::nullopt;
        }
        power_by_id.emplace(event.event_id, *power);
    }

    // Spec (rooms/v10.md — Definitions, "Reverse topological power ordering"):
    // "the lexicographically smallest topological ordering based on the DAG
    // formed by auth events ... ordered from earliest event to latest ...
    // found by sorting the events using Kahn's algorithm for topological
    // sorting, and at each step selecting, among all the candidate vertices,
    // the smallest vertex using the above comparison relation."
    // The DAG is the auth_events graph restricted to `conflicted`: an edge
    // runs from auth event A to event E when A is in E's auth_events and both
    // are in the set, so an auth event is always emitted before any event
    // that cites it, whatever the two senders' power levels.
    auto const count = conflicted.size();
    auto index_by_id = std::unordered_map<std::string, std::size_t>{};
    index_by_id.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
        if (!index_by_id.emplace(conflicted[i].event_id, i).second)
        {
            // Two entries with one event id cannot be ordered
            // deterministically and dropping either would be silent
            // corruption: fail closed.
            log_diagnostic("reverse_topological_power_sort.rejected",
                           {
                               {"reason", "duplicate event id in the set to be ordered", false}
            });
            return std::nullopt;
        }
    }

    auto dependants = std::vector<std::vector<std::size_t>>(count);
    auto unmet_auth_events = std::vector<std::size_t>(count, 0U);
    for (std::size_t i = 0; i < count; ++i)
    {
        auto const* obj = value_is_object(conflicted[i].event_json);
        auto const* auth = obj != nullptr ? array_member(*obj, "auth_events") : nullptr;
        if (auth == nullptr)
        {
            continue;
        }
        for (auto const& entry : *auth)
        {
            auto const* auth_id = auth_entry_event_id(entry);
            if (auth_id == nullptr)
            {
                continue;
            }
            auto const found = index_by_id.find(*auth_id);
            if (found == index_by_id.end())
            {
                continue;
            }
            // A repeated entry adds the edge twice; both the increment and
            // the decrement below run once per occurrence, so it balances.
            dependants[found->second].push_back(i);
            ++unmet_auth_events[i];
        }
    }

    // x < y under the spec's comparison relation. Event ids are unique here,
    // so this is a strict total order and the result is deterministic
    // whatever order `conflicted` arrives in.
    auto const precedes = [&conflicted, &power_by_id](std::size_t x, std::size_t y) -> bool {
        auto const& a = conflicted[x];
        auto const& b = conflicted[y];
        auto const pa = power_by_id.at(a.event_id);
        auto const pb = power_by_id.at(b.event_id);
        if (pa != pb)
        {
            return pa > pb;
        }
        if (a.origin_server_ts != b.origin_server_ts)
        {
            return a.origin_server_ts < b.origin_server_ts;
        }
        // Rule 3: final tie-break is the lexicographically smaller event_id.
        return a.event_id < b.event_id;
    };

    auto ready = std::set<std::size_t, decltype(precedes)>{precedes};
    for (std::size_t i = 0; i < count; ++i)
    {
        if (unmet_auth_events[i] == 0U)
        {
            ready.insert(i);
        }
    }

    auto sorted = std::vector<StateEventReference>{};
    sorted.reserve(count);
    while (!ready.empty())
    {
        auto const next = *ready.begin();
        ready.erase(ready.begin());
        sorted.push_back(conflicted[next]);
        for (auto const dependant : dependants[next])
        {
            if (--unmet_auth_events[dependant] == 0U)
            {
                ready.insert(dependant);
            }
        }
    }

    if (sorted.size() != count)
    {
        // Events remain whose auth_events never became satisfiable: the
        // auth graph has a cycle, which no valid room history can contain
        // (an event's id is a hash over its auth_events). Fail closed rather
        // than emit a partial ordering.
        log_diagnostic("reverse_topological_power_sort.rejected",
                       {
                           {"reason", "cycle in the auth_events graph", false}
        });
        return std::nullopt;
    }
    return sorted;
}

auto is_power_event(StateEventReference const& event) noexcept -> bool
{
    if (event.key.event_type == "m.room.power_levels" || event.key.event_type == "m.room.join_rules")
    {
        return event.key.state_key.empty();
    }
    if (event.key.event_type != "m.room.member")
    {
        return false;
    }
    auto const* obj = value_is_object(event.event_json);
    if (obj == nullptr)
    {
        return false;
    }
    auto const* content = object_member_as_object(*obj, "content");
    if (content == nullptr)
    {
        return false;
    }
    auto const* membership = string_member(*content, "membership");
    if (membership == nullptr)
    {
        return false;
    }
    return (*membership == "leave" || *membership == "ban") && event.sender != event.key.state_key;
}

auto build_event_json_index(std::vector<StateGroup> const& groups) -> EventJsonIndex
{
    auto index = EventJsonIndex{};
    for (auto const& group : groups)
    {
        for (auto const& event : group.state)
        {
            if (!event.event_id.empty() && value_has_content(event.event_json))
            {
                index.emplace(event.event_id, std::cref(event.event_json));
            }
        }
    }
    return index;
}

auto mainline_order(std::vector<StateEventReference>& events, StateMap const& resolved,
                    EventJsonIndex const& events_by_id, StateResolutionLimits const& limits) -> void
{
    auto const no_lookup = EventLookupFn{};
    auto source = AuthChainEventSource{events_by_id, no_lookup, limits.max_auth_chain_walk_events};
    std::ignore = mainline_order_with_source(events, resolved, source, limits);
}

auto resolve_state_v2(StateResolutionRequest const& request, rooms::RoomVersionPolicy const& policy)
    -> StateResolutionResult
{
    if (auto error = validate_state_resolution_request(request); error.has_value())
    {
        log_diagnostic("resolve_state_v2.rejected",
                       {
                           {"room_version", request.room_version, false},
                           {"reason",       *error,               false}
        });
        return {false, {}, *error};
    }

    if (request.state_groups.empty())
    {
        log_diagnostic("resolve_state_v2.empty", {
                                                     {"room_version", request.room_version, false}
        });
        return {true, {}, {}};
    }

    // Step 1: Partition into conflicted and unconflicted
    auto [unconflicted, conflicted_events] = partition_conflicted_state(request.state_groups, request.limits);

    // Step 3: Collect all conflicted events and sort by reverse topological power ordering
    if (unconflicted.empty() && conflicted_events.empty())
    {
        // partition_conflicted_state aborted because there were too many
        // distinct state keys to process safely.
        log_diagnostic("resolve_state_v2.rejected",
                       {
                           {"room_version", request.room_version,  false},
                           {"reason",       "too many state keys", false}
        });
        return {false, {}, "too many state keys"};
    }

    auto all_conflicted = std::vector<StateEventReference>{};
    all_conflicted.reserve(conflicted_events.size());
    auto seen_conflicted_ids = std::unordered_map<StateKey, std::unordered_set<std::string>, StateKeyHash>{};
    for (auto const& group : request.state_groups)
    {
        for (auto const& event : group.state)
        {
            if (!conflicted_events.contains(event.key))
            {
                continue;
            }

            auto& seen_ids = seen_conflicted_ids.try_emplace(event.key).first->second;
            if (seen_ids.insert(event.event_id).second)
            {
                all_conflicted.push_back(event);
                if (all_conflicted.size() > request.limits.max_conflicted_state_keys)
                {
                    log_diagnostic("resolve_state_v2.rejected", {
                                                                    {"room_version", request.room_version,         false},
                                                                    {"reason",       "too many conflicted events", false}
                    });
                    return {false, {}, "too many conflicted events"};
                }
            }
        }
    }

    if (all_conflicted.empty())
    {
        // No conflicted state at all: the resolved state is exactly the
        // unconflicted state map (spec Algorithm step 5, trivially, since
        // there is nothing else to update). Skip the auth-chain walk
        // entirely rather than running it unconditionally — the auth
        // difference and conflicted state subgraph only matter when there is
        // something in dispute, and computing them anyway would require
        // every event in every submitted state group to have a fully
        // walkable auth chain even when nothing needs resolving, which is
        // both wasted work and an unnecessary fail-closed risk for callers
        // (e.g. the mainline-depth-bound test) that never triggered a
        // conflict in the first place.
        auto result_state = std::vector<StateEventReference>{};
        result_state.reserve(unconflicted.size());
        for (auto const& [key, event] : unconflicted)
        {
            result_state.push_back(event);
        }
        log_diagnostic("resolve_state_v2.resolved", {
                                                        {"room_version", request.room_version,                false},
                                                        {"events",       std::to_string(result_state.size()), false}
        });
        return {true, std::move(result_state), {}};
    }

    // Auth chain walk: computes the auth difference (and, for v12, the
    // conflicted state subgraph) so power events reachable only through auth
    // chains are not silently ignored. Backed by the submitted state groups
    // plus request.event_lookup for anything else.
    auto const known_index = build_event_json_index(request.state_groups);
    auto source = AuthChainEventSource{known_index, request.event_lookup, request.limits.max_auth_chain_walk_events};

    // Spec (rooms/v10.md — Definitions, "Auth difference"): "∪Ci − ∩Ci",
    // where Ci is the full auth chain of state group i.
    auto const auth_difference =
        compute_auth_difference(request.state_groups, source, request.limits.max_auth_chain_walk_events);
    if (!auth_difference.has_value() || source.missing())
    {
        log_diagnostic("resolve_state_v2.rejected",
                       {
                           {"room_version", request.room_version,                                  false},
                           {"reason",       "missing or unreachable event during auth-chain walk", false}
        });
        return {false, {}, "state-res v2: missing or unreachable event during auth-chain walk"};
    }

    // Spec (rooms/v10.md — Definitions, "Full conflicted set"): "the union of
    // the conflicted state set and the auth difference." Room v12 additionally
    // folds in the conflicted state subgraph (rooms/v12.md).
    auto full_conflicted_by_id = std::unordered_map<std::string, StateEventReference>{};
    for (auto const& event : all_conflicted)
    {
        full_conflicted_by_id.emplace(event.event_id, event);
    }
    for (auto const& id : *auth_difference)
    {
        if (full_conflicted_by_id.contains(id))
        {
            continue;
        }
        auto ref = materialize_ref(id, source);
        if (!ref.has_value())
        {
            log_diagnostic("resolve_state_v2.rejected",
                           {
                               {"room_version", request.room_version,                      false},
                               {"reason",       "auth difference event could not be read", false}
            });
            return {false, {}, "state-res v2: auth difference event could not be read"};
        }
        full_conflicted_by_id.emplace(id, std::move(*ref));
    }

    auto const is_v2_1 = policy.state_resolution == rooms::StateResolutionAlgorithm::v2_1;
    if (is_v2_1)
    {
        auto conflicted_ids = std::unordered_set<std::string>{};
        conflicted_ids.reserve(all_conflicted.size());
        for (auto const& event : all_conflicted)
        {
            conflicted_ids.insert(event.event_id);
        }
        auto const subgraph =
            compute_conflicted_state_subgraph(conflicted_ids, source, request.limits.max_auth_chain_walk_events);
        if (!subgraph.has_value() || source.missing())
        {
            log_diagnostic("resolve_state_v2.rejected",
                           {
                               {"room_version", request.room_version,                    false},
                               {"reason",       "conflicted state subgraph walk failed", false}
            });
            return {false, {}, "state-res v2: conflicted state subgraph walk failed"};
        }
        for (auto const& id : *subgraph)
        {
            if (full_conflicted_by_id.contains(id))
            {
                continue;
            }
            auto ref = materialize_ref(id, source);
            if (!ref.has_value())
            {
                log_diagnostic("resolve_state_v2.rejected",
                               {
                                   {"room_version", request.room_version,                          false},
                                   {"reason",       "conflicted subgraph event could not be read", false}
                });
                return {false, {}, "state-res v2: conflicted subgraph event could not be read"};
            }
            full_conflicted_by_id.emplace(id, std::move(*ref));
        }
    }

    // Iterative auth checks (spec rooms/v10 — Algorithm): apply each event to
    // the running resolved state if it passes the authorization rules. All
    // candidates for each key must be iterated — a later (lower-power)
    // candidate can still overwrite an earlier one if it passes auth. Do NOT
    // short-circuit on resolved.contains(key).
    // Spec (rooms/v12.md — State resolution, modification 1): "The iterative
    // auth checks algorithm ... now starts with an empty state map instead of
    // the unconflicted state map" for room v12; versions 2-11 still start
    // from the unconflicted state map.
    auto resolved = is_v2_1 ? StateMap{} : unconflicted;
    if (is_v2_1)
    {
        // v12 (MSC4291) events never name m.room.create in their own
        // auth_events (rooms/v12.md rule 3.2: "MUST NOT be selected" — the
        // room_id implies it instead), so build_auth_event_map_from_state's
        // per-candidate auth_events fallback can never find it while
        // `resolved` has no create entry of its own. Left unseeded, the
        // very first iterative auth check for ANY v12 candidate would see
        // `auth_events.create` empty and deny every event with "room has no
        // create event" (authorization.cpp Step 2), regardless of the
        // candidate's actual validity — state resolution could never
        // recompute any v12 room's state at all.
        //
        // Spec (rooms/v12.md rule 2): "If the event's room_id is not an
        // event ID for an accepted... m.room.create event, with the sigil
        // `!` instead of `$`, reject" — the room ID literally IS the create
        // event's own reference hash under a different sigil. That is the
        // primary source of truth used below: swap the sigil, fetch that
        // exact event id through the same fail-closed AuthChainEventSource
        // every other auth-chain lookup in this function uses, and seed
        // `resolved` with it. If `room_id` is present but the derived event
        // cannot be fetched, this fails closed rather than falling back to
        // `unconflicted` — the whole point of deriving from room_id is that
        // a submitted state group's agreement is exactly what a hostile or
        // partial state set (a later phase's remote-supplied `/state_ids`
        // claim) can omit or forge, so tolerating its absence here would
        // silently reintroduce the failure this fix exists to close. The
        // `unconflicted` fallback below is kept ONLY for a request with no
        // `room_id` at all — see the comment on it.
        if (request.room_id.size() >= 2U && request.room_id.front() == '!')
        {
            auto const create_event_id = "$" + request.room_id.substr(1U);
            auto create_ref = materialize_ref(create_event_id, source);
            if (!create_ref.has_value() || source.missing() || create_ref->key.event_type != "m.room.create" ||
                !create_ref->key.state_key.empty())
            {
                log_diagnostic("resolve_state_v2.rejected",
                               {
                                   {"room_version", request.room_version,                                       false},
                                   {"reason",       "room v12 create event (derived from room_id) unreachable", false}
                });
                return {false, {}, "state-res v2: room v12 create event (derived from room_id) could not be fetched"};
            }
            resolved[create_ref->key] = *create_ref;
        }
        else if (auto const it = unconflicted.find(StateKey{"m.room.create", ""}); it != unconflicted.end())
        {
            // Fallback ONLY when `room_id` is absent. Every real caller
            // (compute_state_before, recompute_current_state) always
            // supplies it, so this path is unreachable from untrusted
            // federation input; it exists so a caller using synthetic
            // event ids that do not follow the MSC4291 room_id convention
            // (this module's own unit tests) does not need every fixture
            // migrated just to keep resolving.
            resolved[it->first] = it->second;
        }
    }
    auto apply_iterative_auth_checks = [&resolved, &policy,
                                        &source](std::vector<StateEventReference> const& sorted) -> void {
        for (auto const& event : sorted)
        {
            // Events whose JSON representation is null/invalid cannot be applied.
            if (!value_has_content(event.event_json))
            {
                continue;
            }

            auto auth_map = build_auth_event_map_from_state(event.event_json, resolved, source);
            auto const decision = authorize_event_against_auth_events(event.event_json, policy, auth_map);
            if (decision.allowed)
            {
                resolved[event.key] = event;
            }
        }
    };

    // Algorithm step 1: "Select the set X of all power events that appear in
    // the full conflicted set. For each such power event P, enlarge X by
    // adding the events in the auth chain of P which also belong to the full
    // conflicted set." Sort X by the reverse topological power ordering.
    auto power_events = std::vector<StateEventReference>{};
    auto selected_ids = std::unordered_set<std::string>{};
    for (auto const& [id, event] : full_conflicted_by_id)
    {
        if (is_power_event(event))
        {
            power_events.push_back(event);
            selected_ids.insert(id);
        }
    }

    auto enlarge_queue = std::vector<std::string>{selected_ids.begin(), selected_ids.end()};
    while (!enlarge_queue.empty())
    {
        auto const id = std::move(enlarge_queue.back());
        enlarge_queue.pop_back();
        auto const& event = full_conflicted_by_id.at(id);
        auto const chain = walk_auth_chain(event.event_json, source, request.limits.max_auth_chain_walk_events);
        if (!chain.has_value() || source.missing())
        {
            log_diagnostic("resolve_state_v2.rejected", {
                                                            {"room_version", request.room_version,               false},
                                                            {"reason",       "enlarge-X auth chain walk failed", false}
            });
            return {false, {}, "state-res v2: enlarge-X auth chain walk failed"};
        }
        for (auto const& ancestor_id : *chain)
        {
            auto const it = full_conflicted_by_id.find(ancestor_id);
            if (it == full_conflicted_by_id.end())
            {
                continue;
            }
            if (selected_ids.insert(ancestor_id).second)
            {
                power_events.push_back(it->second);
                enlarge_queue.push_back(ancestor_id);
            }
        }
    }

    auto remaining_events = std::vector<StateEventReference>{};
    for (auto const& [id, event] : full_conflicted_by_id)
    {
        if (!selected_ids.contains(id))
        {
            remaining_events.push_back(event);
        }
    }

    // The reverse topological power ordering sort reads each candidate's own
    // auth_events, regardless of algorithm variant — only the iterative auth
    // checks' starting map changes for v12 (modification 1 above).
    auto sorted_power_result =
        reverse_topological_power_sort(power_events, known_index, request.event_lookup, policy, request.limits);
    if (!sorted_power_result.has_value())
    {
        auto const sort_failure_fields = std::vector<observability::StructuredLogField>{
            {"room_version", request.room_version,                           false},
            {"reason",       "reverse topological power sort failed closed", false},
        };
        log_diagnostic("resolve_state_v2.rejected", sort_failure_fields);
        return {false, {}, "state-res v2: reverse topological power sort failed closed"};
    }
    auto const& sorted_power = *sorted_power_result;

    // Algorithm step 2: auth-check the power events first to obtain the
    // partially resolved state.
    apply_iterative_auth_checks(sorted_power);

    // Algorithm step 3: order only the remaining events by the mainline
    // ordering based on the power levels in the partially resolved state.
    if (!mainline_order_with_source(remaining_events, resolved, source, request.limits) || source.missing())
    {
        log_diagnostic("resolve_state_v2.rejected", {
                                                        {"room_version", request.room_version,                       false},
                                                        {"reason",       "mainline ordering auth-chain walk failed", false}
        });
        return {false, {}, "state-res v2: mainline ordering auth-chain walk failed"};
    }

    // Algorithm step 4: auth-check the remaining events against the partially
    // resolved state.
    apply_iterative_auth_checks(remaining_events);

    // Algorithm step 5: "Update the result by replacing any event with the
    // event with the same key from the unconflicted state map, if such an
    // event exists, to get the final resolved state." Unlike the
    // pre-auth-difference implementation, this is NOT a no-op:
    // full_conflicted_by_id can contain auth-chain-only events that share a
    // key with an unconflicted entry (e.g. an outdated power_levels ancestor
    // used only to authorize a later event), and step 5 makes sure the true
    // unconflicted value always wins that key in the final result.
    for (auto const& [key, event] : unconflicted)
    {
        resolved[key] = event;
    }

    // Build result
    auto result_state = std::vector<StateEventReference>{};
    for (auto const& [key, event] : resolved)
    {
        result_state.push_back(event);
    }

    log_diagnostic("resolve_state_v2.resolved", {
                                                    {"room_version", request.room_version,                false},
                                                    {"events",       std::to_string(result_state.size()), false}
    });
    return {true, std::move(result_state), {}};
}

auto state_resolution_summary(StateResolutionResult const& result) -> std::string
{
    return "state resolution: resolved=" + std::string{result.resolved ? "true" : "false"} +
           " events=" + std::to_string(result.resolved_state.size()) + " reason=" + result.reason;
}

} // namespace merovingian::events
