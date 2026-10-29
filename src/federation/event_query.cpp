// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/event_query.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/limits.hpp"
#include "merovingian/events/redaction.hpp"
#include "merovingian/federation/server_acl.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("event_query", event, fields, severity);
    }

    [[nodiscard]] auto parsed_value(std::string_view json) -> std::optional<canonicaljson::Value>
    {
        auto parsed = canonicaljson::parse_lossless(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        return std::move(parsed.value);
    }

    [[nodiscard]] auto serialize(canonicaljson::Object object) -> std::string
    {
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
        return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
    }

    [[nodiscard]] auto now_ms() -> std::int64_t
    {
        return static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    [[nodiscard]] auto member_value(canonicaljson::Object const& object, std::string_view key)
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

    [[nodiscard]] auto find_event(database::PersistentStore const& store, std::string_view event_id)
        -> database::PersistentEvent const*
    {
        auto const it = store.events.find(event_id);
        return it == store.events.end() ? nullptr : &*it;
    }

    // The server name of a `@localpart:server_name` user ID: everything after the
    // FIRST colon, so a server name that carries a port ("@u:host:8448") stays
    // whole. Empty when the ID has no server part.
    [[nodiscard]] auto user_id_server_name(std::string_view user_id) -> std::string_view
    {
        if (user_id.size() < 2U || user_id.front() != '@')
        {
            return {};
        }
        auto const colon = user_id.find(':');
        if (colon == std::string_view::npos || colon + 1U >= user_id.size())
        {
            return {};
        }
        return user_id.substr(colon + 1U);
    }

    // The string at `content.<key>` of a stored event's JSON, when present.
    [[nodiscard]] auto content_string(std::string_view event_json, std::string_view key) -> std::optional<std::string>
    {
        auto const value = parsed_value(event_json);
        if (!value.has_value())
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&value->storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* content_value = member_value(*object, "content");
        auto const* content =
            content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
        if (content == nullptr)
        {
            return std::nullopt;
        }
        auto const* field = member_value(*content, key);
        auto const* text = field == nullptr ? nullptr : std::get_if<std::string>(&field->storage());
        return text == nullptr ? std::nullopt : std::optional<std::string>{*text};
    }

    // True when the room's CURRENT state has a `join` m.room.member event for a
    // user on `origin`. Reads the current-state table, not the memberships
    // projection, so the answer is the room's state and nothing derived from it.
    [[nodiscard]] auto origin_has_joined_user(database::PersistentStore const& store, std::string_view room_id,
                                              std::string_view origin) -> bool
    {
        auto candidate_event_ids = std::unordered_set<std::string_view>{};
        for (auto const& state : store.state)
        {
            if (state.room_id == room_id && state.event_type == "m.room.member" &&
                user_id_server_name(state.state_key) == origin)
            {
                candidate_event_ids.insert(state.event_id);
            }
        }
        if (candidate_event_ids.empty())
        {
            return false;
        }
        for (auto const& event : store.events)
        {
            if (event.room_id == room_id && candidate_event_ids.contains(event.event_id) &&
                content_string(event.json, "membership") == "join")
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto room_is_world_readable(database::PersistentStore const& store, std::string_view room_id) -> bool
    {
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id || state.event_type != "m.room.history_visibility" || !state.state_key.empty())
            {
                continue;
            }
            auto const* event = find_event(store, state.event_id);
            return event != nullptr && content_string(event->json, "history_visibility") == "world_readable";
        }
        return false;
    }

    constexpr auto forbidden_body =
        std::string_view{R"({"errcode":"M_FORBIDDEN","error":"The requesting server is not in the room"})"};

    [[nodiscard]] auto forbidden_result() -> RoomReadResult
    {
        return {RoomReadStatus::forbidden, {}};
    }

    [[nodiscard]] auto not_found_result() -> RoomReadResult
    {
        return {RoomReadStatus::not_found, {}};
    }

    [[nodiscard]] auto malformed_result() -> RoomReadResult
    {
        return {RoomReadStatus::malformed, {}};
    }

    // Reads `key` as a list of strings. Absent, not a list, or any non-string
    // element gives nullopt.
    [[nodiscard]] auto string_list_member(canonicaljson::Object const& object, std::string_view key)
        -> std::optional<std::vector<std::string>>
    {
        auto const* value = member_value(object, key);
        auto const* array = value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&value->storage());
        if (array == nullptr)
        {
            return std::nullopt;
        }
        auto strings = std::vector<std::string>{};
        strings.reserve(array->size());
        for (auto const& element : *array)
        {
            auto const* text = std::get_if<std::string>(&element.storage());
            if (text == nullptr)
            {
                return std::nullopt;
            }
            strings.push_back(*text);
        }
        return strings;
    }

    // Reads the optional integer `key`: `fallback` when absent, nullopt when present
    // but not an integer.
    [[nodiscard]] auto optional_integer_member(canonicaljson::Object const& object, std::string_view key,
                                               std::int64_t fallback) -> std::optional<std::int64_t>
    {
        auto const* value = member_value(object, key);
        if (value == nullptr)
        {
            return fallback;
        }
        auto const* number = std::get_if<std::int64_t>(&value->storage());
        return number == nullptr ? std::nullopt : std::optional<std::int64_t>{*number};
    }

    // Computes the transitive closure of auth events reachable from `seed_ids`
    // by following PersistentEvent::auth_event_ids. The traversal is breadth
    // first from the seed order so the result is deterministic, and every ID is
    // emitted at most once. Seeds (and references) that do not resolve to a
    // stored event are skipped rather than emitted, so callers never surface a
    // dangling ID for which no PDU body exists.
    [[nodiscard]] auto collect_auth_chain(database::PersistentStore const& store,
                                          std::vector<std::string> const& seed_ids,
                                          std::size_t limit = std::numeric_limits<std::size_t>::max())
        -> std::vector<std::string>
    {
        auto ordered = std::vector<std::string>{};
        auto seen = std::unordered_set<std::string>{};
        auto queue = std::deque<std::string>{};
        for (auto const& id : seed_ids)
        {
            if (seen.insert(id).second)
            {
                queue.push_back(id);
            }
        }
        while (!queue.empty() && ordered.size() <= limit)
        {
            auto const id = std::move(queue.front());
            queue.pop_front();
            auto const* event = find_event(store, id);
            if (event == nullptr)
            {
                continue;
            }
            ordered.push_back(id);
            for (auto const& auth_id : event->auth_event_ids)
            {
                if (seen.insert(auth_id).second)
                {
                    queue.push_back(auth_id);
                }
            }
        }
        return ordered;
    }

    // The (type, state_key) identity of a stored event, derived from its JSON.
    // `is_state` is true only when the event carries a `state_key` member, which
    // is what distinguishes a state event from a message event per the spec.
    struct StateIdentity final
    {
        std::string type{};
        std::string state_key{};
        bool is_state{false};
    };

    [[nodiscard]] auto state_identity(std::string_view json) -> StateIdentity
    {
        auto value = parsed_value(json);
        if (!value.has_value())
        {
            return {};
        }
        auto const* object = std::get_if<canonicaljson::Object>(&value->storage());
        if (object == nullptr)
        {
            return {};
        }
        auto identity = StateIdentity{};
        if (auto const* state_key = member_value(*object, "state_key"); state_key != nullptr)
        {
            if (auto const* text = std::get_if<std::string>(&state_key->storage()); text != nullptr)
            {
                identity.state_key = *text;
                identity.is_state = true;
            }
        }
        if (auto const* type = member_value(*object, "type"); type != nullptr)
        {
            if (auto const* text = std::get_if<std::string>(&type->storage()); text != nullptr)
            {
                identity.type = *text;
            }
        }
        return identity;
    }

    // Reconstructs the resolved room state as of `at_event_id` — the state prior
    // to the changes that event induces — by walking the event DAG backward from
    // the event's prev_events (the event itself is excluded). For each
    // (type, state_key) the ancestor with the greatest (depth, event_id) wins,
    // which is the deterministic linearisation that state resolution yields for a
    // conflict-free DAG. Returns the chosen state event IDs, or an empty vector
    // when the event is unknown or belongs to another room.
    [[nodiscard]] auto reconstruct_state_at_event(database::PersistentStore const& store, std::string_view room_id,
                                                  std::string_view at_event_id) -> std::vector<std::string>
    {
        auto const* start = find_event(store, at_event_id);
        if (start == nullptr || start->room_id != room_id)
        {
            return {};
        }
        struct Choice final
        {
            std::uint64_t depth{0U};
            std::string event_id{};
        };
        auto chosen = std::map<std::pair<std::string, std::string>, Choice>{};
        auto seen = std::unordered_set<std::string>{};
        auto queue = std::deque<std::string>{};
        for (auto const& prev_id : start->prev_event_ids)
        {
            if (seen.insert(prev_id).second)
            {
                queue.push_back(prev_id);
            }
        }
        while (!queue.empty())
        {
            auto const id = std::move(queue.front());
            queue.pop_front();
            auto const* event = find_event(store, id);
            if (event == nullptr || event->room_id != room_id || event->json.empty())
            {
                continue;
            }
            if (auto const identity = state_identity(event->json); identity.is_state)
            {
                auto const key = std::pair{identity.type, identity.state_key};
                auto const existing = chosen.find(key);
                if (existing == chosen.end() || event->depth > existing->second.depth ||
                    (event->depth == existing->second.depth && id > existing->second.event_id))
                {
                    chosen[key] = Choice{event->depth, id};
                }
            }
            for (auto const& prev_id : event->prev_event_ids)
            {
                if (seen.insert(prev_id).second)
                {
                    queue.push_back(prev_id);
                }
            }
        }
        auto result = std::vector<std::string>{};
        result.reserve(chosen.size());
        for (auto const& [key, choice] : chosen)
        {
            result.push_back(choice.event_id);
        }
        return result;
    }

    // The room's current recorded state event IDs -- the fallback
    // `resolve_state_event_ids_at` (client-server context) uses when no event to
    // reconstruct against is given. The federation /state and /state_ids
    // responses never fall back to it.
    [[nodiscard]] auto current_state_event_ids(database::PersistentStore const& store, std::string_view room_id)
        -> std::vector<std::string>
    {
        auto ids = std::vector<std::string>{};
        for (auto const& state_event : store.state)
        {
            if (state_event.room_id == room_id)
            {
                ids.push_back(state_event.event_id);
            }
        }
        return ids;
    }

    // Reconstructs "the room state at `event`" -- state that includes `event`'s
    // own contribution when it is itself a state event, unlike
    // `reconstruct_state_at_event` (which stops just short of it). Starts from
    // the state prior to `event` and, when `event` carries a state_key,
    // replaces (or adds) the entry for its (type, state_key) with `event`
    // itself, since a state event's own change is by definition part of the
    // room's state once that event has happened.
    [[nodiscard]] auto reconstruct_state_including_event(database::PersistentStore const& store,
                                                         std::string_view room_id, database::PersistentEvent const& at)
        -> std::vector<std::string>
    {
        auto ids = reconstruct_state_at_event(store, room_id, at.event_id);
        auto const identity = state_identity(at.json);
        if (!identity.is_state)
        {
            return ids;
        }
        auto const existing = std::ranges::find_if(ids, [&](std::string const& id) {
            auto const* event = find_event(store, id);
            if (event == nullptr)
            {
                return false;
            }
            auto const candidate_identity = state_identity(event->json);
            return candidate_identity.type == identity.type && candidate_identity.state_key == identity.state_key;
        });
        if (existing != ids.end())
        {
            *existing = at.event_id;
        }
        else
        {
            ids.push_back(at.event_id);
        }
        return ids;
    }

    enum class ServerVisibility : unsigned char
    {
        world_readable,
        shared,
        invited,
        joined,
    };

    // The four values of `m.room.history_visibility`'s `history_visibility`. Anything else, and an
    // event with no such field, is `shared` (CS API "Room History Visibility": "if no
    // `history_visibility` is set, or if the value is not understood, the visibility is assumed to
    // be `shared`").
    [[nodiscard]] auto parse_server_visibility(std::string_view value) noexcept -> ServerVisibility
    {
        if (value == "world_readable")
        {
            return ServerVisibility::world_readable;
        }
        if (value == "invited")
        {
            return ServerVisibility::invited;
        }
        if (value == "joined")
        {
            return ServerVisibility::joined;
        }
        return ServerVisibility::shared;
    }

    // Decides, for one requesting server, which room events it may read in full, and redacts the
    // rest. One instance serves one request: it builds its indexes over the store once, lazily, and
    // caches per state group, so a page of events costs one group lookup per event and one
    // membership scan per DISTINCT group, never a walk of the room. Not thread-safe; it must not
    // outlive the store reference.
    //
    // The rule is the client-server "Room History Visibility" rule applied to the server `origin`
    // (owner decision 2026-10-29), against the state group recorded for the event (ADR-0064): the
    // room's state immediately after it, so the event's own state change counts.
    //   world_readable, shared  visible;
    //   invited                 visible when a user of `origin` is invited or joined in that state;
    //   joined                  visible when a user of `origin` is joined in that state.
    // It fails closed: an event with no state group, a broken group chain, or a group naming an
    // event the store lacks is not visible.
    class ServerEventFilter final
    {
    public:
        ServerEventFilter(database::PersistentStore const& store, std::string_view origin)
            : store_{store}
            , origin_{origin}
        {
        }

        [[nodiscard]] auto can_see(database::PersistentEvent const& event) -> bool
        {
            if (origin_.empty())
            {
                return false;
            }
            auto const group_id = group_of(event.event_id);
            if (!group_id.has_value())
            {
                return false;
            }
            auto const& view = view_of_group(*group_id);
            if (!view.valid)
            {
                return false;
            }
            switch (view.visibility)
            {
            case ServerVisibility::world_readable:
            case ServerVisibility::shared:
                return true;
            case ServerVisibility::invited:
                return view.origin_invited_or_joined;
            case ServerVisibility::joined:
                return view.origin_joined;
            }
            return false;
        }

        // The event as a JSON value for `origin`: as stored when visible, otherwise the room
        // version's redaction of it (signatures, hashes, `prev_events`, `auth_events` and so the event
        // ID are kept, so the receiver can verify it and place it in the graph). nullopt when the
        // stored JSON does not parse, or the event is invisible and cannot be redacted (the room's
        // version is unknown or unsupported): the caller then leaves the event out rather than send
        // it in full.
        [[nodiscard]] auto value_for(database::PersistentEvent const& event) -> std::optional<canonicaljson::Value>
        {
            auto parsed = parsed_value(event.json);
            if (!parsed.has_value() || can_see(event))
            {
                return parsed;
            }
            auto const* policy = policy_for(event.room_id);
            if (policy == nullptr)
            {
                log_diagnostic("event_query.redaction_unavailable",
                               {
                                   {"event_id", event.event_id, false}
                },
                               observability::LogEventSeverity::warning);
                return std::nullopt;
            }
            auto redaction = events::redact_event(*parsed, *policy);
            if (!redaction.error.empty())
            {
                return std::nullopt;
            }
            log_diagnostic("event_query.redacted_for_server",
                           {
                               {"event_id", event.event_id,       false},
                               {"origin",   std::string{origin_}, false}
            });
            return std::move(redaction.event);
        }

        // As `value_for`, serialised: the stored JSON itself when visible.
        [[nodiscard]] auto json_for(database::PersistentEvent const& event) -> std::optional<std::string>
        {
            if (can_see(event))
            {
                return event.json;
            }
            auto const redacted = value_for(event);
            if (!redacted.has_value())
            {
                return std::nullopt;
            }
            auto const serialized = canonicaljson::serialize_canonical(*redacted);
            if (serialized.error != canonicaljson::CanonicalJsonError::none)
            {
                return std::nullopt;
            }
            return serialized.output;
        }

    private:
        struct GroupView final
        {
            bool valid{false};
            ServerVisibility visibility{ServerVisibility::shared};
            // Computed only for `invited` and `joined`, the settings that ask.
            bool origin_joined{false};
            bool origin_invited_or_joined{false};
        };

        enum class Lookup : unsigned char
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

        [[nodiscard]] auto group_of(std::string_view event_id) -> std::optional<std::string_view>
        {
            if (!event_group_index_built_)
            {
                group_by_event_.reserve(store_.event_state_groups.size());
                for (auto const& mapping : store_.event_state_groups)
                {
                    group_by_event_.emplace(mapping.event_id, mapping.state_group_id);
                }
                event_group_index_built_ = true;
            }
            auto const found = group_by_event_.find(event_id);
            return found == group_by_event_.end() ? std::nullopt : std::optional<std::string_view>{found->second};
        }

        auto ensure_group_index() -> void
        {
            if (group_index_built_)
            {
                return;
            }
            groups_by_id_.reserve(store_.state_groups.size());
            for (auto const& group : store_.state_groups)
            {
                groups_by_id_.emplace(group.state_group_id, &group);
            }
            for (auto const& entry : store_.state_group_state)
            {
                entries_by_group_[entry.state_group_id].push_back(&entry);
            }
            group_index_built_ = true;
        }

        // Finds the event ID `group_id`'s full state holds for (event_type, state_key), walking the
        // delta chain newest first exactly as database::read_state_group_full_state does: bounded,
        // cycle-checked, and broken (not "absent") when a group on the chain is missing.
        [[nodiscard]] auto lookup_in_group(std::string_view group_id, std::string_view event_type,
                                           std::string_view state_key) -> LookupResult
        {
            ensure_group_index();
            auto visited = std::unordered_set<std::string_view>{};
            auto current = group_id;
            for (auto hops = std::size_t{0U};; ++hops)
            {
                if (!visited.insert(current).second || hops > events::max_state_group_delta_depth)
                {
                    return {Lookup::broken, {}};
                }
                auto const group = groups_by_id_.find(current);
                if (group == groups_by_id_.end())
                {
                    return {Lookup::broken, {}};
                }
                if (auto const entries = entries_by_group_.find(current); entries != entries_by_group_.end())
                {
                    for (auto const* entry : entries->second)
                    {
                        if (entry->event_type == event_type && entry->state_key == state_key)
                        {
                            return {Lookup::found, entry->event_id};
                        }
                    }
                }
                if (!group->second->parent_state_group_id.has_value())
                {
                    return {Lookup::absent, {}};
                }
                current = *group->second->parent_state_group_id;
            }
        }

        // Fills `origin_joined` and `origin_invited_or_joined` from every `m.room.member` entry of
        // `group_id`'s full state whose user is on `origin`. A key set by a newer group on the chain
        // shadows the same key in an older one. False when the chain is broken or names a member
        // event the store lacks.
        [[nodiscard]] auto scan_origin_membership(std::string_view group_id, GroupView& view) -> bool
        {
            ensure_group_index();
            auto visited = std::unordered_set<std::string_view>{};
            auto shadowed = std::unordered_set<std::string_view>{};
            auto current = group_id;
            for (auto hops = std::size_t{0U};; ++hops)
            {
                if (!visited.insert(current).second || hops > events::max_state_group_delta_depth)
                {
                    return false;
                }
                auto const group = groups_by_id_.find(current);
                if (group == groups_by_id_.end())
                {
                    return false;
                }
                if (auto const entries = entries_by_group_.find(current); entries != entries_by_group_.end())
                {
                    for (auto const* entry : entries->second)
                    {
                        if (entry->event_type != "m.room.member" || user_id_server_name(entry->state_key) != origin_ ||
                            !shadowed.insert(entry->state_key).second)
                        {
                            continue;
                        }
                        auto const* member_event = find_event(store_, entry->event_id);
                        if (member_event == nullptr)
                        {
                            return false;
                        }
                        auto const membership = content_string(member_event->json, "membership");
                        if (membership == std::optional<std::string>{"join"})
                        {
                            view.origin_joined = true;
                            view.origin_invited_or_joined = true;
                            return true;
                        }
                        if (membership == std::optional<std::string>{"invite"})
                        {
                            view.origin_invited_or_joined = true;
                        }
                    }
                }
                if (!group->second->parent_state_group_id.has_value())
                {
                    return true;
                }
                current = *group->second->parent_state_group_id;
            }
        }

        [[nodiscard]] auto view_of_group(std::string_view group_id) -> GroupView const&
        {
            auto const key = std::string{group_id};
            if (auto const cached = group_views_.find(key); cached != group_views_.end())
            {
                return cached->second;
            }
            auto view = GroupView{};
            auto const visibility_event = lookup_in_group(group_id, "m.room.history_visibility", "");
            if (visibility_event.outcome != Lookup::broken)
            {
                view.valid = true;
                if (visibility_event.outcome == Lookup::found)
                {
                    auto const* event = find_event(store_, visibility_event.event_id);
                    if (event == nullptr)
                    {
                        view.valid = false; // the group names an event this store does not hold
                    }
                    else if (auto const value = content_string(event->json, "history_visibility"); value.has_value())
                    {
                        view.visibility = parse_server_visibility(*value);
                    }
                }
                if (view.valid &&
                    (view.visibility == ServerVisibility::invited || view.visibility == ServerVisibility::joined))
                {
                    view.valid = scan_origin_membership(group_id, view);
                }
            }
            return group_views_.emplace(key, view).first->second;
        }

        [[nodiscard]] auto policy_for(std::string const& room_id) -> rooms::RoomVersionPolicy const*
        {
            if (auto const cached = policies_.find(room_id); cached != policies_.end())
            {
                return cached->second;
            }
            auto const* policy = homeserver::stored_room_version_policy(store_, room_id);
            policies_.emplace(room_id, policy);
            return policy;
        }

        database::PersistentStore const& store_;
        std::string_view origin_;
        bool event_group_index_built_{false};
        std::unordered_map<std::string_view, std::string_view> group_by_event_{};
        bool group_index_built_{false};
        std::unordered_map<std::string_view, database::PersistentStateGroup const*> groups_by_id_{};
        std::unordered_map<std::string_view, std::vector<database::PersistentStateGroupStateEntry const*>>
            entries_by_group_{};
        std::unordered_map<std::string, GroupView> group_views_{};
        std::unordered_map<std::string, rooms::RoomVersionPolicy const*> policies_{};
    };

} // namespace

auto origin_has_joined_user_in_room(database::PersistentStore const& store, std::string_view room_id,
                                    std::string_view origin) -> bool
{
    if (origin.empty() || room_id.empty())
    {
        return false;
    }
    return origin_has_joined_user(store, room_id, origin);
}

auto origin_may_read_room(database::PersistentStore const& store, std::string_view room_id, std::string_view origin)
    -> bool
{
    if (origin.empty() || room_id.empty())
    {
        return false;
    }
    return origin_has_joined_user(store, room_id, origin) || room_is_world_readable(store, room_id);
}

auto build_event_response(database::PersistentStore const& store, std::string_view event_id,
                          std::string_view local_server_name, std::string_view origin) -> RoomReadResult
{
    auto const* event = find_event(store, event_id);
    if (event == nullptr || event->json.empty())
    {
        log_diagnostic("event_query.not_found", {
                                                    {"event_id", std::string{event_id}, false}
        });
        return not_found_result();
    }
    if (!room_server_acl_allows(store, event->room_id, origin) || !origin_may_read_room(store, event->room_id, origin))
    {
        log_diagnostic("event_query.forbidden",
                       {
                           {"event_id", std::string{event_id}, false},
                           {"origin",   std::string{origin},   false}
        });
        return forbidden_result();
    }
    // A visible event goes out as stored; one none of the origin's users could see goes out
    // redacted (server-level history visibility, see ServerEventFilter).
    auto filter = ServerEventFilter{store, origin};
    auto event_value = filter.value_for(*event);
    if (!event_value.has_value())
    {
        log_diagnostic("event_query.parse_failed", {
                                                       {"event_id", std::string{event_id}, false}
        });
        return not_found_result();
    }
    auto pdus = canonicaljson::Array{};
    pdus.push_back(std::move(*event_value));
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{local_server_name}}));
    response.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{now_ms()}));
    response.push_back(canonicaljson::make_member("pdus", canonicaljson::Value{std::move(pdus)}));
    log_diagnostic("event_query.accepted", {
                                               {"event_id", std::string{event_id}, false}
    });
    auto body = serialize(std::move(response));
    return body.empty() ? not_found_result() : RoomReadResult{RoomReadStatus::ok, std::move(body)};
}

auto build_state_response(database::PersistentStore const& store, std::string_view room_id,
                          std::string_view at_event_id, std::string_view origin) -> RoomReadResult
{
    if (!origin_may_read_room(store, room_id, origin))
    {
        log_diagnostic("state_query.forbidden",
                       {
                           {"room_id", std::string{room_id}, false},
                           {"origin",  std::string{origin},  false}
        });
        return forbidden_result();
    }
    // The event must be one this server stored in this room: there is no
    // fallback to the room's current state for an unknown event.
    auto const* at_event = at_event_id.empty() ? nullptr : find_event(store, at_event_id);
    if (at_event == nullptr || at_event->room_id != room_id)
    {
        return not_found_result();
    }
    // Deliberately NOT filtered by server-level history visibility (unlike /event, /backfill and
    // /get_missing_events): state events are part of the room's authorisation, and a joining or
    // catching-up server computes state and authorises events from them, so they are sent whole.
    // The origin_may_read_room gate above still applies. Filtering state would need an ADR.
    auto pdus = canonicaljson::Array{};
    // Seed IDs for the auth chain: every auth event named by a returned state
    // event. The transitive closure is computed once after the state is gathered.
    auto auth_seed_ids = std::vector<std::string>{};
    for (auto const& state_event_id : reconstruct_state_at_event(store, room_id, at_event_id))
    {
        auto const* event = find_event(store, state_event_id);
        if (event == nullptr || event->json.empty())
        {
            continue;
        }
        auto value = parsed_value(event->json);
        if (!value.has_value())
        {
            continue;
        }
        auth_seed_ids.insert(auth_seed_ids.end(), event->auth_event_ids.begin(), event->auth_event_ids.end());
        pdus.push_back(std::move(*value));
    }
    if (pdus.empty())
    {
        log_diagnostic("state_query.not_found", {
                                                    {"room_id", std::string{room_id}, false}
        });
        return not_found_result();
    }
    // auth_chain carries the full event bodies for the transitive auth closure
    // so a receiving server can authorize the returned state. Spec: SS API
    // GET /_matrix/federation/v1/state/{roomId}.
    auto auth_chain = canonicaljson::Array{};
    for (auto const& auth_id : collect_auth_chain(store, auth_seed_ids))
    {
        auto const* event = find_event(store, auth_id);
        if (event == nullptr || event->json.empty())
        {
            continue;
        }
        auto value = parsed_value(event->json);
        if (!value.has_value())
        {
            continue;
        }
        auth_chain.push_back(std::move(*value));
    }
    auto const pdu_count = pdus.size();
    auto const auth_chain_count = auth_chain.size();
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("auth_chain", canonicaljson::Value{std::move(auth_chain)}));
    response.push_back(canonicaljson::make_member("pdus", canonicaljson::Value{std::move(pdus)}));
    log_diagnostic("state_query.accepted", {
                                               {"room_id",    std::string{room_id},             false},
                                               {"pdus",       std::to_string(pdu_count),        false},
                                               {"auth_chain", std::to_string(auth_chain_count), false}
    });
    auto body = serialize(std::move(response));
    return body.empty() ? not_found_result() : RoomReadResult{RoomReadStatus::ok, std::move(body)};
}

auto build_event_auth_response(database::PersistentStore const& store, std::string_view room_id,
                               std::string_view event_id, std::string_view origin) -> RoomReadResult
{
    if (!origin_may_read_room(store, room_id, origin))
    {
        log_diagnostic("event_auth_query.forbidden",
                       {
                           {"room_id", std::string{room_id}, false},
                           {"origin",  std::string{origin},  false}
        });
        return forbidden_result();
    }
    auto const* event = event_id.empty() ? nullptr : find_event(store, event_id);
    if (event == nullptr || event->room_id != room_id)
    {
        return not_found_result();
    }
    // Like /state, the auth chain is NOT filtered by server-level history visibility: auth events are
    // state events, part of the room's authorisation, and the receiver needs them whole to authorise
    // the event. The origin_may_read_room gate above still applies.
    // The chain is the closure of the event's auth events, not the event itself.
    // The walk is bounded so one request cannot read an unbounded part of the
    // store. The spec promises "the complete auth chain", so a chain longer than
    // the bound is refused, never answered with part of it (ADR-0284). The walk
    // collects one past the bound, which is how a longer chain is told apart.
    auto const auth_ids = collect_auth_chain(store, event->auth_event_ids, max_event_auth_chain_events);
    if (auth_ids.size() > max_event_auth_chain_events)
    {
        log_diagnostic("event_auth_query.too_large",
                       {
                           {"room_id",  std::string{room_id},                        false},
                           {"event_id", std::string{event_id},                       false},
                           {"bound",    std::to_string(max_event_auth_chain_events), false}
        },
                       observability::LogEventSeverity::warning);
        return RoomReadResult{RoomReadStatus::too_large, {}};
    }
    auto chain = canonicaljson::Array{};
    for (auto const& auth_id : auth_ids)
    {
        auto const* auth_event = find_event(store, auth_id);
        if (auth_event == nullptr || auth_event->room_id != room_id || auth_event->json.empty())
        {
            continue;
        }
        if (auto value = parsed_value(auth_event->json); value.has_value())
        {
            chain.push_back(std::move(*value));
        }
    }
    auto const chain_count = chain.size();
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("auth_chain", canonicaljson::Value{std::move(chain)}));
    log_diagnostic("event_auth_query.accepted",
                   {
                       {"room_id",    std::string{room_id},        false},
                       {"auth_chain", std::to_string(chain_count), false}
    });
    auto body = serialize(std::move(response));
    return body.empty() ? not_found_result() : RoomReadResult{RoomReadStatus::ok, std::move(body)};
}

auto build_state_ids_response(database::PersistentStore const& store, std::string_view room_id,
                              std::string_view at_event_id, std::string_view origin) -> RoomReadResult
{
    if (!origin_may_read_room(store, room_id, origin))
    {
        log_diagnostic("state_ids_query.forbidden",
                       {
                           {"room_id", std::string{room_id}, false},
                           {"origin",  std::string{origin},  false}
        });
        return forbidden_result();
    }
    auto const* at_event = at_event_id.empty() ? nullptr : find_event(store, at_event_id);
    if (at_event == nullptr || at_event->room_id != room_id)
    {
        return not_found_result();
    }
    // IDs only, and unfiltered for the same reason as /state: state is the room's authorisation record.
    auto pdu_ids = canonicaljson::Array{};
    auto auth_seed_ids = std::vector<std::string>{};
    for (auto const& state_event_id : reconstruct_state_at_event(store, room_id, at_event_id))
    {
        if (auto const* event = find_event(store, state_event_id); event != nullptr)
        {
            auth_seed_ids.insert(auth_seed_ids.end(), event->auth_event_ids.begin(), event->auth_event_ids.end());
        }
        pdu_ids.push_back(canonicaljson::Value{state_event_id});
    }
    if (pdu_ids.empty())
    {
        log_diagnostic("state_ids_query.not_found", {
                                                        {"room_id", std::string{room_id}, false}
        });
        return not_found_result();
    }
    auto auth_chain_ids = canonicaljson::Array{};
    for (auto const& auth_id : collect_auth_chain(store, auth_seed_ids))
    {
        auth_chain_ids.push_back(canonicaljson::Value{auth_id});
    }
    auto const pdu_id_count = pdu_ids.size();
    auto const auth_chain_id_count = auth_chain_ids.size();
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("auth_chain_ids", canonicaljson::Value{std::move(auth_chain_ids)}));
    response.push_back(canonicaljson::make_member("pdu_ids", canonicaljson::Value{std::move(pdu_ids)}));
    log_diagnostic("state_ids_query.accepted", {
                                                   {"room_id",        std::string{room_id},                false},
                                                   {"pdu_ids",        std::to_string(pdu_id_count),        false},
                                                   {"auth_chain_ids", std::to_string(auth_chain_id_count), false}
    });
    auto body = serialize(std::move(response));
    return body.empty() ? not_found_result() : RoomReadResult{RoomReadStatus::ok, std::move(body)};
}

auto resolve_state_event_ids_at(database::PersistentStore const& store, std::string_view room_id,
                                std::string_view at_event_id) -> std::vector<std::string>
{
    if (at_event_id.empty())
    {
        return current_state_event_ids(store, room_id);
    }
    auto const* at = find_event(store, at_event_id);
    if (at == nullptr || at->room_id != room_id)
    {
        return current_state_event_ids(store, room_id);
    }
    return reconstruct_state_including_event(store, room_id, *at);
}

auto event_visible_to_server(database::PersistentStore const& store, std::string_view event_id, std::string_view origin)
    -> bool
{
    auto const* event = find_event(store, event_id);
    if (event == nullptr)
    {
        return false;
    }
    auto filter = ServerEventFilter{store, origin};
    return filter.can_see(*event);
}

auto build_backfill_pdus(database::PersistentStore const& store, std::string_view room_id,
                         std::vector<std::string> const& event_ids, std::size_t limit, std::string_view origin)
    -> std::vector<std::string>
{
    if (limit == 0U)
    {
        return {};
    }
    // Server-level history visibility: an event none of the origin's users could see is sent
    // redacted, not dropped, and the walk continues through its prev_events either way.
    auto filter = ServerEventFilter{store, origin};
    auto pdus = std::vector<std::string>{};
    auto seen = std::unordered_set<std::string>{};
    auto queue = std::deque<std::string>{};
    for (auto const& event_id : event_ids)
    {
        if (seen.insert(event_id).second)
        {
            queue.push_back(event_id);
        }
    }
    while (!queue.empty() && pdus.size() < limit)
    {
        auto const event_id = std::move(queue.front());
        queue.pop_front();
        auto const* event = find_event(store, event_id);
        if (event == nullptr || event->room_id != room_id || event->json.empty())
        {
            continue;
        }
        if (auto pdu = filter.json_for(*event); pdu.has_value())
        {
            pdus.push_back(std::move(*pdu));
        }
        for (auto const& prev_event_id : event->prev_event_ids)
        {
            if (seen.insert(prev_event_id).second)
            {
                queue.push_back(prev_event_id);
            }
        }
    }
    log_diagnostic("backfill_query.accepted", {
                                                  {"room_id",   std::string{room_id},             false},
                                                  {"requested", std::to_string(event_ids.size()), false},
                                                  {"pdus",      std::to_string(pdus.size()),      false}
    });
    return pdus;
}

auto build_backfill_response(database::PersistentStore const& store, BackfillRequest const& request,
                             FederationQueryPolicy const& policy) -> BackfillResult
{
    if (!origin_may_read_room(store, request.room_id, request.origin))
    {
        log_diagnostic("backfill_query.forbidden",
                       {
                           {"room_id", request.room_id, false},
                           {"origin",  request.origin,  false}
        });
        return {false, 403U, std::string{forbidden_body}, {}};
    }
    return {true,
            200U,
            {},
            build_backfill_pdus(store, request.room_id, request.event_ids,
                                std::min(request.limit, policy.max_backfill_pdus), request.origin)};
}

auto build_get_missing_events_response(database::PersistentStore const& store, std::string_view room_id,
                                       std::string_view request_body, std::string_view origin,
                                       FederationQueryPolicy const& policy) -> RoomReadResult
{
    // Membership first: a server outside the room learns nothing, not even
    // whether its request body was well formed.
    if (!origin_may_read_room(store, room_id, origin))
    {
        log_diagnostic("get_missing_events.forbidden",
                       {
                           {"room_id", std::string{room_id}, false},
                           {"origin",  std::string{origin},  false}
        });
        return forbidden_result();
    }
    auto request = parsed_value(request_body);
    if (!request.has_value())
    {
        return malformed_result();
    }
    auto const* root = std::get_if<canonicaljson::Object>(&request->storage());
    if (root == nullptr)
    {
        return malformed_result();
    }
    auto const latest_events = string_list_member(*root, "latest_events");
    auto const earliest_events = string_list_member(*root, "earliest_events");
    auto const requested_limit =
        optional_integer_member(*root, "limit", static_cast<std::int64_t>(default_missing_events_limit));
    auto const min_depth = optional_integer_member(*root, "min_depth", 0);
    if (!latest_events.has_value() || !earliest_events.has_value() || !requested_limit.has_value() ||
        !min_depth.has_value() || latest_events->size() > policy.max_missing_events_latest)
    {
        return malformed_result();
    }
    auto const limit = static_cast<std::size_t>(
        std::clamp(*requested_limit, std::int64_t{0}, static_cast<std::int64_t>(policy.max_missing_events_pdus)));

    // Breadth-first walk of prev_events from latest_events. Everything the
    // requester already has (earliest_events) and the latest events themselves
    // are pre-marked seen, so they are never returned and, because a walk only
    // extends through returned or root events, never walked past. Events in
    // another room, unknown events and events below min_depth are dropped
    // without being followed.
    auto seen = std::unordered_set<std::string>{earliest_events->begin(), earliest_events->end()};
    auto queue = std::deque<std::string>{};
    auto roots = std::unordered_set<std::string>{};
    for (auto const& id : *latest_events)
    {
        if (!seen.contains(id))
        {
            roots.insert(id);
            queue.push_back(id);
        }
    }
    seen.insert(roots.begin(), roots.end());
    auto collected = std::vector<database::PersistentEvent const*>{};
    auto lookups = std::size_t{0U};
    while (!queue.empty() && collected.size() < limit && lookups < policy.max_missing_events_traversal)
    {
        auto const id = std::move(queue.front());
        queue.pop_front();
        ++lookups;
        auto const* event = find_event(store, id);
        if (event == nullptr || event->room_id != room_id || event->json.empty() ||
            static_cast<std::int64_t>(event->depth) < *min_depth)
        {
            continue;
        }
        if (!roots.contains(id))
        {
            collected.push_back(event);
        }
        for (auto const& prev_id : event->prev_event_ids)
        {
            if (seen.insert(prev_id).second)
            {
                queue.push_back(prev_id);
            }
        }
    }
    // The walk runs newest to oldest; hand the requester the oldest first.
    // Server-level history visibility: an event none of the origin's users could see comes back
    // redacted, not dropped (the walk above is unchanged, so the graph stays whole).
    auto filter = ServerEventFilter{store, origin};
    auto events = canonicaljson::Array{};
    for (auto it = collected.rbegin(); it != collected.rend(); ++it)
    {
        auto value = filter.value_for(**it);
        if (value.has_value())
        {
            events.push_back(std::move(*value));
        }
    }
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("events", canonicaljson::Value{std::move(events)}));
    auto body = serialize(std::move(response));
    return body.empty() ? malformed_result() : RoomReadResult{RoomReadStatus::ok, std::move(body)};
}

} // namespace merovingian::federation
