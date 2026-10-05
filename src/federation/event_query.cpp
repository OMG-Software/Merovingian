// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/event_query.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/server_acl.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <string_view>
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
        auto const it = std::ranges::find_if(store.events, [event_id](database::PersistentEvent const& event) {
            return event.event_id == event_id;
        });
        return it == store.events.end() ? nullptr : &*it;
    }

    // Like `find_event`, but scans from the newest stored event backwards. The
    // store has no event index, and the events a get_missing_events walk visits
    // are the recently stored ones, so this finds them without crossing the whole
    // history.
    [[nodiscard]] auto find_event_newest_first(database::PersistentStore const& store, std::string_view event_id)
        -> database::PersistentEvent const*
    {
        for (auto it = store.events.rbegin(); it != store.events.rend(); ++it)
        {
            if (it->event_id == event_id)
            {
                return &*it;
            }
        }
        return nullptr;
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
                                          std::vector<std::string> const& seed_ids) -> std::vector<std::string>
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
        while (!queue.empty())
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

} // namespace

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
    auto event_value = parsed_value(event->json);
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

auto build_backfill_pdus(database::PersistentStore const& store, std::string_view room_id,
                         std::vector<std::string> const& event_ids, std::size_t limit) -> std::vector<std::string>
{
    if (limit == 0U)
    {
        return {};
    }
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
        pdus.push_back(event->json);
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
                                std::min(request.limit, policy.max_backfill_pdus))};
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
        auto const* event = find_event_newest_first(store, id);
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
    auto events = canonicaljson::Array{};
    for (auto it = collected.rbegin(); it != collected.rend(); ++it)
    {
        auto value = parsed_value((*it)->json);
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
