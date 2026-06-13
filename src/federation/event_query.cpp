// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/event_query.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
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

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("event_query", event, std::move(fields)));
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

} // namespace

auto build_event_response(database::PersistentStore const& store, std::string_view event_id,
                          std::string_view origin_server_name) -> std::string
{
    auto const it = std::ranges::find_if(store.events, [event_id](database::PersistentEvent const& event) {
        return event.event_id == event_id;
    });
    if (it == store.events.end() || it->json.empty())
    {
        log_diagnostic("event_query.not_found", {{"event_id", std::string{event_id}, false}});
        return {};
    }
    auto event_value = parsed_value(it->json);
    if (!event_value.has_value())
    {
        log_diagnostic("event_query.parse_failed", {{"event_id", std::string{event_id}, false}});
        return {};
    }
    auto pdus = canonicaljson::Array{};
    pdus.push_back(std::move(*event_value));
    auto response = canonicaljson::Object{};
    response.push_back(
        canonicaljson::make_member("origin", canonicaljson::Value{std::string{origin_server_name}}));
    response.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{now_ms()}));
    response.push_back(canonicaljson::make_member("pdus", canonicaljson::Value{std::move(pdus)}));
    log_diagnostic("event_query.accepted", {{"event_id", std::string{event_id}, false}});
    return serialize(std::move(response));
}

auto build_state_response(database::PersistentStore const& store, std::string_view room_id) -> std::string
{
    auto pdus = canonicaljson::Array{};
    // Seed IDs for the auth chain: every auth event named by a returned state
    // event. The transitive closure is computed once after the state is gathered.
    auto auth_seed_ids = std::vector<std::string>{};
    for (auto const& state_event : store.state)
    {
        if (state_event.room_id != room_id)
        {
            continue;
        }
        auto const* event = find_event(store, state_event.event_id);
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
        log_diagnostic("state_query.not_found", {{"room_id", std::string{room_id}, false}});
        return {};
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
    log_diagnostic("state_query.accepted", {{"room_id",    std::string{room_id},            false},
                                            {"pdus",       std::to_string(pdu_count),       false},
                                            {"auth_chain", std::to_string(auth_chain_count), false}});
    return serialize(std::move(response));
}

auto build_state_ids_response(database::PersistentStore const& store, std::string_view room_id) -> std::string
{
    auto pdu_ids = canonicaljson::Array{};
    auto auth_seed_ids = std::vector<std::string>{};
    for (auto const& state_event : store.state)
    {
        if (state_event.room_id != room_id)
        {
            continue;
        }
        if (auto const* event = find_event(store, state_event.event_id); event != nullptr)
        {
            auth_seed_ids.insert(auth_seed_ids.end(), event->auth_event_ids.begin(), event->auth_event_ids.end());
        }
        pdu_ids.push_back(canonicaljson::Value{state_event.event_id});
    }
    if (pdu_ids.empty())
    {
        log_diagnostic("state_ids_query.not_found", {{"room_id", std::string{room_id}, false}});
        return {};
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
    log_diagnostic("state_ids_query.accepted", {{"room_id",        std::string{room_id},                false},
                                                {"pdu_ids",        std::to_string(pdu_id_count),        false},
                                                {"auth_chain_ids", std::to_string(auth_chain_id_count), false}});
    return serialize(std::move(response));
}

auto build_get_missing_events_response(database::PersistentStore const& store, std::string_view room_id,
                                       std::string_view request_body) -> std::string
{
    auto request = parsed_value(request_body);
    if (!request.has_value())
    {
        return {};
    }
    auto const* root = std::get_if<canonicaljson::Object>(&request->storage());
    if (root == nullptr)
    {
        return {};
    }
    // Defaults follow the Matrix federation spec.
    auto limit = std::int64_t{10};
    if (auto const* limit_value = member_value(*root, "limit"); limit_value != nullptr)
    {
        if (auto const* n = std::get_if<std::int64_t>(&limit_value->storage()); n != nullptr && *n > 0)
        {
            limit = *n;
        }
    }
    auto min_depth = std::int64_t{0};
    if (auto const* min_depth_value = member_value(*root, "min_depth"); min_depth_value != nullptr)
    {
        if (auto const* n = std::get_if<std::int64_t>(&min_depth_value->storage()); n != nullptr)
        {
            min_depth = *n;
        }
    }
    // Collect events in the room above min_depth, ascending depth, capped by limit.
    // A full implementation would walk from `latest_events` back toward
    // `earliest_events`; this v1 returns the same depth-ordered slice clients
    // typically use to backfill a gap.
    struct Entry final
    {
        std::uint64_t depth{0U};
        std::string json{};
    };
    auto candidates = std::vector<Entry>{};
    for (auto const& event : store.events)
    {
        if (event.room_id != room_id || event.json.empty())
        {
            continue;
        }
        if (static_cast<std::int64_t>(event.depth) < min_depth)
        {
            continue;
        }
        candidates.push_back({event.depth, event.json});
    }
    std::ranges::sort(candidates, [](Entry const& lhs, Entry const& rhs) noexcept { return lhs.depth < rhs.depth; });
    auto events = canonicaljson::Array{};
    for (auto const& entry : candidates)
    {
        if (static_cast<std::int64_t>(events.size()) >= limit)
        {
            break;
        }
        auto value = parsed_value(entry.json);
        if (!value.has_value())
        {
            continue;
        }
        events.push_back(std::move(*value));
    }
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("events", canonicaljson::Value{std::move(events)}));
    return serialize(std::move(response));
}

} // namespace merovingian::federation
