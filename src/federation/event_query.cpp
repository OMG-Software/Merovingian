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
#include <optional>
#include <string>
#include <string_view>
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
    for (auto const& state_event : store.state)
    {
        if (state_event.room_id != room_id)
        {
            continue;
        }
        auto const event = std::ranges::find_if(
            store.events, [&state_event](database::PersistentEvent const& candidate) {
                return candidate.event_id == state_event.event_id;
            });
        if (event == store.events.end() || event->json.empty())
        {
            continue;
        }
        auto value = parsed_value(event->json);
        if (!value.has_value())
        {
            continue;
        }
        pdus.push_back(std::move(*value));
    }
    if (pdus.empty())
    {
        log_diagnostic("state_query.not_found", {{"room_id", std::string{room_id}, false}});
        return {};
    }
    auto const pdu_count = pdus.size();
    auto response = canonicaljson::Object{};
    // auth_chain reconstruction is not yet implemented; an empty array keeps
    // the response well-formed for clients that tolerate it.
    response.push_back(canonicaljson::make_member("auth_chain", canonicaljson::Value{canonicaljson::Array{}}));
    response.push_back(canonicaljson::make_member("pdus", canonicaljson::Value{std::move(pdus)}));
    log_diagnostic("state_query.accepted", {{"room_id", std::string{room_id}, false},
                                            {"pdus",    std::to_string(pdu_count), false}});
    return serialize(std::move(response));
}

auto build_state_ids_response(database::PersistentStore const& store, std::string_view room_id) -> std::string
{
    auto pdu_ids = canonicaljson::Array{};
    for (auto const& state_event : store.state)
    {
        if (state_event.room_id != room_id)
        {
            continue;
        }
        pdu_ids.push_back(canonicaljson::Value{state_event.event_id});
    }
    if (pdu_ids.empty())
    {
        log_diagnostic("state_ids_query.not_found", {{"room_id", std::string{room_id}, false}});
        return {};
    }
    auto const pdu_id_count = pdu_ids.size();
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("auth_chain_ids", canonicaljson::Value{canonicaljson::Array{}}));
    response.push_back(canonicaljson::make_member("pdu_ids", canonicaljson::Value{std::move(pdu_ids)}));
    log_diagnostic("state_ids_query.accepted", {{"room_id", std::string{room_id},           false},
                                                {"pdu_ids", std::to_string(pdu_id_count), false}});
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
