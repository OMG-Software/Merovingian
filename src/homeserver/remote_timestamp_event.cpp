// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/remote_timestamp_event.hpp"

#include "merovingian/auth/identity.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <variant>

namespace merovingian::homeserver
{
namespace
{

    constexpr auto max_event_id_bytes = std::size_t{255U};

    [[nodiscard]] auto direction_letter(database::TimeDirection direction) noexcept -> char
    {
        return direction == database::TimeDirection::forwards ? 'f' : 'b';
    }

} // namespace

auto timestamp_to_event_candidate_servers(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view our_server) -> std::vector<std::string>
{
    // server -> the lowest stream ordering of a current join of one of its users.
    auto earliest_join = std::map<std::string, std::uint64_t, std::less<>>{};
    for (auto const& membership : store.memberships)
    {
        if (membership.room_id != room_id || membership.membership != "join")
        {
            continue;
        }
        auto const server = auth::identifier_server_name(membership.user_id);
        if (server.empty() || server == our_server)
        {
            continue;
        }
        auto const known = earliest_join.find(server);
        if (known == earliest_join.end())
        {
            earliest_join.emplace(std::string{server}, membership.stream_ordering);
        }
        else
        {
            known->second = std::min(known->second, membership.stream_ordering);
        }
    }
    auto ranked = std::vector<std::pair<std::uint64_t, std::string>>{};
    ranked.reserve(earliest_join.size());
    for (auto const& [server, ordering] : earliest_join)
    {
        ranked.emplace_back(ordering, server);
    }
    std::ranges::sort(ranked);
    auto servers = std::vector<std::string>{};
    for (auto& entry : ranked)
    {
        if (servers.size() == max_timestamp_to_event_servers)
        {
            break;
        }
        servers.push_back(std::move(entry.second));
    }
    return servers;
}

auto parse_timestamp_to_event_answer(std::string_view body) -> std::optional<RemoteTimestampEvent>
{
    auto const parsed = canonicaljson::parse_lossless(body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return std::nullopt;
    }
    auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (object == nullptr)
    {
        return std::nullopt;
    }
    auto answer = RemoteTimestampEvent{};
    auto have_id = false;
    auto have_ts = false;
    for (auto const& member : *object)
    {
        if (member.key == "event_id")
        {
            auto const* id = std::get_if<std::string>(&member.value->storage());
            if (id == nullptr || id->empty() || id->front() != '$' || id->size() > max_event_id_bytes)
            {
                return std::nullopt;
            }
            answer.event_id = *id;
            have_id = true;
        }
        else if (member.key == "origin_server_ts")
        {
            auto const* ts = std::get_if<std::int64_t>(&member.value->storage());
            if (ts == nullptr)
            {
                return std::nullopt;
            }
            answer.origin_server_ts = *ts;
            have_ts = true;
        }
    }
    if (!have_id || !have_ts)
    {
        return std::nullopt;
    }
    return answer;
}

auto timestamp_is_closer(std::int64_t candidate, std::optional<std::int64_t> current, std::int64_t ts,
                         database::TimeDirection direction) noexcept -> bool
{
    if (direction == database::TimeDirection::forwards)
    {
        return candidate >= ts && (!current.has_value() || candidate < *current);
    }
    return candidate <= ts && (!current.has_value() || candidate > *current);
}

auto acquire_closer_timestamp_event(HomeserverRuntime& runtime, std::unique_lock<RuntimeMutex>& guard,
                                    std::string_view room_id, std::vector<std::string> const& servers, std::int64_t ts,
                                    database::TimeDirection direction, std::optional<std::int64_t> local_ts,
                                    OutboundDeadline const& deadline) -> std::optional<std::string>
{
    wire_federation_callbacks(runtime);
    auto const our_server = runtime.config.server().server_name;
    auto const target = std::string{"/_matrix/federation/v1/timestamp_to_event/"} +
                        core::percent_encode_path_component(room_id) + "?ts=" + std::to_string(ts) +
                        "&dir=" + direction_letter(direction);
    for (auto const& server : servers)
    {
        if (deadline.expired())
        {
            break;
        }
        // The signing key is copied while the runtime lock is held; the call then owns it.
        auto const signing_key = ensure_runtime_server_signing_key(runtime);
        if (!signing_key.has_value())
        {
            return std::nullopt;
        }
        auto secret = core::SecretBuffer{runtime.database.signing_secret_key.bytes()};
        auto const tx = federation::make_outbound_transaction(server, "GET", target, our_server, {});
        auto const [ok, body] = [&] {
            auto const released = RuntimeLockRelease{guard};
            return perform_bounded_outbound_call(runtime, room_id, tx, signing_key->key_id, std::move(secret),
                                                 "timestamp_to_event.ask", deadline.remaining_seconds());
        }();
        if (!ok)
        {
            continue;
        }
        auto const answer = parse_timestamp_to_event_answer(body);
        if (!answer.has_value() || !timestamp_is_closer(answer->origin_server_ts, local_ts, ts, direction))
        {
            continue;
        }
        auto const stored = [&] {
            auto const released = RuntimeLockRelease{guard};
            return fetch_remote_event_into_store(runtime, room_id, server, answer->event_id, deadline);
        }();
        if (stored)
        {
            return answer->event_id;
        }
        LOG_WARNING("timestamp_to_event: the event a server named could not be fetched and verified; room_id=" +
                    std::string{room_id} + " server=" + server + " event_id=" + answer->event_id);
    }
    return std::nullopt;
}

} // namespace merovingian::homeserver
