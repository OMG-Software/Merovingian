// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0247: a stream ordering reserved for an event that is committed with runtime.mutex
// released is pending until the event is applied, and no sync position passes it. A /sync token
// handed out in that window covered the ordering, so the event, applied a moment later, sat at or
// below every later `since` and never reached the client (Complement
// TestRestrictedRoomsRemoteJoin: a remote user's leave, ordering 22, applied just after a sync
// returned 22).

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/stream_token.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto position_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
}

// A /sync response, from `since` when it is given.
[[nodiscard]] auto sync_body(ClientServerRuntime& rt, std::string const& token, std::string const& since = {})
    -> merovingian::canonicaljson::Object
{
    auto const synced =
        call(rt, "GET", since.empty() ? "/_matrix/client/v3/sync" : "/_matrix/client/v3/sync?since=" + since, token);
    REQUIRE(synced.response.status == 200U);
    return parse_object(synced.response.body);
}

[[nodiscard]] auto next_batch_of(merovingian::canonicaljson::Object const& body) -> std::string
{
    auto const* next_batch = string_member(body, "next_batch");
    REQUIRE(next_batch != nullptr);
    return *next_batch;
}

// The event ordering of a /sync response's next_batch.
[[nodiscard]] auto event_ordering_of(merovingian::canonicaljson::Object const& body) -> std::uint64_t
{
    auto const decoded = merovingian::sync::decode_stream_token(next_batch_of(body));
    REQUIRE(decoded.has_value());
    return decoded->event_ordering;
}

// How many timeline events of `room_id` in `body` have content.body `text`.
[[nodiscard]] auto timeline_count(merovingian::canonicaljson::Object const& body, std::string const& room_id,
                                  std::string_view text) -> std::size_t
{
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* join = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "join");
    auto const* room = join == nullptr ? nullptr : object_member_as_object(*join, room_id);
    auto const* timeline = room == nullptr ? nullptr : object_member_as_object(*room, "timeline");
    auto const* events = timeline == nullptr ? nullptr : object_member_as_array(*timeline, "events");
    if (events == nullptr)
    {
        return 0U;
    }
    return static_cast<std::size_t>(std::ranges::count_if(*events, [text](auto const& entry) {
        auto const& event = std::get<merovingian::canonicaljson::Object>(entry.storage());
        auto const* content = object_member_as_object(event, "content");
        auto const* event_body = content == nullptr ? nullptr : string_member(*content, "body");
        return event_body != nullptr && *event_body == text;
    }));
}

} // namespace

SCENARIO("No sync position passes a stream ordering whose event is still being committed",
         "[homeserver][sync][sync-position][concurrency]")
{
    GIVEN("a joined room, and an ordering reserved for an event not yet applied")
    {
        auto started = merovingian::homeserver::start_client_server(position_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const registered =
            call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json("alice", "CorrectHorse7!"));
        REQUIRE(registered.response.status == 200U);
        auto const token = std::string{*string_member(parse_object(registered.response.body), "access_token")};
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, "{}");
        REQUIRE(created.response.status == 200U);
        auto const room_id = std::string{*string_member(parse_object(created.response.body), "room_id")};

        auto reserved = std::uint64_t{0U};
        auto pending = std::optional<merovingian::homeserver::PendingStreamOrdering>{};
        {
            auto const lock = std::lock_guard{rt.homeserver.mutex};
            reserved = merovingian::homeserver::allocate_stream_ordering(rt.homeserver.database);
            pending.emplace(rt.homeserver.database, reserved);
        }

        WHEN("a later event is applied and the user syncs while the reservation is pending")
        {
            REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t1", token,
                         R"({"msgtype":"m.text","body":"later"})")
                        .response.status == 200U);
            auto const while_pending = sync_body(rt, token);

            THEN("the token stops below the pending ordering, and the later event waits with it")
            {
                // The token and the timeline agree: an event above the token would come
                // again on the next sync, which starts from it.
                REQUIRE(event_ordering_of(while_pending) < reserved);
                REQUIRE(timeline_count(while_pending, room_id, "later") == 0U);
            }

            AND_WHEN("the reserved event is applied and the reservation ends")
            {
                {
                    auto const lock = std::lock_guard{rt.homeserver.mutex};
                    pending.reset();
                }
                auto const after = sync_body(rt, token, next_batch_of(while_pending));

                THEN("the next sync moves past it to the newest ordering and delivers the later event once")
                {
                    REQUIRE(event_ordering_of(after) >= reserved);
                    REQUIRE(event_ordering_of(after) == rt.homeserver.database.next_stream_ordering - 1U);
                    REQUIRE(timeline_count(after, room_id, "later") == 1U);
                }
            }
        }
    }
}
