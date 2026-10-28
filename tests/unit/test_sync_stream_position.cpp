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

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

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

// The event ordering of a /sync response's next_batch.
[[nodiscard]] auto next_batch_event_ordering(ClientServerRuntime& rt, std::string const& token) -> std::uint64_t
{
    auto const synced = call(rt, "GET", "/_matrix/client/v3/sync", token);
    REQUIRE(synced.response.status == 200U);
    auto const body = parse_object(synced.response.body);
    auto const* next_batch = string_member(body, "next_batch");
    REQUIRE(next_batch != nullptr);
    auto const decoded = merovingian::sync::decode_stream_token(*next_batch);
    REQUIRE(decoded.has_value());
    return decoded->event_ordering;
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
            auto const while_pending = next_batch_event_ordering(rt, token);

            THEN("the token stops below the pending ordering, so the event cannot be skipped")
            {
                REQUIRE(while_pending < reserved);
            }

            AND_WHEN("the reserved event is applied and the reservation ends")
            {
                {
                    auto const lock = std::lock_guard{rt.homeserver.mutex};
                    pending.reset();
                }
                auto const after = next_batch_event_ordering(rt, token);

                THEN("the token moves past it to the newest ordering")
                {
                    REQUIRE(after >= reserved);
                    REQUIRE(after == rt.homeserver.database.next_stream_ordering - 1U);
                }
            }
        }
    }
}
