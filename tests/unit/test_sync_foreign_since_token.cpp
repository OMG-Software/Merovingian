// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/stream_token.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto json_string_after(std::string const& body, std::string const& key) -> std::string
{
    auto const needle = "\"" + key + "\":\"";
    auto const begin = body.find(needle);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + needle.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

struct LoggedInUser final
{
    std::string token{};
    std::string device_id{};
};

[[nodiscard]] auto register_user(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& name)
    -> LoggedInUser
{
    auto const registered = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(name, "CorrectHorse7!")});
    REQUIRE(registered.response.status == 200U);
    auto const device_id = name + "_DEVICE";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + name +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + device_id + R"("})"});
    REQUIRE(login.response.status == 200U);
    return {json_string_after(login.response.body, "access_token"), device_id};
}

[[nodiscard]] auto sync_since(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                              std::string const& since) -> merovingian::homeserver::DispatchResult
{
    auto const path = since.empty() ? std::string{"/_matrix/client/v3/sync"} : "/_matrix/client/v3/sync?since=" + since;
    return merovingian::homeserver::handle_client_server_request(runtime, {"GET", path, token, {}});
}

[[nodiscard]] auto next_batch_of(merovingian::homeserver::DispatchResult const& result)
    -> merovingian::sync::StreamToken
{
    auto const decoded = merovingian::sync::decode_stream_token(json_string_after(result.response.body, "next_batch"));
    REQUIRE(decoded.has_value());
    return *decoded;
}

} // namespace

// Spec: Matrix Client-Server API v1.19, GET /_matrix/client/v3/sync, `since`: "A point in time to
// continue a sync from. This should be the next_batch token returned by an earlier call to this
// endpoint." A token ahead of this server's own counters is not one it issued. Audit run-2 F-03:
// any registered user could raise the server-wide counter to 2^64-1 this way, the next allocation
// wrapped it to 0, and other users' to-device messages were then deleted undelivered.
SCENARIO("A /sync token ahead of the server's streams does not move server-wide state", "[sync][security][sync-stream]")
{
    GIVEN("two users, the second holding a real next_batch token")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const attacker = register_user(runtime, "attacker");
        auto const victim = register_user(runtime, "victim");
        auto const victim_since = json_string_after(sync_since(runtime, victim.token, {}).response.body, "next_batch");
        auto& store = runtime.homeserver.database.persistent_store;
        // A sync can itself allocate an id (presence), so "did not move" means it stayed within a few
        // of where it was, not that it is equal.
        auto const honest_ceiling = store.next_sync_stream_id + 16U;

        WHEN("the first user syncs with a token whose sync component is 2^64-1")
        {
            auto const forged = sync_since(runtime, attacker.token, "0_0_ffffffffffffffff");

            THEN("the request is served as an initial sync with no error")
            {
                REQUIRE(forged.response.status == 200U);
            }

            THEN("the server-wide counter does not move to the forged value")
            {
                REQUIRE(store.next_sync_stream_id < honest_ceiling);
            }

            THEN("the token handed back is an honest one")
            {
                REQUIRE(next_batch_of(forged).sync_stream_id < honest_ceiling);
            }

            THEN("a to-device message sent afterwards still reaches the other user")
            {
                auto const body =
                    R"({"messages":{"@victim:example.org":{")" + victim.device_id + R"(":{"secret":"room-key"}}}})";
                auto const sent = merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"PUT", "/_matrix/client/v3/sendToDevice/m.room_key/txn-after-forged", attacker.token, body});
                REQUIRE(sent.response.status == 200U);

                auto const delivered = sync_since(runtime, victim.token, victim_since);
                REQUIRE(delivered.response.status == 200U);
                REQUIRE(delivered.response.body.find("room-key") != std::string::npos);
                REQUIRE(next_batch_of(delivered).sync_stream_id >
                        merovingian::sync::decode_stream_token(victim_since)->sync_stream_id);
            }
        }

        WHEN("a user's token has an event position past anything this server stored")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", attacker.token, R"({"preset":"private_chat"})"});
            REQUIRE(room.response.status == 200U);
            auto const room_id = json_string_after(room.response.body, "room_id");

            auto const forged = sync_since(runtime, attacker.token, "7fffffffffffffff_7fffffffffffffff_0");

            THEN("they are given the room, as in an initial sync, and a token from this server's stream")
            {
                REQUIRE(forged.response.status == 200U);
                REQUIRE(forged.response.body.find(room_id) != std::string::npos);
                REQUIRE(next_batch_of(forged).event_ordering < std::uint64_t{0x7fffffffffffffffULL});
            }
        }

        WHEN("a user syncs with the server's own current token")
        {
            auto const current = json_string_after(sync_since(runtime, attacker.token, {}).response.body, "next_batch");
            auto const incremental = sync_since(runtime, attacker.token, current);

            THEN("it stays an incremental sync")
            {
                REQUIRE(incremental.response.status == 200U);
                REQUIRE(next_batch_of(incremental).sync_stream_id < honest_ceiling);
            }
        }
    }
}

// The counter's rows are BIGINT on PostgreSQL, and ids are only ever skipped, never reused: a reused
// id falls at or below clients' tokens, which is what deleted their to-device messages.
SCENARIO("The sync stream counter refuses to pass its ceiling rather than wrap", "[database][sync-stream][security]")
{
    GIVEN("a store whose counter is at the ceiling")
    {
        auto store = merovingian::database::PersistentStore{};
        store.next_sync_stream_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        auto const at_ceiling = store.next_sync_stream_id;

        WHEN("another stream id is requested")
        {
            THEN("no id is issued and the counter stays where it was")
            {
                REQUIRE_THROWS_AS(std::ignore = merovingian::database::allocate_sync_stream_id(store),
                                  std::overflow_error);
                REQUIRE(store.next_sync_stream_id == at_ceiling);
            }
        }
    }

    GIVEN("a store whose counter is just below the ceiling")
    {
        auto store = merovingian::database::PersistentStore{};
        store.next_sync_stream_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) - 1U;

        WHEN("another stream id is requested")
        {
            auto const issued = merovingian::database::allocate_sync_stream_id(store);

            THEN("the ceiling itself is issued")
            {
                REQUIRE(issued == static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));
            }
        }
    }
}
