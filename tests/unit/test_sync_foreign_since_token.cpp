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

        WHEN("a user's token is ahead of this server only in its membership position")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", attacker.token, R"({"preset":"private_chat"})"});
            REQUIRE(room.response.status == 200U);
            auto const room_id = json_string_after(room.response.body, "room_id");

            auto const forged = sync_since(runtime, attacker.token, "0_7fffffffffffffff_0");

            THEN("they are given the room, as in an initial sync, and a token from this server's stream")
            {
                REQUIRE(forged.response.status == 200U);
                REQUIRE(forged.response.body.find(room_id) != std::string::npos);
                REQUIRE(next_batch_of(forged).membership_ordering < std::uint64_t{0x7fffffffffffffffULL});
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
// ADR-0315: a restored database can put the counter below tokens clients still hold. Any sync in that
// window is served as an initial sync and hands back a token from the restored stream, so a client that
// syncs is off the old token before the counter can reach it, and to-device rows numbered below the old
// token are delivered rather than purged as acknowledged.
SCENARIO("Clients holding tokens from before a database restore still get their to-device messages",
         "[sync][security][sync-stream][restore]")
{
    GIVEN("two clients holding tokens ahead of a counter set back by a restore")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        auto& store = runtime.homeserver.database.persistent_store;
        auto const counter_at_backup = store.next_sync_stream_id;
        for (auto allocated = 0; allocated < 64; ++allocated)
        {
            std::ignore = merovingian::database::allocate_sync_stream_id(store);
        }
        auto const alice_since = json_string_after(sync_since(runtime, alice.token, {}).response.body, "next_batch");
        auto const bob_since = json_string_after(sync_since(runtime, bob.token, {}).response.body, "next_batch");
        store.next_sync_stream_id = counter_at_backup;

        WHEN("each is sent a to-device message numbered below their token, and they sync")
        {
            auto const send_to = [&](std::string const& user, std::string const& device, std::string const& txn) {
                auto const body = R"({"messages":{"@)" + user + R"(:example.org":{")" + device +
                                  R"(":{"secret":"room-key-for-)" + user + R"("}}}})";
                auto const sent = merovingian::homeserver::handle_client_server_request(
                    runtime, {"PUT", "/_matrix/client/v3/sendToDevice/m.room_key/" + txn, alice.token, body});
                REQUIRE(sent.response.status == 200U);
            };
            send_to("alice", alice.device_id, "txn-restore-alice");
            send_to("bob", bob.device_id, "txn-restore-bob");
            auto const alice_token_position = merovingian::sync::decode_stream_token(alice_since)->sync_stream_id;
            REQUIRE(store.next_sync_stream_id < alice_token_position);

            auto const alice_sync = sync_since(runtime, alice.token, alice_since);
            auto const bob_sync = sync_since(runtime, bob.token, bob_since);

            THEN("each client receives their own message")
            {
                REQUIRE(alice_sync.response.body.find("room-key-for-alice") != std::string::npos);
                REQUIRE(bob_sync.response.body.find("room-key-for-bob") != std::string::npos);
            }

            THEN("each is handed a token from the restored stream, replacing the old one")
            {
                REQUIRE(next_batch_of(alice_sync).sync_stream_id < alice_token_position);
                REQUIRE(next_batch_of(bob_sync).sync_stream_id < alice_token_position);
            }
        }
    }
}

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

// ADR-0315: one request takes several sync positions after it stores an event. Refusing the event while
// positions remain means a request either stores nothing or can finish.
SCENARIO("Local events stop being stored before the sync stream counter runs out", "[database][sync-stream][security]")
{
    GIVEN("a registered user, and a counter inside the reserve below its ceiling")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = register_user(runtime, "alice");
        auto& store = runtime.homeserver.database.persistent_store;
        auto const events_before = store.events.size();
        auto const rooms_before = store.rooms.size();
        constexpr auto ceiling = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        store.next_sync_stream_id = ceiling - merovingian::database::sync_stream_write_reserve;

        WHEN("the user creates a room")
        {
            auto const created = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", user.token, R"({"preset":"private_chat"})"});

            THEN("it fails and leaves no room or event behind")
            {
                REQUIRE(created.response.status >= 400U);
                REQUIRE(store.rooms.size() == rooms_before);
                REQUIRE(store.events.size() == events_before);
            }
        }

        WHEN("another stream id is requested for a request already under way")
        {
            auto const issued = merovingian::database::allocate_sync_stream_id(store);

            THEN("one is still issued")
            {
                REQUIRE(issued == ceiling - merovingian::database::sync_stream_write_reserve + 1U);
            }
        }
    }
}

// ADR-0315: forgetting deletes, so the store's reserve does not cover it. It takes its position first.
SCENARIO("Forgetting a room at the sync stream counter's limit keeps the membership",
         "[database][sync-stream][security]")
{
    GIVEN("a user who has left a room, and a counter at its ceiling")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = register_user(runtime, "alice");
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", user.token, R"({"preset":"private_chat"})"});
        REQUIRE(room.response.status == 200U);
        auto const room_path = "/_matrix/client/v3/rooms/" + json_string_after(room.response.body, "room_id");
        auto const left = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", room_path + "/leave", user.token, "{}"});
        REQUIRE(left.response.status == 200U);
        auto& store = runtime.homeserver.database.persistent_store;
        auto const memberships_before = store.memberships.size();
        store.next_sync_stream_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

        WHEN("the user forgets the room")
        {
            auto const forgotten = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", room_path + "/forget", user.token, "{}"});

            THEN("the request is answered with an error")
            {
                REQUIRE(forgotten.response.status == 500U);
            }

            THEN("the membership is still there")
            {
                REQUIRE(store.memberships.size() == memberships_before);
            }
        }
    }
}

// ADR-0315: other devices learn of a key change through a sync position taken after the key is stored, so
// a key upload is refused while the client can still retry it, not after it can no longer be announced.
SCENARIO("Key and device uploads are refused before they are stored when the sync stream counter is near its limit",
         "[database][sync-stream][security]")
{
    GIVEN("a logged-in user and a valid device key upload")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = register_user(runtime, "alice");
        auto const device = user.device_id;
        auto const body = R"({"device_keys":{"user_id":"@alice:example.org","device_id":")" + device +
                          R"(","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:)" + device +
                          R"(":"curve25519-public","ed25519:)" + device + R"(":"ed25519-public"},"signatures":{}}})";
        auto& store = runtime.homeserver.database.persistent_store;
        auto const device_path = "/_matrix/client/v3/devices/" + device;
        constexpr auto ceiling = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

        WHEN("the counter is well below its limit")
        {
            auto const uploaded = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", user.token, body});
            auto const signatures = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/signatures/upload", user.token, "{}"});
            auto const renamed = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", device_path, user.token, R"({"display_name":"renamed"})"});

            THEN("all of them are accepted")
            {
                REQUIRE(uploaded.response.status == 200U);
                REQUIRE(store.device_keys.size() == 1U);
                REQUIRE(signatures.response.status == 200U);
                REQUIRE(renamed.response.status == 200U);
            }
        }

        WHEN("the counter is at its limit")
        {
            store.next_sync_stream_id = ceiling;
            auto const uploaded = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", user.token, body});
            auto const signatures = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/signatures/upload", user.token, "{}"});
            auto const renamed = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", device_path, user.token, R"({"display_name":"renamed"})"});
            auto const read_back =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", device_path, user.token, {}});

            THEN("each is refused and nothing was stored")
            {
                REQUIRE(uploaded.response.status == 500U);
                REQUIRE(store.device_keys.empty());
                REQUIRE(signatures.response.status == 500U);
                REQUIRE(renamed.response.status == 500U);
                REQUIRE(read_back.response.body.find("renamed") == std::string::npos);
            }
        }
    }
}

// ADR-0315: signing out revokes access. It must not depend on a position to announce it.
SCENARIO("Logging out at the sync stream counter's limit still revokes the session",
         "[database][sync-stream][security]")
{
    GIVEN("two users sharing a room, and a counter at its ceiling")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice.token, R"({"preset":"public_chat"})"});
        REQUIRE(room.response.status == 200U);
        auto const joined = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/join/" + json_string_after(room.response.body, "room_id"), bob.token, "{}"});
        REQUIRE(joined.response.status == 200U);
        auto& store = runtime.homeserver.database.persistent_store;
        store.next_sync_stream_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

        WHEN("one of them logs out")
        {
            auto const logged_out = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/logout", bob.token, "{}"});

            THEN("the logout succeeds and the token no longer works")
            {
                REQUIRE(logged_out.response.status == 200U);
                auto const whoami = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/account/whoami", bob.token, {}});
                REQUIRE(whoami.response.status == 401U);
            }
        }
    }
}

// ADR-0315: writes that take their position first fail with nothing stored; the client still gets an answer.
SCENARIO("A client request that finds the sync stream counter exhausted is answered",
         "[database][sync-stream][security]")
{
    GIVEN("a logged-in user and a counter at its ceiling")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = register_user(runtime, "alice");
        auto& store = runtime.homeserver.database.persistent_store;
        store.next_sync_stream_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

        WHEN("the user writes account data")
        {
            auto const written = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/user/@alice:example.org/account_data/org.example.ceiling",
                          user.token, R"({"a":1})"});

            THEN("the request is answered with an error")
            {
                REQUIRE(written.response.status == 500U);
            }
        }
    }
}
