// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Sync tokens this server did not issue in its current stream token epoch: forged tokens ahead of its streams
// (ADR-0315, audit run-2 F-03) and tokens issued before a database restore (ADR-0592, issue 550).
//
// Spec: Matrix Client-Server API v1.19, GET /_matrix/client/v3/sync, `since`: "A point in time to continue a sync
// from. This should be the next_batch token returned by an earlier call to this endpoint." The spec lists no error
// for a token the server cannot serve, so such a token is served as an initial sync. MSC4186 (sliding sync) answers
// an unknown `pos` with 400 M_UNKNOWN_POS.
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/stream_token_epoch.hpp"
#include "merovingian/sync/StreamToken.hpp"
#include "merovingian/sync/ToDevicePosition.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <tuple>

namespace
{

[[nodiscard]] auto config_with_database(merovingian::config::DatabaseConfig database) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        std::move(database),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    return config_with_database(merovingian::tests::in_memory_database_config());
}

[[nodiscard]] auto sqlite_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    return config_with_database(std::move(database));
}

[[nodiscard]] auto unique_path(std::string const& label) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-sync-restore-" + label + "-" + std::to_string(now) + ".sqlite3");
}

// A SQLite database is its file plus, while a connection has it open, a write-ahead log and its index. Every
// runtime on it has been destroyed before this runs, so this is a copy of a database at rest, as a backup is.
auto copy_database(std::filesystem::path const& from, std::filesystem::path const& to) -> void
{
    for (auto const* suffix : {"", "-wal", "-shm", "-journal"})
    {
        auto const source = std::filesystem::path{from.string() + suffix};
        auto const target = std::filesystem::path{to.string() + suffix};
        std::filesystem::remove(target);
        if (std::filesystem::exists(source))
        {
            std::filesystem::copy_file(source, target);
        }
    }
}

auto remove_database(std::filesystem::path const& path) -> void
{
    for (auto const* suffix : {"", "-wal", "-shm", "-journal"})
    {
        std::filesystem::remove(std::filesystem::path{path.string() + suffix});
    }
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

// A token with this server's own epoch, so what decides how it is served is its positions alone.
[[nodiscard]] auto token_in_this_epoch(merovingian::homeserver::ClientServerRuntime const& runtime,
                                       std::uint64_t event_ordering, std::uint64_t membership_ordering,
                                       std::uint64_t sync_stream_id) -> std::string
{
    return merovingian::sync::encode_stream_token({event_ordering, membership_ordering, sync_stream_id,
                                                   runtime.homeserver.database.persistent_store.stream_token_epoch});
}

auto send_room_key(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& sender_token,
                   std::string const& user, std::string const& device, std::string const& txn) -> void
{
    auto const body = R"({"messages":{"@)" + user + R"(:example.org":{")" + device + R"(":{"secret":"room-key-for-)" +
                      user + "-" + txn + R"("}}}})";
    auto const sent = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/sendToDevice/m.room_key/" + txn, sender_token, body});
    REQUIRE(sent.response.status == 200U);
}

} // namespace

// ADR-0315, audit run-2 F-03: any registered user could raise the server-wide counter to 2^64-1 with a forged
// token, the next allocation wrapped it to 0, and other users' to-device messages were then deleted undelivered.
// Every forged token here carries the server's own epoch, so the positions are what is judged (ADR-0592).
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
        REQUIRE(store.stream_token_epoch != 0U);
        // A sync can itself allocate an id (presence), so "did not move" means it stayed within a few
        // of where it was, not that it is equal.
        auto const honest_ceiling = store.next_sync_stream_id + 16U;

        WHEN("the first user syncs with a token whose sync component is 2^64-1")
        {
            auto const forged =
                sync_since(runtime, attacker.token,
                           token_in_this_epoch(runtime, 0U, 0U, std::numeric_limits<std::uint64_t>::max()));

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
                REQUIRE(next_batch_of(forged).epoch == store.stream_token_epoch);
            }

            THEN("a to-device message sent afterwards still reaches the other user")
            {
                send_room_key(runtime, attacker.token, "victim", victim.device_id, "txn-after-forged");

                auto const delivered = sync_since(runtime, victim.token, victim_since);
                REQUIRE(delivered.response.status == 200U);
                REQUIRE(delivered.response.body.find("room-key-for-victim-txn-after-forged") != std::string::npos);
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

            auto const forged =
                sync_since(runtime, attacker.token,
                           token_in_this_epoch(runtime, 0x7fffffffffffffffULL, 0x7fffffffffffffffULL, 0U));

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

            auto const forged =
                sync_since(runtime, attacker.token, token_in_this_epoch(runtime, 0U, 0x7fffffffffffffffULL, 0U));

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

// ADR-0315: a restored database can put the counter below tokens clients still hold. Even before the restore step
// runs, a sync in that window is served as an initial sync and hands back a token from the restored stream, so a
// client that syncs is off the old token before the counter can reach it, and to-device rows numbered below the
// old token are delivered rather than purged as acknowledged.
SCENARIO("A client that syncs before a restored counter reaches its token still gets its to-device messages",
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
            send_room_key(runtime, alice.token, "alice", alice.device_id, "txn-restore-alice");
            send_room_key(runtime, alice.token, "bob", bob.device_id, "txn-restore-bob");
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

// Issue 550, ADR-0592: a client offline from a restore until the counter has passed its token could not be told
// from a current one, and the to-device rows numbered after the restore at or below its token were purged as
// acknowledged: room keys lost. The restore step (`merovingian-server --after-restore`) starts a fresh epoch, so
// every token from before it is served as an initial sync, whatever its positions. This is a real restore: the
// SQLite file is copied away, the server runs on and issues tokens, then the copy is put back.
SCENARIO("Clients returning after a restore with tokens the counter has passed still get their to-device messages",
         "[sync][security][sync-stream][restore][issue-550]")
{
    GIVEN("a backup, then two clients holding tokens issued after it, then the backup restored")
    {
        auto const path = unique_path("live");
        auto const backup = unique_path("backup");
        remove_database(path);
        remove_database(backup);
        auto const config = sqlite_config(path);
        auto alice = LoggedInUser{};
        auto bob = LoggedInUser{};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            alice = register_user(started.runtime, "alice");
            bob = register_user(started.runtime, "bob");
        }
        copy_database(path, backup);

        auto alice_since = std::string{};
        auto bob_since = std::string{};
        auto epoch_before = std::uint64_t{0U};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            auto& store = started.runtime.homeserver.database.persistent_store;
            epoch_before = store.stream_token_epoch;
            for (auto allocated = 0; allocated < 64; ++allocated)
            {
                std::ignore = merovingian::database::allocate_sync_stream_id(store);
            }
            alice_since = json_string_after(sync_since(started.runtime, alice.token, {}).response.body, "next_batch");
            bob_since = json_string_after(sync_since(started.runtime, bob.token, {}).response.body, "next_batch");
        }
        auto const old_position = std::max(merovingian::sync::decode_stream_token(alice_since)->sync_stream_id,
                                           merovingian::sync::decode_stream_token(bob_since)->sync_stream_id);

        copy_database(backup, path);
        REQUIRE(merovingian::homeserver::begin_stream_token_epoch_after_restore(config));

        WHEN("each is sent a room key, the counter passes both their tokens, and both return with them")
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            auto& runtime = started.runtime;
            auto& store = runtime.homeserver.database.persistent_store;
            REQUIRE(store.next_sync_stream_id < old_position);
            send_room_key(runtime, bob.token, "alice", alice.device_id, "txn-after-restore");
            send_room_key(runtime, alice.token, "bob", bob.device_id, "txn-after-restore");
            while (store.next_sync_stream_id <= old_position)
            {
                std::ignore = merovingian::database::allocate_sync_stream_id(store);
            }
            // The messages are numbered at or below the old tokens: without the epoch, these tokens would
            // acknowledge them and the sync would delete them.
            REQUIRE(store.to_device_messages.size() == 2U);
            for (auto const& message : store.to_device_messages)
            {
                REQUIRE(message.stream_id <= old_position);
            }

            auto const alice_sync = sync_since(runtime, alice.token, alice_since);
            auto const bob_sync = sync_since(runtime, bob.token, bob_since);

            THEN("the database is in a different epoch from the one the tokens were issued in")
            {
                REQUIRE(store.stream_token_epoch != 0U);
                REQUIRE(store.stream_token_epoch != epoch_before);
                REQUIRE(merovingian::sync::decode_stream_token(alice_since)->epoch == epoch_before);
            }

            THEN("each client receives the room key sent to them")
            {
                REQUIRE(alice_sync.response.status == 200U);
                REQUIRE(bob_sync.response.status == 200U);
                REQUIRE(alice_sync.response.body.find("room-key-for-alice-txn-after-restore") != std::string::npos);
                REQUIRE(bob_sync.response.body.find("room-key-for-bob-txn-after-restore") != std::string::npos);
            }

            THEN("each is handed a token in the restored database's epoch")
            {
                REQUIRE(next_batch_of(alice_sync).epoch == store.stream_token_epoch);
                REQUIRE(next_batch_of(bob_sync).epoch == store.stream_token_epoch);
            }
        }
        remove_database(path);
        remove_database(backup);
    }
}

// ADR-0592: the epoch is drawn once for a database and kept across restarts, or tokens would turn foreign at every
// restart; --after-restore replaces it, and has nothing to do for the in-memory backend.
SCENARIO("A database keeps its stream token epoch across restarts until --after-restore replaces it",
         "[sync][sync-stream][restore]")
{
    GIVEN("a SQLite database the server has started on once")
    {
        auto const path = unique_path("epoch");
        remove_database(path);
        auto const config = sqlite_config(path);
        auto first = std::uint64_t{0U};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            first = started.runtime.homeserver.database.persistent_store.stream_token_epoch;
        }

        WHEN("the server restarts, then --after-restore runs, then the server starts again")
        {
            auto after_restart = std::uint64_t{0U};
            {
                auto started = merovingian::homeserver::start_client_server(config);
                REQUIRE(started.started);
                after_restart = started.runtime.homeserver.database.persistent_store.stream_token_epoch;
            }
            auto const restored = merovingian::homeserver::begin_stream_token_epoch_after_restore(config);
            auto after_restore = std::uint64_t{0U};
            {
                auto started = merovingian::homeserver::start_client_server(config);
                REQUIRE(started.started);
                after_restore = started.runtime.homeserver.database.persistent_store.stream_token_epoch;
            }

            THEN("the first start drew an epoch and the restart kept it")
            {
                REQUIRE(first != 0U);
                REQUIRE(after_restart == first);
            }

            THEN("--after-restore replaced it with a different one, which the next start uses")
            {
                REQUIRE(restored);
                REQUIRE(after_restore != 0U);
                REQUIRE(after_restore != first);
            }
        }
        remove_database(path);
    }

    GIVEN("the in-memory backend")
    {
        WHEN("--after-restore runs")
        {
            auto const restored =
                merovingian::homeserver::begin_stream_token_epoch_after_restore(registration_enabled_config());

            THEN("it is refused: there is no backup to restore into it")
            {
                REQUIRE_FALSE(restored);
            }
        }
    }
}

// ADR-0592: a token from another epoch is foreign whatever its positions, including ones this server could have
// issued; a token with no epoch component is one too, since every database has an epoch. On /sync it acknowledges
// nothing, so a to-device message at or below its sync position is delivered, not deleted.
SCENARIO("A /sync token from another stream token epoch is served as an initial sync", "[sync][security][restore]")
{
    GIVEN("a user with a to-device message waiting, and the current position of the stream")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        send_room_key(runtime, alice.token, "bob", bob.device_id, "txn-foreign-epoch");
        auto& store = runtime.homeserver.database.persistent_store;
        auto const current = next_batch_of(sync_since(runtime, alice.token, {}));
        auto const other_epoch = store.stream_token_epoch ^ 0x5a5a5a5a5a5a5a5aULL;

        WHEN("bob syncs with the current positions in another epoch, then with no epoch at all")
        {
            auto const foreign = merovingian::sync::encode_stream_token(
                {current.event_ordering, current.membership_ordering, current.sync_stream_id, other_epoch});
            auto const unversioned = merovingian::sync::encode_stream_token(
                {current.event_ordering, current.membership_ordering, current.sync_stream_id, 0U});
            auto const first = sync_since(runtime, bob.token, foreign);
            auto const second = sync_since(runtime, bob.token, unversioned);

            THEN("each is answered as an initial sync that still holds the message")
            {
                REQUIRE(first.response.status == 200U);
                REQUIRE(first.response.body.find("room-key-for-bob-txn-foreign-epoch") != std::string::npos);
                REQUIRE(second.response.status == 200U);
                REQUIRE(second.response.body.find("room-key-for-bob-txn-foreign-epoch") != std::string::npos);
            }

            THEN("each hands back a token in this server's epoch")
            {
                REQUIRE(next_batch_of(first).epoch == store.stream_token_epoch);
                REQUIRE(next_batch_of(second).epoch == store.stream_token_epoch);
            }
        }

        WHEN("bob syncs with the same positions in this server's epoch")
        {
            auto const current_token = merovingian::sync::encode_stream_token(current);
            auto const acknowledged = sync_since(runtime, bob.token, current_token);
            auto const after = sync_since(runtime, bob.token, current_token);

            THEN("the message counts as seen, as it would for any token this server issued at that position")
            {
                REQUIRE(acknowledged.response.status == 200U);
                REQUIRE(after.response.body.find("room-key-for-bob-txn-foreign-epoch") == std::string::npos);
            }
        }
    }
}

// MSC4186 (unstable): a `pos` the server cannot serve is answered 400 M_UNKNOWN_POS. The to_device extension's own
// `since` survives that answer in clients, so it carries the epoch too (ADR-0592): one from another epoch
// acknowledges nothing.
SCENARIO("Sliding sync positions from another stream token epoch acknowledge nothing",
         "[sliding-sync][security][restore]")
{
    GIVEN("a user with a to-device message waiting")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        send_room_key(runtime, alice.token, "bob", bob.device_id, "txn-sliding");
        auto& store = runtime.homeserver.database.persistent_store;
        auto const other_epoch = store.stream_token_epoch ^ 0x5a5a5a5a5a5a5a5aULL;
        auto const path = std::string{"/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"};

        WHEN("bob sends a pos from another epoch")
        {
            auto const pos = merovingian::sync::encode_stream_token({0U, 0U, store.next_sync_stream_id, other_epoch});
            auto const answered = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", path + "?pos=" + pos, bob.token, R"({"conn_id":"encryption"})"}, false);

            THEN("it is an unknown position")
            {
                REQUIRE(answered.response.status == 400U);
                REQUIRE(answered.response.body.find("M_UNKNOWN_POS") != std::string::npos);
            }
        }

        WHEN("bob asks for to-device messages with a since from another epoch past the message")
        {
            auto const since = merovingian::sync::encode_to_device_position({store.next_sync_stream_id, other_epoch});
            auto const answered = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", path, bob.token,
                 R"({"conn_id":"encryption","extensions":{"to_device":{"enabled":true,"since":")" + since + R"("}}})"},
                false);

            THEN("the message is delivered, and the next position is in this server's epoch")
            {
                REQUIRE(answered.response.status == 200U);
                REQUIRE(answered.response.body.find("room-key-for-bob-txn-sliding") != std::string::npos);
                auto const next = merovingian::sync::decode_to_device_position(json_string_after(
                    answered.response.body.substr(answered.response.body.find("to_device")), "next_batch"));
                REQUIRE(next.has_value());
                REQUIRE(next->epoch == store.stream_token_epoch);
            }
        }
    }
}

// Spec: GET /_matrix/client/v3/keys/changes, `from`: "Should be the next_batch field from a response to an earlier
// call to /sync." ADR-0592: a `from` from another epoch names no position in this numbering, so the answer is
// every change the log holds rather than none.
SCENARIO("/keys/changes from a token of another stream token epoch lists every change", "[e2ee][security][restore]")
{
    GIVEN("two users sharing a room, one of whose keys changed before the other's latest token")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice.token, R"({"preset":"public_chat"})"});
        REQUIRE(room.response.status == 200U);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/join/" + json_string_after(room.response.body, "room_id"),
                              bob.token, "{}"})
                    .response.status == 200U);
        auto const device = bob.device_id;
        auto const keys = R"({"device_keys":{"user_id":"@bob:example.org","device_id":")" + device +
                          R"(","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:)" + device +
                          R"(":"curve25519-public","ed25519:)" + device + R"(":"ed25519-public"}}})";
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/keys/upload", bob.token, keys})
                    .response.status == 200U);
        auto const latest = next_batch_of(sync_since(runtime, alice.token, {}));
        auto& store = runtime.homeserver.database.persistent_store;
        auto const to = merovingian::sync::encode_stream_token(latest);
        auto const changes_from = [&](std::uint64_t epoch) {
            auto const from = merovingian::sync::encode_stream_token(
                {latest.event_ordering, latest.membership_ordering, latest.sync_stream_id, epoch});
            return merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/keys/changes?from=" + from + "&to=" + to, alice.token, {}});
        };

        WHEN("alice asks for changes from her latest token, in this epoch and in another")
        {
            auto const current = changes_from(store.stream_token_epoch);
            auto const foreign = changes_from(store.stream_token_epoch ^ 0x5a5a5a5a5a5a5a5aULL);

            THEN("this epoch's token lists nothing before it, and the other epoch's lists bob")
            {
                REQUIRE(current.response.status == 200U);
                REQUIRE(current.response.body.find("@bob:example.org") == std::string::npos);
                REQUIRE(foreign.response.status == 200U);
                REQUIRE(foreign.response.body.find("@bob:example.org") != std::string::npos);
            }
        }
    }
}
