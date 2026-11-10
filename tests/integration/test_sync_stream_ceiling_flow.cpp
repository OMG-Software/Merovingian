// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The sync stream counter near its ceiling (ADR-0315): what is refused before it is stored, what still finishes,
// and a watermark write that fails (ADR-0540). Request-level, so in integration (issue 552). The counter's own
// boundary, without a runtime, is in tests/unit/test_sync_stream_ceiling.cpp.
#include "../support/ConsoleLogCapture.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstdint>
#include <functional>
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

} // namespace

// ADR-0540: a failed watermark write must not fail the allocation (callers allocate after their own commit),
// and the next successful write must record the counter past the id whose write failed, so a restart cannot
// hand it out again.
SCENARIO("A sync stream id whose watermark write fails is issued and covered by the next write",
         "[database][sync-stream][security]")
{
    GIVEN("a running store whose watermark write is made to fail once")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& store = started.runtime.homeserver.database.persistent_store;
        auto const before = store.next_sync_stream_id;
        merovingian::database::enable_statement_capture(store, 8U);
        merovingian::database::force_persist_failure_for_statement(store, "upsert_sync_stream_watermark");

        WHEN("two stream ids are requested, the first while the write fails")
        {
            auto const [failed, next, logged] = std::invoke([&store] {
                auto const capture = merovingian::tests::ConsoleLogCapture{};
                auto const first = merovingian::database::allocate_sync_stream_id(store);
                auto const second = merovingian::database::allocate_sync_stream_id(store);
                return std::tuple{first, second, capture.has_line("ERROR", "sync_stream.watermark_persist_failed")};
            });

            THEN("the failed write is logged at error level")
            {
                REQUIRE(logged);
            }

            THEN("both are issued, in order, and never the same position")
            {
                REQUIRE(failed == before + 1U);
                REQUIRE(next == before + 2U);
            }
            THEN("the watermark the second write commits is past the id whose write failed")
            {
                REQUIRE_FALSE(store.captured_statements.empty());
                auto const& written = store.captured_statements.back();
                REQUIRE(written.name == "upsert_sync_stream_watermark");
                REQUIRE(written.parameters.size() == 1U);
                REQUIRE(written.parameters[0].value == std::to_string(next));
                REQUIRE(next > failed);
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

// ADR-0315: a remote server would keep a knock or an invite that this server then failed to store, so these
// are refused before they leave. Nothing listens at elsewhere.example.org, so reaching the exchange would
// answer some other error.
SCENARIO(
    "Membership changes that need another server are refused before the exchange when the counter is near its limit",
    "[database][sync-stream][security]")
{
    GIVEN("a user in a room, and a counter inside the reserve below its ceiling")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = register_user(runtime, "alice");
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", user.token, R"({"preset":"private_chat"})"});
        REQUIRE(room.response.status == 200U);
        auto const room_path = "/_matrix/client/v3/rooms/" + json_string_after(room.response.body, "room_id");
        auto& store = runtime.homeserver.database.persistent_store;
        constexpr auto ceiling = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        store.next_sync_stream_id = ceiling - merovingian::database::sync_stream_write_reserve;
        auto const events_before = store.events.size();

        // Generated once, across every run of this GIVEN, so nothing here can name this run's room.
        struct Trigger final
        {
            std::string remote_path{};
            std::string body{};
        };
        auto const trigger = GENERATE(
            Trigger{"/_matrix/client/v3/knock/!remote:elsewhere.example.org", "{}"},
            Trigger{"/_matrix/client/v3/join/!remote:elsewhere.example.org", "{}"},
            Trigger{{}, R"({"user_id":"@bob:elsewhere.example.org"})"},
            Trigger{
                {},
                R"({"id_server":"id.elsewhere.example.org","id_access_token":"t","medium":"email","address":"bob@example.org"})"});
        auto const path = trigger.remote_path.empty() ? room_path + "/invite" : trigger.remote_path;

        WHEN("the user asks for it: " + path + " " + trigger.body)
        {
            auto const answered = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", path, user.token, trigger.body});

            THEN("the counter is the reason it is refused, and nothing was stored")
            {
                REQUIRE(answered.response.status == 500U);
                REQUIRE(answered.response.body.find("sync stream counter exhausted") != std::string::npos);
                REQUIRE(store.events.size() == events_before);
            }
        }
    }
}
