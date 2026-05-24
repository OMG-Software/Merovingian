// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/http/outbound_client.hpp"

#include "federation_signing_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto make_dispatch_worker(merovingian::http::OutboundClient& client)
    -> std::unique_ptr<merovingian::federation::DispatchWorker>
{
    auto config = merovingian::federation::DispatchWorkerConfig{};
    config.origin = "example.org";
    config.key_id = "ed25519:auto";
    config.secret_key = merovingian::federation::test::keypair_from_seed("outbound-dispatch-test").secret_key;
    config.max_queue_depth = 64U;
    config.max_retries = 2U;
    config.idle_poll = std::chrono::milliseconds{5};
    auto resolver = merovingian::federation::DispatchResolver{[](std::string_view server_name) {
        auto result = merovingian::federation::ServerDiscoveryResult{};
        result.server_name = std::string{server_name};
        result.resolved_host = std::string{server_name};
        result.resolved_port = 8448U;
        result.discovery_allowed = true;
        return std::optional<merovingian::federation::ServerDiscoveryResult>{result};
    }};
    auto clock = []() -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    };
    auto sleep_fn = [](std::chrono::milliseconds) {};
    return std::make_unique<merovingian::federation::DispatchWorker>(
        std::move(config), client, std::move(resolver), std::move(clock), std::move(sleep_fn), nullptr);
}

[[nodiscard]] auto login_token(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto room_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"room_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

} // namespace

SCENARIO("send_event enqueues outbound transactions for remote room members",
         "[homeserver][outbound-dispatch][send-event]")
{
    GIVEN("a homeserver runtime with a dispatch worker and a room containing a remote member")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        auto client = merovingian::http::OutboundClient{};
        auto worker = make_dispatch_worker(client);
        homeserver.dispatch_worker = worker.get();

        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.status == 200U);
        auto const id = room_id(room.body);

        // Add a remote member to the room
        auto* local_room = std::ranges::find_if(
            homeserver.database.rooms, [&id](auto const& r) { return r.room_id == id; });
        REQUIRE(local_room != homeserver.database.rooms.end());
        local_room->members.push_back("@bob:remote.example.org");

        auto const summary_before = worker->summary();

        WHEN("a local user sends a message event to the room")
        {
            auto const message = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.message","content":{"body":"hello remote","msgtype":"m.text"}})"});

            THEN("the event is persisted and a transaction is enqueued for the remote server")
            {
                REQUIRE(message.status == 200U);
                auto const summary_after = worker->summary();
                REQUIRE(summary_after.enqueued > summary_before.enqueued);
                REQUIRE(summary_after.pending > 0U);
            }
        }

        worker->request_shutdown();
        worker->join();
    }
}

SCENARIO("Inbound PDU sink assigns stream ordering and notifies sync",
         "[homeserver][outbound-dispatch][inbound-sync]")
{
    GIVEN("a homeserver runtime with a wired pdu_sink and sync notifier")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        // Wire the sync notifier via the proper accessor
        std::ignore = merovingian::homeserver::ensure_sync_notifier(runtime);

        // Wire federation callbacks (creates pdu_sink, dispatch_worker, etc.)
        merovingian::homeserver::wire_federation_callbacks(homeserver);

        // pdu_sink should now be wired
        REQUIRE(homeserver.federation.pdu_sink);
        REQUIRE(homeserver.sync_notifier != nullptr);

        auto const ordering_before = homeserver.database.next_stream_ordering;

        WHEN("an inbound PDU is ingested through the pdu_sink")
        {
            auto envelope = merovingian::federation::InboundPduEnvelope{};
            envelope.event_id = "$test_inbound_event";
            envelope.room_id = "!inbound_test:remote.example.org";
            envelope.sender = "@bob:remote.example.org";
            envelope.event_type = "m.room.message";
            envelope.depth = 1U;
            envelope.json = R"({"type":"m.room.message","content":{"body":"hello","msgtype":"m.text"}})";

            auto const result = homeserver.federation.pdu_sink(envelope);

            THEN("the event is accepted with a non-zero stream ordering")
            {
                REQUIRE(result.status == merovingian::federation::PduIngestionStatus::accepted);
                REQUIRE(homeserver.database.next_stream_ordering > ordering_before);
                auto const& events = homeserver.database.persistent_store.events;
                REQUIRE_FALSE(events.empty());
                REQUIRE(events.back().stream_ordering > 0U);
            }
        }
    }
}

SCENARIO("send_event without dispatch worker persists events locally",
         "[homeserver][outbound-dispatch][no-worker]")
{
    GIVEN("a homeserver runtime without a dispatch worker")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;
        REQUIRE(homeserver.dispatch_worker == nullptr);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.status == 200U);
        auto const id = room_id(room.body);

        WHEN("a local user sends a message event")
        {
            auto const events_before = homeserver.database.persistent_store.events.size();
            auto const message = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.message","content":{"body":"hello","msgtype":"m.text"}})"});

            THEN("the event is persisted even without outbound dispatch")
            {
                REQUIRE(message.status == 200U);
                REQUIRE(homeserver.database.persistent_store.events.size() > events_before);
            }
        }
    }
}

SCENARIO("send_event does not enqueue transactions for local-only rooms",
         "[homeserver][outbound-dispatch][local-only]")
{
    GIVEN("a homeserver runtime with a dispatch worker and a room with only local members")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        auto client = merovingian::http::OutboundClient{};
        auto worker = make_dispatch_worker(client);
        homeserver.dispatch_worker = worker.get();

        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.status == 200U);
        auto const id = room_id(room.body);

        auto const summary_before = worker->summary();

        WHEN("a local user sends a message event to the local-only room")
        {
            auto const message = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.message","content":{"body":"local only","msgtype":"m.text"}})"});

            THEN("the event is persisted but no outbound transactions are enqueued")
            {
                REQUIRE(message.status == 200U);
                auto const summary_after = worker->summary();
                REQUIRE(summary_after.enqueued == summary_before.enqueued);
            }
        }

        worker->request_shutdown();
        worker->join();
    }
}