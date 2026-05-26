// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
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
#include <vector>

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

[[nodiscard]] auto has_membership(merovingian::database::PersistentStore const& store, std::string_view id,
                                  std::string_view user_id, std::string_view membership) -> bool
{
    return std::ranges::any_of(store.memberships, [&](merovingian::database::PersistentMembership const& current) {
        return current.room_id == id && current.user_id == user_id && current.membership == membership;
    });
}

[[nodiscard]] auto has_local_member(merovingian::homeserver::LocalDatabase const& database, std::string_view id,
                                    std::string_view user_id) -> bool
{
    auto const room = std::ranges::find_if(database.rooms, [&](auto const& current) {
        return current.room_id == id;
    });
    return room != database.rooms.end() &&
           std::ranges::any_of(room->members, [&](std::string const& member) { return member == user_id; });
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
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto client = merovingian::http::OutboundClient{};
        auto worker = make_dispatch_worker(client);
        homeserver.dispatch_worker.reset(worker.get());
        std::ignore = worker.release();

        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        // Add a remote member to the room
        auto local_room = std::ranges::find_if(
            homeserver.database.rooms, [&id](auto const& r) { return r.room_id == id; });
        REQUIRE(local_room != homeserver.database.rooms.end());
        local_room->members.push_back("@bob:remote.example.org");

        auto const summary_before = homeserver.dispatch_worker->summary();

        WHEN("a local user sends a message event to the room")
        {
            auto const message = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.message","content":{"body":"hello remote","msgtype":"m.text"}})"});

            THEN("the event is persisted and a transaction is enqueued for the remote server")
            {
                REQUIRE(message.response.status == 200U);
                auto const summary_after = homeserver.dispatch_worker->summary();
                REQUIRE(summary_after.enqueued > summary_before.enqueued);
                REQUIRE(summary_after.pending > 0U);
            }
        }

        homeserver.dispatch_worker->request_shutdown();
        homeserver.dispatch_worker->join();
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
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        WHEN("a local user sends a message event")
        {
            auto const events_before = homeserver.database.persistent_store.events.size();
            auto const message = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.message","content":{"body":"hello","msgtype":"m.text"}})"});

            THEN("the event is persisted even without outbound dispatch")
            {
                REQUIRE(message.response.status == 200U);
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
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto client = merovingian::http::OutboundClient{};
        auto worker = make_dispatch_worker(client);
        homeserver.dispatch_worker.reset(worker.get());
        std::ignore = worker.release();

        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        auto const summary_before = homeserver.dispatch_worker->summary();

        WHEN("a local user sends a message event to the local-only room")
        {
            auto const message = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.message","content":{"body":"local only","msgtype":"m.text"}})"});

            THEN("the event is persisted but no outbound transactions are enqueued")
            {
                REQUIRE(message.response.status == 200U);
                auto const summary_after = homeserver.dispatch_worker->summary();
                REQUIRE(summary_after.enqueued == summary_before.enqueued);
            }
        }

        homeserver.dispatch_worker->request_shutdown();
        homeserver.dispatch_worker->join();
    }
}

SCENARIO("Inbound send_join records remote membership for outbound delivery",
         "[homeserver][federation][send-join][membership]")
{
    GIVEN("a local room and a production membership acceptor")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto client = merovingian::http::OutboundClient{};
        auto worker = make_dispatch_worker(client);
        homeserver.dispatch_worker.reset(worker.get());
        std::ignore = worker.release();

        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        merovingian::homeserver::wire_federation_callbacks(homeserver);
        REQUIRE(homeserver.federation.membership_acceptor);

        WHEN("a remote homeserver completes send_join for one of its users")
        {
            auto const remote_user = std::string{"@bob:remote.example.org"};
            auto envelope = merovingian::federation::InboundPduEnvelope{};
            envelope.event_id = "$join_event:remote.example.org";
            envelope.room_id = id;
            envelope.sender = remote_user;
            envelope.event_type = "m.room.member";
            envelope.state_key = remote_user;
            envelope.depth = 10U;
            envelope.json =
                "{\"auth_events\":[],\"content\":{\"membership\":\"join\"},\"depth\":10,\"origin_server_ts\":1,"
                "\"prev_events\":[],\"room_id\":\"" +
                id + "\",\"sender\":\"" + remote_user + "\",\"state_key\":\"" + remote_user +
                "\",\"type\":\"m.room.member\"}";

            auto const accepted = homeserver.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_join, id, envelope.event_id, envelope);

            THEN("the persistent and in-memory room membership include the remote user")
            {
                REQUIRE(accepted.accepted);
                REQUIRE(has_membership(homeserver.database.persistent_store, id, remote_user, "join"));
                REQUIRE(has_local_member(homeserver.database, id, remote_user));
            }

            THEN("later local messages are queued for that remote homeserver")
            {
                auto const summary_before = homeserver.dispatch_worker->summary();
                auto const message = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                              R"({"type":"m.room.message","content":{"body":"hello joined remote","msgtype":"m.text"}})"});

                REQUIRE(message.response.status == 200U);
                auto const summary_after = homeserver.dispatch_worker->summary();
                REQUIRE(summary_after.enqueued > summary_before.enqueued);
            }
        }

        homeserver.dispatch_worker->request_shutdown();
        homeserver.dispatch_worker->join();
    }
}

SCENARIO("Inbound federation invites are signed, persisted, and visible in sync",
         "[homeserver][federation][invite][sync]")
{
    GIVEN("a local user and a production invite handler")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              merovingian::tests::registration_json("bob", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        homeserver.outbound_client.reset();
        homeserver.discovery_network.reset();
        merovingian::homeserver::wire_federation_callbacks(homeserver);
        REQUIRE(homeserver.federation.invite_handler);

        WHEN("a remote homeserver invites the local user")
        {
            auto request = merovingian::federation::InviteRequest{};
            request.room_id = "!remote_room:remote.example.org";
            request.event_id = "$invite_event:remote.example.org";
            request.room_version = "12";
            request.invite_event_json =
                R"({"auth_events":[],"content":{"membership":"invite"},"depth":7,"origin_server_ts":1,)"
                R"("prev_events":[],"room_id":"!remote_room:remote.example.org","sender":"@alice:remote.example.org",)"
                R"("state_key":"@bob:example.org","type":"m.room.member"})";

            auto const accepted = homeserver.federation.invite_handler(request);
            auto const sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the invite is accepted as a signed event and appears in rooms.invite")
            {
                REQUIRE(accepted.accepted);
                REQUIRE(accepted.status == 200U);
                REQUIRE(accepted.signed_event_json.find("\"signatures\"") != std::string::npos);
                REQUIRE(has_membership(homeserver.database.persistent_store, request.room_id,
                                       "@bob:example.org", "invite"));
                REQUIRE(sync.response.status == 200U);
                REQUIRE(sync.response.body.find("\"invite\"") != std::string::npos);
                REQUIRE(sync.response.body.find(request.room_id) != std::string::npos);
            }
        }
    }
}

SCENARIO("createRoom invites remote Matrix users through outbound federation",
         "[homeserver][federation][create-room][invite]")
{
    GIVEN("a local user creating a room with a remote invitee")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto client = merovingian::http::OutboundClient{};
        auto worker = make_dispatch_worker(client);
        homeserver.dispatch_worker.reset(worker.get());
        std::ignore = worker.release();
        auto const summary_before = homeserver.dispatch_worker->summary();

        WHEN("the createRoom body contains a remote invite")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token,
                          R"({"invite":["@bob:remote.example.org"]})"});

            THEN("the invite membership is persisted and an outbound invite transaction is queued")
            {
                REQUIRE(room.response.status == 200U);
                auto const id = room_id(room.response.body);
                REQUIRE(has_membership(homeserver.database.persistent_store, id,
                                       "@bob:remote.example.org", "invite"));
                auto const summary_after = homeserver.dispatch_worker->summary();
                REQUIRE(summary_after.enqueued > summary_before.enqueued);
            }
        }

        homeserver.dispatch_worker->request_shutdown();
        homeserver.dispatch_worker->join();
    }
}
