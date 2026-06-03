// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/http/outbound_client.hpp"

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
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto make_dispatch_worker(merovingian::http::OutboundClient& client,
                                        merovingian::database::PersistentStore* persistent_store = nullptr)
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
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
    };
    auto sleep_fn = [](std::chrono::milliseconds) {
    };
    return std::make_unique<merovingian::federation::DispatchWorker>(
        std::move(config), client, std::move(resolver), std::move(clock), std::move(sleep_fn), persistent_store);
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
    return room != database.rooms.end() && std::ranges::any_of(room->members, [&](std::string const& member) {
               return member == user_id;
           });
}

[[nodiscard]] auto first_invite_transaction_body(merovingian::database::PersistentStore const& store) -> std::string
{
    auto const transaction = std::ranges::find_if(
        store.federation_transactions, [](merovingian::database::PersistentFederationTransaction const& current) {
            return current.target.find("/_matrix/federation/v2/invite/") != std::string::npos;
        });
    REQUIRE(transaction != store.federation_transactions.end());
    return transaction->body;
}

[[nodiscard]] auto direct_to_device_transactions(merovingian::database::PersistentStore const& store)
    -> std::vector<merovingian::database::PersistentFederationTransaction const*>
{
    auto transactions = std::vector<merovingian::database::PersistentFederationTransaction const*>{};
    for (auto const& transaction : store.federation_transactions)
    {
        if (transaction.body.find(R"("edu_type":"m.direct_to_device")") != std::string::npos)
        {
            transactions.push_back(&transaction);
        }
    }
    return transactions;
}

[[nodiscard]] auto direct_to_device_message_id(std::string_view transaction_body) -> std::string
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(std::string{transaction_body});
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(root != nullptr);

    auto const edus_it = std::ranges::find_if(*root, [](merovingian::canonicaljson::ObjectMember const& member) {
        return member.key == "edus";
    });
    REQUIRE(edus_it != root->end());
    REQUIRE(edus_it->value != nullptr);
    auto const* edus = std::get_if<merovingian::canonicaljson::Array>(&edus_it->value->storage());
    REQUIRE(edus != nullptr);
    REQUIRE(edus->size() == 1U);

    auto const* edu = std::get_if<merovingian::canonicaljson::Object>(&(*edus)[0].storage());
    REQUIRE(edu != nullptr);
    auto const content_it = std::ranges::find_if(*edu, [](merovingian::canonicaljson::ObjectMember const& member) {
        return member.key == "content";
    });
    REQUIRE(content_it != edu->end());
    REQUIRE(content_it->value != nullptr);
    auto const* content = std::get_if<merovingian::canonicaljson::Object>(&content_it->value->storage());
    REQUIRE(content != nullptr);

    auto const message_id_it =
        std::ranges::find_if(*content, [](merovingian::canonicaljson::ObjectMember const& member) {
            return member.key == "message_id";
        });
    REQUIRE(message_id_it != content->end());
    REQUIRE(message_id_it->value != nullptr);
    auto const* message_id = std::get_if<std::string>(&message_id_it->value->storage());
    REQUIRE(message_id != nullptr);
    return *message_id;
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
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
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
        auto local_room = std::ranges::find_if(homeserver.database.rooms, [&id](auto const& r) {
            return r.room_id == id;
        });
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

SCENARIO("Inbound PDU sink assigns stream ordering and notifies sync", "[homeserver][outbound-dispatch][inbound-sync]")
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

SCENARIO("Remote sendToDevice federation dispatch keeps durable unique transaction IDs across counter resets",
         "[homeserver][outbound-dispatch][send-to-device][regression]")
{
    GIVEN("a logged-in local sender with a persistent dispatch worker")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto client = merovingian::http::OutboundClient{};
        auto worker = make_dispatch_worker(client, &homeserver.database.persistent_store);
        homeserver.dispatch_worker.reset(worker.get());
        std::ignore = worker.release();

        WHEN("two remote sendToDevice requests are issued across a restarted local counter")
        {
            auto const first_counter = homeserver.database.next_session_id;
            auto const first_send = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/sendToDevice/m.room.encrypted/client-txn-1", token,
                 R"({"messages":{"@bob:remote.example.org":{"REMOTE1":{"algorithm":"m.olm.v1.curve25519-aes-sha2","ciphertext":{"curve25519:REMOTE1":{"body":"cipher-1","type":0}}}}}})"});
            REQUIRE(first_send.response.status == 200U);

            auto first_transactions = direct_to_device_transactions(homeserver.database.persistent_store);
            REQUIRE(first_transactions.size() == 1U);
            auto const first_txn_id = first_transactions.front()->transaction_id;
            REQUIRE_FALSE(first_txn_id.empty());
            REQUIRE(direct_to_device_message_id(first_transactions.front()->body) == "client-txn-1");

            homeserver.database.next_session_id = first_counter;

            auto const second_send = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/sendToDevice/m.room.encrypted/client-txn-2", token,
                 R"({"messages":{"@bob:remote.example.org":{"REMOTE1":{"algorithm":"m.olm.v1.curve25519-aes-sha2","ciphertext":{"curve25519:REMOTE1":{"body":"cipher-2","type":0}}}}}})"});
            REQUIRE(second_send.response.status == 200U);

            THEN("both outbound federation transactions remain durable and preserve the client transaction IDs")
            {
                auto direct_to_device = direct_to_device_transactions(homeserver.database.persistent_store);
                REQUIRE(direct_to_device.size() == 2U);

                auto transaction_ids = std::vector<std::string>{};
                auto message_ids = std::vector<std::string>{};
                for (auto const* transaction : direct_to_device)
                {
                    transaction_ids.push_back(transaction->transaction_id);
                    message_ids.push_back(direct_to_device_message_id(transaction->body));
                }

                std::ranges::sort(transaction_ids);
                auto const unique_transaction_ids = std::ranges::unique(transaction_ids);
                REQUIRE(unique_transaction_ids.begin() == transaction_ids.end());
                REQUIRE(std::ranges::find(message_ids, "client-txn-1") != message_ids.end());
                REQUIRE(std::ranges::find(message_ids, "client-txn-2") != message_ids.end());
            }
        }

        homeserver.dispatch_worker->request_shutdown();
        homeserver.dispatch_worker->join();
    }
}

SCENARIO("send_event without dispatch worker persists events locally", "[homeserver][outbound-dispatch][no-worker]")
{
    GIVEN("a homeserver runtime without a dispatch worker")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;
        REQUIRE(homeserver.dispatch_worker == nullptr);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
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

SCENARIO("send_event does not enqueue transactions for local-only rooms", "[homeserver][outbound-dispatch][local-only]")
{
    GIVEN("a homeserver runtime with a dispatch worker and a room with only local members")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
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
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
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
                    runtime,
                    {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
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
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("bob", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
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
            request.invite_room_state_json = {
                R"({"content":{"creator":"@alice:remote.example.org","room_version":"12"},"sender":"@alice:remote.example.org","state_key":"","type":"m.room.create"})",
                R"({"content":{"name":"Remote DM"},"sender":"@alice:remote.example.org","state_key":"","type":"m.room.name"})",
                R"({"content":{"displayname":"Alice Remote","membership":"join"},"sender":"@alice:remote.example.org","state_key":"@alice:remote.example.org","type":"m.room.member"})",
            };

            auto const accepted = homeserver.federation.invite_handler(request);
            auto const sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the invite is accepted as a signed event and sync exposes the stripped invite state")
            {
                REQUIRE(accepted.accepted);
                REQUIRE(accepted.status == 200U);
                REQUIRE(accepted.signed_event_json.find("\"signatures\"") != std::string::npos);
                REQUIRE(has_membership(homeserver.database.persistent_store, request.room_id, "@bob:example.org",
                                       "invite"));
                REQUIRE(sync.response.status == 200U);
                REQUIRE(sync.response.body.find("\"invite\"") != std::string::npos);
                REQUIRE(sync.response.body.find(request.room_id) != std::string::npos);
                REQUIRE(sync.response.body.find("\"m.room.name\"") != std::string::npos);
                REQUIRE(sync.response.body.find("Remote DM") != std::string::npos);
                REQUIRE(sync.response.body.find("@alice:remote.example.org") != std::string::npos);
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
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto client = merovingian::http::OutboundClient{};
        auto worker = make_dispatch_worker(client, &homeserver.database.persistent_store);
        homeserver.dispatch_worker.reset(worker.get());
        std::ignore = worker.release();
        auto const summary_before = homeserver.dispatch_worker->summary();

        WHEN("the createRoom body contains a remote invite")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"invite":["@bob:remote.example.org"]})"});

            THEN("the invite membership is persisted and an outbound invite transaction is queued")
            {
                REQUIRE(room.response.status == 200U);
                auto const id = room_id(room.response.body);
                REQUIRE(has_membership(homeserver.database.persistent_store, id, "@bob:remote.example.org", "invite"));
                auto const summary_after = homeserver.dispatch_worker->summary();
                REQUIRE(summary_after.enqueued > summary_before.enqueued);
            }
        }

        homeserver.dispatch_worker->request_shutdown();
        homeserver.dispatch_worker->join();
    }
}

SCENARIO("createRoom outbound invites carry the created room's version",
         "[homeserver][federation][create-room][invite][room-version]")
{
    GIVEN("a local user creating a room with a remote invitee and a requested room version")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto client = merovingian::http::OutboundClient{};
        auto worker = make_dispatch_worker(client, &homeserver.database.persistent_store);
        homeserver.dispatch_worker.reset(worker.get());
        std::ignore = worker.release();

        WHEN("createRoom targets room version 11")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token,
                          R"({"invite":["@bob:remote.example.org"],"room_version":"11"})"});

            THEN("the queued outbound invite body advertises that same room version")
            {
                REQUIRE(room.response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(
                    first_invite_transaction_body(homeserver.database.persistent_store));
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const room_version = std::ranges::find_if(*root, [](auto const& member) {
                    return member.key == "room_version";
                });
                REQUIRE(room_version != root->end());
                auto const* version_text = std::get_if<std::string>(&room_version->value->storage());
                REQUIRE(version_text != nullptr);
                REQUIRE(*version_text == "11");
            }
        }

        homeserver.dispatch_worker->request_shutdown();
        homeserver.dispatch_worker->join();
    }
}
