// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            PUSH GATEWAY DELIVERY — END-TO-END INTEGRATION TESTS         |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 §push-notifications               |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications |
// |  Spec: Matrix Push Gateway API v1.19                                    |
// |  URL:  ../../docs/matrix-v1.19-spec/push-gateway-api.md                 |
// |                                                                         |
// |  Drives a real message send through the full pipeline — push rule       |
// |  evaluation, PushGatewayClient, and a real local TLS mock gateway —     |
// |  via the test_forced_push_gateway_resolution seam (mirrors             |
// |  test_identity_service_flow.cpp's test_forced_identity_resolution       |
// |  precedent). Proves: delivery is fully gated on push.enabled; a         |
// |  notify-worthy message reaches the gateway with the right fields; a     |
// |  rejected pushkey is deleted; and an unreachable gateway never blocks   |
// |  or fails the send that triggered it (delivery runs off the request     |
// |  path via HomeserverRuntime::orphan_futures_ — see room_service.cpp's   |
// |  dispatch_push_deliveries).                                             |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/push/push_gateway_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto push_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    // push.enabled defaults to false; scenarios that need delivery flip it on
    // explicitly against started.runtime.homeserver.config.
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                      std::string const& localpart) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login_body = std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} +
                            localpart + R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart +
                            R"(_DEV"})";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// Creates a private_chat room inviting bob and has bob join it. Returns the
// room ID. A 2-member room with a plain m.room.message event reliably fires
// the server-default `.m.rule.message` underride rule (notify:true,
// unconditional on event type) regardless of member-count-scoped rules.
[[nodiscard]] auto room_with_alice_and_bob(merovingian::homeserver::ClientServerRuntime& runtime,
                                           std::string const& alice, std::string const& bob) -> std::string
{
    auto const create = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"private_chat","invite":["@bob:example.org"]})"});
    REQUIRE(create.response.status == 200U);
    auto const create_body = parse_object(create.response.body);
    auto const* room_id = string_member(create_body, "room_id");
    REQUIRE(room_id != nullptr);
    auto const join = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/join", bob, "{}"});
    REQUIRE(join.response.status == 200U);
    return *room_id;
}

// Registers an http pusher for `token` pointing at `url`. Returns the
// pushkey used, so callers can assert on it later.
auto register_http_pusher(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                          std::string const& app_id, std::string const& pushkey, std::string const& url) -> void
{
    auto const body = std::string{R"({"app_id":")"} + app_id + R"(","pushkey":")" + pushkey +
                      R"(","kind":"http","app_display_name":"Integration App",)" +
                      R"("device_display_name":"Integration Device","lang":"en","data":{"url":")" + url + R"("}})";
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/pushers/set", token, body});
    REQUIRE(response.response.status == 200U);
}

// PUT /rooms/{roomId}/send/m.room.message/{txnId} — a plain text message.
[[nodiscard]] auto send_text_message(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                     std::string const& room_id, std::string const& txn_id, std::string const& body)
    -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn_id, token,
                  R"({"msgtype":"m.text","body":")" + body + R"("})"});
}

// Deterministic wait: blocks on every future queued in orphan_futures_ (the
// same mechanism join_room's background member-fill task uses) instead of
// sleeping. Waiting does not consume/invalidate a std::future.
//
// The mutex is held only long enough to move the futures out of
// orphan_futures_, mirroring HomeserverRuntime::~HomeserverRuntime(); it must
// never be held across the blocking wait() below. A push-delivery task's
// final action (decrementing push_delivery_in_flight_) does not need this
// mutex, but holding it across the wait would still needlessly block a
// concurrent dispatch_push_deliveries call trying to reap or park a future.
auto wait_for_background_tasks(merovingian::homeserver::HomeserverRuntime& runtime) -> void
{
    auto drained = std::vector<std::future<void>>{};
    {
        auto const lock = std::lock_guard{runtime.orphan_futures_mutex_};
        drained = std::move(runtime.orphan_futures_);
    }
    for (auto& future : drained)
    {
        if (future.valid())
        {
            future.wait();
        }
    }
    // Merge back rather than overwrite: nothing else runs concurrently with
    // wait_for_background_tasks() in these tests, but appending instead of
    // reassigning means a future dispatch_push_deliveries call parking a new
    // entry during the wait window can never be clobbered.
    {
        auto const lock = std::lock_guard{runtime.orphan_futures_mutex_};
        for (auto& future : drained)
        {
            runtime.orphan_futures_.push_back(std::move(future));
        }
    }
}

[[nodiscard]] auto pusher_count(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::size_t
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/pushers", token, {}});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* pushers = object_member_as_array(body, "pushers");
    REQUIRE(pushers != nullptr);
    return pushers->size();
}

// Creates a private_chat room with only alice as a member — deliberately
// does NOT invite bob, so the room's membership state (and LocalRoom::members)
// never includes him until the WHEN clause invites him. Returns the room ID.
[[nodiscard]] auto room_with_alice_only(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& alice)
    -> std::string
{
    auto const create = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"private_chat"})"});
    REQUIRE(create.response.status == 200U);
    auto const create_body = parse_object(create.response.body);
    auto const* room_id = string_member(create_body, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

// POST /rooms/{roomId}/invite — invites `user_id` (a full mxid) into the room.
// Named _via_http to avoid any ambiguity with merovingian::homeserver::invite_user
// (the room_service.cpp entry point this HTTP call ultimately dispatches to).
[[nodiscard]] auto invite_user_via_http(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                        std::string const& room_id, std::string const& user_id)
    -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", token, R"({"user_id":")" + user_id + R"("})"});
}

} // namespace

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications
//
// Merovingian-specific gate (docs/todos/capability-gaps.md): push.enabled
// defaults to false so merging delivery cannot cause an existing deployment
// to start sending gateway traffic on upgrade. This proves the gate is
// load-bearing at the room_service.cpp call site, not just inside
// PushGatewayClient::notify().
SCENARIO("push delivery is never attempted while push.enabled is false", "[integration][push]")
{
    GIVEN("alice and bob in a room, bob has an http pusher, and push delivery is disabled (the default)")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        REQUIRE_FALSE(started.runtime.homeserver.config.server().push.enabled);

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);
        register_http_pusher(started.runtime, bob, "org.matrix.integration", "bob-pushkey-disabled",
                             "https://push.disabled.test/_matrix/push/v1/notify");

        WHEN("alice sends a message")
        {
            auto const send = send_text_message(started.runtime, alice, room_id, "txn-disabled", "hello bob");

            THEN("the send succeeds and no background push task was ever queued")
            {
                REQUIRE(send.response.status == 200U);
                auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                REQUIRE(started.runtime.homeserver.orphan_futures_.empty());
            }
        }
    }
}

// Spec: Matrix Push Gateway API v1.19, POST /_matrix/push/v1/notify
// URL: ../../docs/matrix-v1.19-spec/push-gateway-api.md#post_matrixpushv1notify
//
// Spec MUST: the homeserver "include[s] all of the event-related fields in
// the /notify request" for a non-event_id_only pusher. This proves the
// message send succeeds immediately (delivery is async) and that the
// dispatched notification, once the background task drains, reaches the
// mock gateway with the expected event_id/room_id/sender/type.
SCENARIO("an enabled gateway receives a notify request for a message that matches a push rule", "[integration][push]")
{
    GIVEN("push delivery enabled, alice and bob in a room, and bob's pusher pointed at a real mock gateway")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        auto const gateway_host = std::string{"push.localhost.test"};
        auto cert = merovingian::tests::tls_mock::write_test_tls_certificate(gateway_host);
        auto tls_ctx = merovingian::homeserver::make_tls_server_context(cert.certificate_file, cert.private_key_file);
        REQUIRE(tls_ctx.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        auto const gateway_url = "https://" + gateway_host + ":" + std::to_string(port) + "/_matrix/push/v1/notify";

        started.runtime.homeserver.test_forced_push_gateway_resolution[gateway_host] =
            merovingian::push::TestForcedPushGatewayResolution{{"127.0.0.1"}, cert.certificate_pem};

        auto const pushkey = std::string{"bob-pushkey-notify"};
        register_http_pusher(started.runtime, bob, "org.matrix.integration", pushkey, gateway_url);

        auto captured_request = std::string{};
        auto const notify_response = merovingian::tests::tls_mock::json_http_response("200 OK", R"({"rejected":[]})");
        auto server_thread = std::thread{[&] {
            merovingian::tests::tls_mock::run_one_shot_tls_server(acceptor, *tls_ctx.context, notify_response,
                                                                  &captured_request);
        }};
        auto const server_join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("alice sends a message that matches the default .m.rule.message rule")
        {
            auto const send = send_text_message(started.runtime, alice, room_id, "txn-notify", "hello bob");
            REQUIRE(send.response.status == 200U);
            auto const send_body = parse_object(send.response.body);
            auto const* event_id = string_member(send_body, "event_id");
            REQUIRE(event_id != nullptr);

            wait_for_background_tasks(started.runtime.homeserver);
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("the mock gateway received exactly one notify request naming bob's pushkey and the sent event")
            {
                REQUIRE_FALSE(captured_request.empty());
                REQUIRE(captured_request.find(pushkey) != std::string::npos);
                REQUIRE(captured_request.find(*event_id) != std::string::npos);
                REQUIRE(captured_request.find(room_id) != std::string::npos);
                REQUIRE(captured_request.find("\"sender\":\"@alice:example.org\"") != std::string::npos);
                REQUIRE(captured_request.find("\"type\":\"m.room.message\"") != std::string::npos);
            }

            THEN("bob's pusher is still registered (the gateway did not reject it)")
            {
                REQUIRE(pusher_count(started.runtime, bob) == 1U);
            }
        }
    }
}

// Spec: Matrix Push Gateway API v1.19, POST /_matrix/push/v1/notify — 200 response
// URL: ../../docs/matrix-v1.19-spec/push-gateway-api.md#post_matrixpushv1notify
//
// Spec MUST: "Homeservers must cease sending notification requests for these
// pushkeys and remove the associated pushers."
SCENARIO("a pushkey the gateway rejects is removed from the recipient's pushers", "[integration][push]")
{
    GIVEN("push delivery enabled, alice and bob in a room, and a mock gateway that rejects bob's pushkey")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        auto const gateway_host = std::string{"push-reject.localhost.test"};
        auto cert = merovingian::tests::tls_mock::write_test_tls_certificate(gateway_host);
        auto tls_ctx = merovingian::homeserver::make_tls_server_context(cert.certificate_file, cert.private_key_file);
        REQUIRE(tls_ctx.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        auto const gateway_url = "https://" + gateway_host + ":" + std::to_string(port) + "/_matrix/push/v1/notify";

        started.runtime.homeserver.test_forced_push_gateway_resolution[gateway_host] =
            merovingian::push::TestForcedPushGatewayResolution{{"127.0.0.1"}, cert.certificate_pem};

        auto const pushkey = std::string{"bob-pushkey-rejected"};
        register_http_pusher(started.runtime, bob, "org.matrix.integration", pushkey, gateway_url);
        REQUIRE(pusher_count(started.runtime, bob) == 1U);

        auto const notify_response =
            merovingian::tests::tls_mock::json_http_response("200 OK", R"({"rejected":[")" + pushkey + R"("]})");
        auto server_thread = std::thread{[&] {
            merovingian::tests::tls_mock::run_one_shot_tls_server(acceptor, *tls_ctx.context, notify_response);
        }};
        auto const server_join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("alice sends a message and the background delivery drains")
        {
            auto const send = send_text_message(started.runtime, alice, room_id, "txn-reject", "hello bob");
            REQUIRE(send.response.status == 200U);
            wait_for_background_tasks(started.runtime.homeserver);
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("bob's rejected pusher was deleted")
            {
                REQUIRE(pusher_count(started.runtime, bob) == 0U);
            }
        }
    }
}

// This is the core resilience guarantee behind the delivery design: gateway
// I/O runs entirely off the request path (see room_service.cpp's
// dispatch_push_deliveries), so a slow, hostile, or unreachable gateway
// cannot block or fail the message send that triggered it.
SCENARIO("message sending succeeds even when the recipient's push gateway is unreachable", "[integration][push]")
{
    GIVEN("push delivery enabled, alice and bob in a room, and bob's pusher pointed at a closed local port")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        // Reserve a loopback port, then let the acceptor close before any
        // client connects — the port refuses connections, standing in for an
        // unreachable gateway without depending on external network access.
        auto closed_port = std::uint16_t{0U};
        {
            auto reservation = merovingian::net::TcpAcceptor{};
            REQUIRE(reservation.bind("127.0.0.1", 0U).ok);
            closed_port = reservation.bound_port();
            REQUIRE(closed_port > 0U);
        }
        auto const gateway_host = std::string{"push-unreachable.localhost.test"};
        auto const gateway_url =
            "https://" + gateway_host + ":" + std::to_string(closed_port) + "/_matrix/push/v1/notify";
        started.runtime.homeserver.test_forced_push_gateway_resolution[gateway_host] =
            merovingian::push::TestForcedPushGatewayResolution{{"127.0.0.1"}, {}};
        register_http_pusher(started.runtime, bob, "org.matrix.integration", "bob-pushkey-unreachable", gateway_url);

        WHEN("alice sends a message")
        {
            auto const send = send_text_message(started.runtime, alice, room_id, "txn-unreachable", "hello bob");

            THEN("the send still succeeds, and the background delivery attempt completes without hanging")
            {
                REQUIRE(send.response.status == 200U);
                wait_for_background_tasks(started.runtime.homeserver);

                // The pusher is untouched: an unreachable gateway is a transport
                // failure, not a `rejected` pushkey, so it must not be deleted.
                REQUIRE(pusher_count(started.runtime, bob) == 1U);
            }
        }
    }
}

// This is the resource-exhaustion fix behind dispatch_push_deliveries (0.11.11
// gap audit): without reaping, HomeserverRuntime::orphan_futures_ grows by one
// entry per notify-worthy event for the life of the runtime. See
// reap_completed_futures (runtime.hpp/.cpp), shared with join_room's
// make_join race reaping so the reap-before-park policy is defined once.
SCENARIO("a completed push-delivery task is reaped before the next one is parked", "[integration][push]")
{
    GIVEN("push delivery enabled, alice and bob in a room, and bob's pusher pointed at a real mock gateway")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        auto const gateway_host = std::string{"push-reap.localhost.test"};
        auto cert = merovingian::tests::tls_mock::write_test_tls_certificate(gateway_host);
        auto tls_ctx = merovingian::homeserver::make_tls_server_context(cert.certificate_file, cert.private_key_file);
        REQUIRE(tls_ctx.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        auto const gateway_url = "https://" + gateway_host + ":" + std::to_string(port) + "/_matrix/push/v1/notify";

        started.runtime.homeserver.test_forced_push_gateway_resolution[gateway_host] =
            merovingian::push::TestForcedPushGatewayResolution{{"127.0.0.1"}, cert.certificate_pem};

        register_http_pusher(started.runtime, bob, "org.matrix.integration", "bob-pushkey-reap", gateway_url);

        // Two accepts, one per message sent below.
        auto const ok_response = merovingian::tests::tls_mock::json_http_response("200 OK", R"({"rejected":[]})");
        auto const path_responses = std::vector<std::pair<std::string, std::string>>{
            {"/_matrix/push/v1/notify", ok_response},
            {"/_matrix/push/v1/notify", ok_response},
        };
        auto server_thread = std::thread{[&] {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, *tls_ctx.context, path_responses);
        }};
        auto const server_join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("alice sends a first message, its delivery drains, and alice sends a second message")
        {
            auto const first_send = send_text_message(started.runtime, alice, room_id, "txn-reap-1", "first");
            REQUIRE(first_send.response.status == 200U);
            wait_for_background_tasks(started.runtime.homeserver);

            THEN("the first, now-completed task is still parked — nothing reaps it until the next dispatch")
            {
                auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                REQUIRE(started.runtime.homeserver.orphan_futures_.size() == 1U);
            }

            auto const second_send = send_text_message(started.runtime, alice, room_id, "txn-reap-2", "second");
            REQUIRE(second_send.response.status == 200U);

            THEN("the completed first task was reaped before the second was parked — the vector does not grow")
            {
                auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                REQUIRE(started.runtime.homeserver.orphan_futures_.size() == 1U);
            }

            wait_for_background_tasks(started.runtime.homeserver);
            if (server_thread.joinable())
            {
                server_thread.join();
            }
        }
    }
}

// The other half of the 0.11.11 resource-exhaustion fix: bounding thread
// creation itself. Directly saturates HomeserverRuntime::push_delivery_
// in_flight_ (guarded by orphan_futures_mutex_, same as reap_completed_
// futures above) rather than spawning the real cap's worth of concurrent
// deliveries — see room_service.cpp's k_max_in_flight_push_deliveries.
SCENARIO("exceeding the in-flight push-delivery cap drops the notification instead of spawning it",
         "[integration][push]")
{
    GIVEN("push delivery enabled, alice and bob in a room, bob has a pusher, and the in-flight counter is saturated")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        // A pusher URL that must never actually be contacted by this test: if
        // dispatch_push_deliveries's cap check failed to drop the delivery, a
        // background task would try to reach this host. No mock server or
        // forced resolution is set up for it — the assertions below catch
        // whether a task was ever spawned at all, not how a hypothetical
        // connection attempt would resolve.
        register_http_pusher(started.runtime, bob, "org.matrix.integration", "bob-pushkey-cap",
                             "https://push-cap-must-not-be-contacted.invalid/_matrix/push/v1/notify");

        // Simulate the cap already being reached by every existing delivery
        // task, without spawning (and waiting out) the real cap's worth of
        // concurrent tasks. Any value at or above the real cap exercises the
        // same drop-not-spawn branch.
        {
            auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
            started.runtime.homeserver.push_delivery_in_flight_ = 1'000'000U;
        }

        WHEN("alice sends a message that would otherwise notify bob")
        {
            auto const send = send_text_message(started.runtime, alice, room_id, "txn-cap", "hello bob");

            THEN("the send still succeeds and no background task was queued for the dropped delivery")
            {
                REQUIRE(send.response.status == 200U);
                auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                REQUIRE(started.runtime.homeserver.orphan_futures_.empty());
            }

            THEN("the saturated counter is untouched by the dropped delivery — it was never incremented")
            {
                auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                REQUIRE(started.runtime.homeserver.push_delivery_in_flight_ == 1'000'000U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 §push-notifications, default rule
// `.m.rule.invite_for_me` — "notify" for an m.room.member event whose
// content.membership is "invite" and state_key names the receiving user.
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications
//
// 0.11.11 gap audit: membership-mutating endpoints (invite/join/leave/kick/
// ban, and the 3PID invite) previously never reached the delivery pipeline
// at all, so this default, enabled-by-default rule — whose entire purpose is
// to notify a user they were invited — could never actually fire. Proves the
// fix: bob is registered with a pusher but is NOT a member of the room (so
// he is absent from LocalRoom::members) when alice invites him; the
// notification must still reach his gateway. See room_service.cpp's
// persist_membership_transition and dispatch_membership_push_notification.
SCENARIO("inviting a user delivers a notification to the invitee's pusher", "[integration][push]")
{
    GIVEN("push delivery enabled, alice has a room, and bob (not a member of it) has a pusher")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_only(started.runtime, alice);

        auto const gateway_host = std::string{"push-invite.localhost.test"};
        auto cert = merovingian::tests::tls_mock::write_test_tls_certificate(gateway_host);
        auto tls_ctx = merovingian::homeserver::make_tls_server_context(cert.certificate_file, cert.private_key_file);
        REQUIRE(tls_ctx.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        auto const gateway_url = "https://" + gateway_host + ":" + std::to_string(port) + "/_matrix/push/v1/notify";

        started.runtime.homeserver.test_forced_push_gateway_resolution[gateway_host] =
            merovingian::push::TestForcedPushGatewayResolution{{"127.0.0.1"}, cert.certificate_pem};

        auto const pushkey = std::string{"bob-pushkey-invite"};
        register_http_pusher(started.runtime, bob, "org.matrix.integration", pushkey, gateway_url);

        auto captured_request = std::string{};
        auto const notify_response = merovingian::tests::tls_mock::json_http_response("200 OK", R"({"rejected":[]})");
        auto server_thread = std::thread{[&] {
            merovingian::tests::tls_mock::run_one_shot_tls_server(acceptor, *tls_ctx.context, notify_response,
                                                                  &captured_request);
        }};
        auto const server_join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("alice invites bob")
        {
            auto const invite = invite_user_via_http(started.runtime, alice, room_id, "@bob:example.org");
            REQUIRE(invite.response.status == 200U);

            wait_for_background_tasks(started.runtime.homeserver);
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("bob's pusher received a notify request naming him as the invite target")
            {
                REQUIRE_FALSE(captured_request.empty());
                REQUIRE(captured_request.find(pushkey) != std::string::npos);
                REQUIRE(captured_request.find(room_id) != std::string::npos);
                REQUIRE(captured_request.find("\"type\":\"m.room.member\"") != std::string::npos);
                REQUIRE(captured_request.find("\"sender\":\"@alice:example.org\"") != std::string::npos);
                REQUIRE(captured_request.find("\"user_is_target\":true") != std::string::npos);
            }
        }
    }
}

// Mirrors "message sending succeeds even when the recipient's push gateway is
// unreachable" above, but for the invite path specifically: proves that
// dispatch_membership_push_notification's background delivery cannot fail or
// block the /invite request itself, matching the same off-request-path
// guarantee send_event already had.
SCENARIO("inviting a user succeeds even when the invitee's push gateway is unreachable", "[integration][push]")
{
    GIVEN("push delivery enabled, alice has a room, and bob has a pusher pointed at a closed local port")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_only(started.runtime, alice);

        // Reserve a loopback port, then let the acceptor close before any
        // client connects — the port refuses connections, standing in for an
        // unreachable gateway without depending on external network access.
        auto closed_port = std::uint16_t{0U};
        {
            auto reservation = merovingian::net::TcpAcceptor{};
            REQUIRE(reservation.bind("127.0.0.1", 0U).ok);
            closed_port = reservation.bound_port();
            REQUIRE(closed_port > 0U);
        }
        auto const gateway_host = std::string{"push-invite-unreachable.localhost.test"};
        auto const gateway_url =
            "https://" + gateway_host + ":" + std::to_string(closed_port) + "/_matrix/push/v1/notify";
        started.runtime.homeserver.test_forced_push_gateway_resolution[gateway_host] =
            merovingian::push::TestForcedPushGatewayResolution{{"127.0.0.1"}, {}};
        register_http_pusher(started.runtime, bob, "org.matrix.integration", "bob-pushkey-invite-unreachable",
                             gateway_url);

        WHEN("alice invites bob")
        {
            auto const invite = invite_user_via_http(started.runtime, alice, room_id, "@bob:example.org");

            THEN("the invite still succeeds, and the background delivery attempt completes without hanging")
            {
                REQUIRE(invite.response.status == 200U);
                wait_for_background_tasks(started.runtime.homeserver);

                // The pusher is untouched: an unreachable gateway is a transport
                // failure, not a `rejected` pushkey, so it must not be deleted.
                REQUIRE(pusher_count(started.runtime, bob) == 1U);
            }
        }
    }
}
