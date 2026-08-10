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
auto wait_for_background_tasks(merovingian::homeserver::HomeserverRuntime& runtime) -> void
{
    auto const lock = std::lock_guard{runtime.orphan_futures_mutex_};
    for (auto& future : runtime.orphan_futures_)
    {
        if (future.valid())
        {
            future.wait();
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
