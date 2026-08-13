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
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/push/push_gateway_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
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

// PUT the caller's own m.ignored_user_list account-data event. Spec:
// docs/matrix-v1.19-spec/client-server-api.md#ignoring-users.
// `percent_encoded_user_id` is the caller's own mxid, percent-encoded for
// the path segment (PUT /user/{userId}/account_data/{type} requires userId
// == the authenticated caller).
auto set_ignored_users(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                       std::string const& percent_encoded_user_id, std::string const& ignored_users_body) -> void
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/user/" + percent_encoded_user_id + "/account_data/m.ignored_user_list",
                  token, ignored_users_body});
    REQUIRE(resp.response.status == 200U);
}

// GET /_matrix/client/v3/notifications, parsed into an object.
[[nodiscard]] auto get_notifications(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> merovingian::canonicaljson::Object
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/notifications", token, {}});
    REQUIRE(response.response.status == 200U);
    return parse_object(response.response.body);
}

// Whether `notifications` contains an entry whose own `event.event_id` field
// equals `event_id`. Parses each element's `event` object rather than
// substring-searching the serialized response, so a value that merely
// appears elsewhere (e.g. quoted inside another event's prev_events) cannot
// produce a false positive.
[[nodiscard]] auto notifications_contain_event(merovingian::canonicaljson::Array const& notifications,
                                               std::string const& event_id) -> bool
{
    for (auto const& entry : notifications)
    {
        auto const* entry_object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        if (entry_object == nullptr)
        {
            continue;
        }
        auto const* event_object = object_member_as_object(*entry_object, "event");
        auto const* found_event_id = event_object == nullptr ? nullptr : string_member(*event_object, "event_id");
        if (found_event_id != nullptr && *found_event_id == event_id)
        {
            return true;
        }
    }
    return false;
}

// Whether the notifications-history entry for `event_id` carries a
// `{"set_tweak":"highlight","value":true}` action — i.e. whether push rule
// evaluation actually chose the highlight tweak for that event. Parses each
// entry's own `actions` array rather than substring-searching the response,
// per this file's structural-assertion discipline (see
// notifications_contain_event above).
[[nodiscard]] auto notification_actions_have_highlight(merovingian::canonicaljson::Array const& notifications,
                                                       std::string const& event_id) -> bool
{
    for (auto const& entry : notifications)
    {
        auto const* entry_object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        if (entry_object == nullptr)
        {
            continue;
        }
        auto const* event_object = object_member_as_object(*entry_object, "event");
        auto const* found_event_id = event_object == nullptr ? nullptr : string_member(*event_object, "event_id");
        if (found_event_id == nullptr || *found_event_id != event_id)
        {
            continue;
        }
        auto const* actions_array = object_member_as_array(*entry_object, "actions");
        if (actions_array == nullptr)
        {
            return false;
        }
        for (auto const& action : *actions_array)
        {
            auto const* action_object = std::get_if<merovingian::canonicaljson::Object>(&action.storage());
            if (action_object == nullptr)
            {
                continue;
            }
            auto const* set_tweak = string_member(*action_object, "set_tweak");
            if (set_tweak == nullptr || *set_tweak != "highlight")
            {
                continue;
            }
            auto const* highlight_value = bool_member(*action_object, "value");
            return highlight_value != nullptr && *highlight_value;
        }
        return false;
    }
    return false;
}

// A federation-enabled variant of push_test_config() — used by the
// federation-delivery scenarios below, which need security.federation.enabled
// so wire_federation_callbacks() actually wires runtime.federation.pdu_sink
// (see wire_federation_callbacks_impl's early-return guard in
// local_http_router.cpp).
[[nodiscard]] auto push_federation_test_config() -> merovingian::config::Config
{
    auto config = push_test_config();
    config.security().federation.enabled = true;
    return config;
}

// Directly seeds `remote_user` as an already-joined member of `room_id`,
// without driving a real make_join/send_join handshake (out of scope here —
// see test_join_room_flow.cpp for that path). Mirrors the seeding technique
// tests/unit/test_federation_pdu_ingest_concurrency.cpp uses for its
// remote-member fixture: writes LocalRoom::members, the PersistentMembership
// row, and a real (state-key, event) pair so build_pdu_auth_event_map finds a
// sender_member entry when a later PDU from this sender is authorized.
auto seed_remote_member(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& room_id,
                        std::string const& remote_user) -> void
{
    namespace canonicaljson = merovingian::canonicaljson;
    auto& homeserver = runtime.homeserver;
    auto& store = homeserver.database.persistent_store;

    auto room_it =
        std::ranges::find_if(homeserver.database.rooms, [&](merovingian::homeserver::LocalRoom const& candidate) {
            return candidate.room_id == room_id;
        });
    REQUIRE(room_it != homeserver.database.rooms.end());
    room_it->members.push_back(remote_user);
    store.memberships.push_back({room_id, remote_user, "join", 0U});

    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));

    auto event_obj = canonicaljson::Object{};
    event_obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.member"}}));
    event_obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    event_obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{remote_user}));
    event_obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{remote_user}));
    event_obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event_obj.push_back(
        canonicaljson::make_member("origin_server_ts", canonicaljson::Value{static_cast<std::int64_t>(500)}));
    event_obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(2)}));
    event_obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));

    auto const hash = merovingian::events::make_content_hash(canonicaljson::Value{event_obj});
    REQUIRE(hash.error.empty());
    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
    event_obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));

    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{event_obj});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    auto const member_event_id = room_id + ":seeded-remote-member:" + remote_user;
    store.events.push_back({member_event_id, room_id, remote_user, serialized.output, 2U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.member", remote_user, member_event_id});
}

// Builds an already-signed-shaped (content-hash-correct, but not
// Ed25519-signed — ingest_pdu_event/PduSink never re-verify the signature;
// that already happened once upstream at authorize_federation_pdu, see
// local_http_router.cpp's #450 TRUST BOUNDARY comment) m.room.message PDU
// envelope from `sender`, mirroring test_federation_pdu_ingest_concurrency.
// cpp's make_message_pdu. Used to drive the wired federation pdu_sink
// directly, standing in for a real inbound /_matrix/federation/v1/send/{txn}
// transaction (which would additionally need X-Matrix request auth and a
// verifiable Ed25519 event signature — orthogonal to what this file tests).
[[nodiscard]] auto make_federation_message_envelope(std::string const& room_id, std::string const& sender,
                                                    std::string const& body, std::string const& event_id)
    -> merovingian::federation::InboundPduEnvelope
{
    namespace canonicaljson = merovingian::canonicaljson;
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("body", canonicaljson::Value{body}));
    content.push_back(canonicaljson::make_member("msgtype", canonicaljson::Value{std::string{"m.text"}}));

    auto event_obj = canonicaljson::Object{};
    event_obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.message"}}));
    event_obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    event_obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{sender}));
    event_obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event_obj.push_back(
        canonicaljson::make_member("origin_server_ts", canonicaljson::Value{static_cast<std::int64_t>(1000)}));
    event_obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(3)}));
    event_obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));

    auto const hash = merovingian::events::make_content_hash(canonicaljson::Value{event_obj});
    REQUIRE(hash.error.empty());
    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
    event_obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));

    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{event_obj});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    auto env = merovingian::federation::InboundPduEnvelope{};
    env.event_id = event_id;
    env.room_id = room_id;
    env.room_version = "12";
    env.sender = sender;
    env.event_type = "m.room.message";
    env.origin_server_ts = 1000;
    env.depth = 3U;
    env.json = serialized.output;
    return env;
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

// ── Ignoring Users (spec: docs/matrix-v1.19-spec/client-server-api.md
// #ignoring-users) — the most user-visible failure mode of an unenforced
// ignore list: a push notification arriving from someone the user ignored.
// Proven the same way as the "push.enabled false" and "in-flight cap
// exceeded" scenarios above — build_pending_push_deliveries's ignore check
// runs before it ever looks up the recipient's pushers, so a suppressed
// delivery never reaches dispatch_push_deliveries and no background task is
// queued at all. The registered pusher URL is deliberately unreachable
// nonsense: if suppression were not wired in, a background task would try to
// contact it and the test would hang or fail via the orphan_futures_ probe
// below, not silently pass.
SCENARIO("a message from an ignored sender never queues a push notification for the ignoring recipient",
         "[integration][push][ignoring-users]")
{
    GIVEN("push delivery enabled, alice and bob in a room, bob has ignored alice, and bob has an http pusher")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        set_ignored_users(started.runtime, bob, "%40bob%3Aexample.org",
                          R"({"ignored_users":{"@alice:example.org":{}}})");
        register_http_pusher(started.runtime, bob, "org.matrix.integration", "bob-pushkey-ignored-sender",
                             "https://push-ignored-sender-must-not-be-contacted.invalid/_matrix/push/v1/notify");

        WHEN("alice (whom bob ignores) sends a message that would otherwise notify bob")
        {
            auto const send = send_text_message(started.runtime, alice, room_id, "txn-ignored-sender", "hello bob");

            THEN("the send still succeeds and no background push task was ever queued for bob")
            {
                REQUIRE(send.response.status == 200U);
                auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                REQUIRE(started.runtime.homeserver.orphan_futures_.empty());
            }
        }
    }
}

// Spec MUST: "Servers must not send room invites from ignored users to
// clients." — proves the invite path (dispatch_membership_push_notification,
// which also funnels through build_pending_push_deliveries) is covered by
// the same suppression, not just the plain message path above.
SCENARIO("an invite from an ignored sender never queues a push notification for the ignoring invitee",
         "[integration][push][ignoring-users]")
{
    GIVEN("push delivery enabled, alice ignores bob, alice has a pusher, and bob has his own room to invite her into")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const bob_room = room_with_alice_only(started.runtime, bob); // bob-owned, alice not a member yet

        set_ignored_users(started.runtime, alice, "%40alice%3Aexample.org",
                          R"({"ignored_users":{"@bob:example.org":{}}})");
        register_http_pusher(started.runtime, alice, "org.matrix.integration", "alice-pushkey-ignored-invite",
                             "https://push-ignored-invite-must-not-be-contacted.invalid/_matrix/push/v1/notify");

        WHEN("bob invites alice, whom he does not know has ignored him")
        {
            auto const invite = invite_user_via_http(started.runtime, bob, bob_room, "@alice:example.org");

            THEN("the invite still succeeds and no background push task was ever queued for alice")
            {
                REQUIRE(invite.response.status == 200U);
                auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                REQUIRE(started.runtime.homeserver.orphan_futures_.empty());
            }
        }
    }
}

// ── GET /_matrix/client/v3/notifications × Ignoring Users ─────────────────
// Spec (spec: docs/matrix-v1.19-spec/client-server-api.md#ignoring-users):
// an ignored sender's events must not reach the ignoring user through any
// client-facing delivery surface, and GET /notifications is exactly that —
// it is fed by the same build_pending_push_deliveries evaluation the push
// gateway path uses (see room_service.cpp), gated by the same
// trust_safety::is_delivery_suppressed check, so a suppressed event is never
// recorded as a notification in the first place.
SCENARIO("a message from an ignored sender never appears in the ignoring recipient's GET /notifications",
         "[integration][push][ignoring-users]")
{
    GIVEN("alice and bob in a room, and bob has ignored alice")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        // push.enabled deliberately left at its default (false): notification
        // history recording must not depend on it (see the "no pusher, push
        // disabled" scenario below) -- this proves the ignore suppression
        // holds under that same condition.
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        set_ignored_users(started.runtime, bob, "%40bob%3Aexample.org",
                          R"({"ignored_users":{"@alice:example.org":{}}})");

        WHEN("alice (whom bob ignores) sends a message, and someone else (charlie) also messages bob")
        {
            auto const ignored_send = send_text_message(started.runtime, alice, room_id, "txn-notif-ignored", "hi bob");
            REQUIRE(ignored_send.response.status == 200U);
            auto const ignored_body = parse_object(ignored_send.response.body);
            auto const* ignored_event_id = string_member(ignored_body, "event_id");
            REQUIRE(ignored_event_id != nullptr);

            auto const charlie = register_and_login(started.runtime, "charlie");
            // room_with_alice_and_bob creates a private_chat room (join_rule
            // "invite"), so charlie must be invited before he can join it --
            // unlike the ignored sender above, who is already a member.
            auto const charlie_invite = invite_user_via_http(started.runtime, alice, room_id, "@charlie:example.org");
            REQUIRE(charlie_invite.response.status == 200U);
            auto const charlie_join = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", charlie, "{}"});
            REQUIRE(charlie_join.response.status == 200U);
            auto const visible_send =
                send_text_message(started.runtime, charlie, room_id, "txn-notif-visible", "hi from charlie too");
            REQUIRE(visible_send.response.status == 200U);
            auto const visible_body = parse_object(visible_send.response.body);
            auto const* visible_event_id = string_member(visible_body, "event_id");
            REQUIRE(visible_event_id != nullptr);

            THEN("bob's GET /notifications does not contain alice's event but does contain charlie's")
            {
                auto const body = get_notifications(started.runtime, bob);
                auto const* notifications = object_member_as_array(body, "notifications");
                REQUIRE(notifications != nullptr);

                // Structural absence check: alice's event_id must not appear
                // as any entry's own event.event_id (not a substring search
                // over the serialized response).
                REQUIRE_FALSE(notifications_contain_event(*notifications, *ignored_event_id));
                // Positive counterpart: an otherwise-identical notification
                // from a non-ignored sender in the same room does appear, so
                // the absence above is not just an empty-array vacuous pass.
                REQUIRE(notifications_contain_event(*notifications, *visible_event_id));
            }
        }
    }
}

// The core judgement call behind recording notification history in
// build_pending_push_deliveries: recording must not be gated on
// server.push.enabled or on the recipient having a registered pusher --
// only actual Push Gateway delivery is gated on those. A user who never
// configured a pusher, on a server that never turned push.enabled on, must
// still see their notifications when they open the client.
SCENARIO("a notification is recorded even when push.enabled is false and the recipient has no pusher",
         "[integration][push]")
{
    GIVEN("push delivery disabled (the default), alice and bob in a room, and bob has no pusher")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        REQUIRE_FALSE(started.runtime.homeserver.config.server().push.enabled);

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);
        REQUIRE(pusher_count(started.runtime, bob) == 0U);

        WHEN("alice sends a message that matches the default .m.rule.message rule")
        {
            auto const send = send_text_message(started.runtime, alice, room_id, "txn-notif-no-push", "hello bob");
            REQUIRE(send.response.status == 200U);
            auto const send_body = parse_object(send.response.body);
            auto const* event_id = string_member(send_body, "event_id");
            REQUIRE(event_id != nullptr);

            THEN("no background push task was queued, but the notification still appears in GET /notifications")
            {
                {
                    auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                    REQUIRE(started.runtime.homeserver.orphan_futures_.empty());
                }
                auto const body = get_notifications(started.runtime, bob);
                auto const* notifications = object_member_as_array(body, "notifications");
                REQUIRE(notifications != nullptr);
                REQUIRE(notifications_contain_event(*notifications, *event_id));
            }
        }
    }
}

// ── Federation-accepted events reach the push pipeline (0.11.11 gap audit,
// PR #479 review finding P1) ──────────────────────────────────────────────
// Spec: Matrix Server-Server API v1.19 §PDUs; Client-Server API v1.19
// §push-notifications
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#pdus
//       ../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications
//
// Before this fix, push delivery was wired only into send_event() — the
// locally-composed-event path. Events accepted over federation persist
// through ingest_pdu_event() (called from the runtime.federation.pdu_sink
// callback wired by wire_federation_callbacks_impl in local_http_router.cpp)
// and only ever published the sync token, never reaching build_pending_push_
// deliveries/dispatch_push_deliveries. A message from a remote room member —
// the ordinary federated-room case — therefore produced no /notifications
// row and no Push Gateway request for a local recipient. This is the
// regression test for the fix (deliver_federation_push_notifications,
// room_service.cpp, called from the pdu_sink lambda).
SCENARIO("an event accepted via federation from a remote sender delivers a push notification and a "
         "notifications-history row to a local recipient",
         "[integration][push][federation]")
{
    GIVEN("push and federation delivery enabled, bob (local) has a room and a pusher, and alice (remote) is already "
          "a joined member of it")
    {
        auto started = merovingian::homeserver::start_client_server(push_federation_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_only(started.runtime, bob); // bob is the room's only local member
        auto const remote_sender = std::string{"@alice:remote.example.org"};
        seed_remote_member(started.runtime, room_id, remote_sender);

        auto const gateway_host = std::string{"push-federation.localhost.test"};
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

        auto const pushkey = std::string{"bob-pushkey-federation"};
        register_http_pusher(started.runtime, bob, "org.matrix.integration", pushkey, gateway_url);

        merovingian::homeserver::wire_federation_callbacks(started.runtime.homeserver);
        REQUIRE(started.runtime.homeserver.federation.pdu_sink != nullptr);

        auto const event_id = room_id + ":federation-msg-1";
        auto const envelope =
            make_federation_message_envelope(room_id, remote_sender, "hello from federation", event_id);

        auto captured_request = std::string{};
        auto const notify_response = merovingian::tests::tls_mock::json_http_response("200 OK", R"({"rejected":[]})");
        auto server_thread = std::thread{[&] {
            merovingian::tests::tls_mock::run_one_shot_tls_server(acceptor, *tls_ctx.context, notify_response,
                                                                  &captured_request);
        }};
        auto const server_join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("the remote message PDU is accepted through the wired federation pdu_sink")
        {
            auto const result = started.runtime.homeserver.federation.pdu_sink(envelope);
            REQUIRE(result.status == merovingian::federation::PduIngestionStatus::accepted);

            wait_for_background_tasks(started.runtime.homeserver);
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("bob's pusher received a notify request naming alice as sender and the federated event")
            {
                REQUIRE_FALSE(captured_request.empty());
                REQUIRE(captured_request.find(pushkey) != std::string::npos);
                REQUIRE(captured_request.find(event_id) != std::string::npos);
                REQUIRE(captured_request.find(room_id) != std::string::npos);
                REQUIRE(captured_request.find("\"sender\":\"" + remote_sender + "\"") != std::string::npos);
                REQUIRE(captured_request.find("\"type\":\"m.room.message\"") != std::string::npos);
            }

            THEN("exactly one push-delivery task was queued for this event")
            {
                auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                REQUIRE(started.runtime.homeserver.orphan_futures_.size() == 1U);
            }

            THEN("bob's GET /notifications contains the federated event")
            {
                auto const body = get_notifications(started.runtime, bob);
                auto const* notifications = object_member_as_array(body, "notifications");
                REQUIRE(notifications != nullptr);
                REQUIRE(notifications_contain_event(*notifications, event_id));
            }
        }
    }
}

// The other half of the P1 fix: deliver_federation_push_notifications is
// wired into the federation pdu_sink, a code path send_event() never touches
// (they are structurally disjoint — send_event() persists locally-composed
// events, pdu_sink only ever runs for PDUs accepted from a remote server —
// see room_service.hpp's doc comment on deliver_federation_push_
// notifications). This proves a locally composed event, sent the ordinary
// way, is still delivered exactly once now that the federation path also
// dispatches push notifications: not zero (a regression in the other
// direction), not two (a double-dispatch bug).
SCENARIO("a locally composed event is still delivered exactly once now that federation-accepted events also "
         "dispatch push notifications",
         "[integration][push][federation]")
{
    GIVEN("push and federation delivery enabled, alice and bob in a room, and bob has a pusher pointed at a mock "
          "gateway that only serves one connection")
    {
        auto started = merovingian::homeserver::start_client_server(push_federation_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;
        merovingian::homeserver::wire_federation_callbacks(started.runtime.homeserver);

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        auto const gateway_host = std::string{"push-no-double.localhost.test"};
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

        auto const pushkey = std::string{"bob-pushkey-no-double"};
        register_http_pusher(started.runtime, bob, "org.matrix.integration", pushkey, gateway_url);

        // Serves exactly one connection: if send_event's local-event path
        // somehow triggered a second delivery attempt, that attempt would
        // find no listener and the test would fail (via the request-count/
        // task-count checks below) rather than silently passing.
        auto captured_request = std::string{};
        auto const notify_response = merovingian::tests::tls_mock::json_http_response("200 OK", R"({"rejected":[]})");
        auto server_thread = std::thread{[&] {
            merovingian::tests::tls_mock::run_one_shot_tls_server(acceptor, *tls_ctx.context, notify_response,
                                                                  &captured_request);
        }};
        auto const server_join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("alice sends one local message")
        {
            auto const send = send_text_message(started.runtime, alice, room_id, "txn-no-double", "hello bob");
            REQUIRE(send.response.status == 200U);
            auto const send_body = parse_object(send.response.body);
            auto const* event_id = string_member(send_body, "event_id");
            REQUIRE(event_id != nullptr);

            wait_for_background_tasks(started.runtime.homeserver);
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("exactly one push-delivery task was queued for the send")
            {
                auto const lock = std::lock_guard{started.runtime.homeserver.orphan_futures_mutex_};
                REQUIRE(started.runtime.homeserver.orphan_futures_.size() == 1U);
            }

            THEN("the mock gateway received exactly one notify request, for that event")
            {
                REQUIRE_FALSE(captured_request.empty());
                REQUIRE(captured_request.find(*event_id) != std::string::npos);
            }
        }
    }
}

// ── Per-recipient pusher bound (0.11.11 gap audit, PR #479 review finding
// P1) ────────────────────────────────────────────────────────────────────
// Spec: Matrix Push Gateway API v1.19, POST /_matrix/push/v1/notify
// URL: ../../docs/matrix-v1.19-spec/push-gateway-api.md#post_matrixpushv1notify
//
// POST /pushers/set has no per-user limit on distinct (app_id, pushkey)
// pairs, and build_pending_push_deliveries used to copy and process every one
// of a recipient's pushers sequentially inside a single background task —
// unbounded by the 128-task in-flight cap, which only bounds the number of
// *tasks*, not the work inside one. Fixed by room_service.cpp's
// k_max_pushers_per_delivery (10): only the first 10 of a recipient's
// pushers are contacted per event; the rest are skipped (with a
// push.pushers.truncated warning log, not silently).
SCENARIO("a recipient with more pushers than the per-delivery cap only has the capped number actually contacted "
         "for one event",
         "[integration][push]")
{
    GIVEN("push delivery enabled, alice and bob in a room, and bob has more http pushers than the per-delivery cap, "
          "all pointed at the same mock gateway")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);
        started.runtime.homeserver.config.server().push.enabled = true;

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        auto const gateway_host = std::string{"push-pusher-cap.localhost.test"};
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

        // 12 distinct (app_id, pushkey) pushers for bob -- 2 more than
        // room_service.cpp's k_max_pushers_per_delivery (10).
        auto constexpr registered_pusher_count = 12U;
        for (auto i = 0U; i < registered_pusher_count; ++i)
        {
            register_http_pusher(started.runtime, bob, "org.matrix.integration", "bob-pushkey-cap-" + std::to_string(i),
                                 gateway_url);
        }
        REQUIRE(pusher_count(started.runtime, bob) == registered_pusher_count);

        auto constexpr expected_processed = 10U; // room_service.cpp's k_max_pushers_per_delivery
        auto const ok_response = merovingian::tests::tls_mock::json_http_response("200 OK", R"({"rejected":[]})");
        auto path_responses = std::vector<std::pair<std::string, std::string>>{};
        for (auto i = 0U; i < expected_processed; ++i)
        {
            path_responses.emplace_back("/_matrix/push/v1/notify", ok_response);
        }
        auto captured_requests = std::vector<std::string>{};
        auto server_thread = std::thread{[&] {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, *tls_ctx.context, path_responses,
                                                                       &captured_requests);
        }};
        auto const server_join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("alice sends a message that matches the default .m.rule.message rule")
        {
            auto const send = send_text_message(started.runtime, alice, room_id, "txn-pusher-cap", "hello bob");
            REQUIRE(send.response.status == 200U);

            wait_for_background_tasks(started.runtime.homeserver);
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("exactly the capped number of pushers were actually contacted, not all twelve")
            {
                REQUIRE(captured_requests.size() == expected_processed);
            }
        }
    }
}

// ── a message body naming the recipient never highlights via a default rule
// (0.11.11 gap audit, PR #479 review findings P2 + follow-on P2) ───────────
// Spec: Matrix Client-Server API v1.19 §push-notifications, "Predefined
// Rules" -- "[Changed in v1.17]: the legacy default push rules that looked
// for mentions in the body of the event were removed."
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications
//
// This scenario used to prove `.m.rule.contains_display_name` (a server
// default at the time) read bob's room-specific membership displayname
// rather than his stale account-wide profile name, using the highlight
// tweak as the observable signal. Per the spec text above,
// `.m.rule.contains_display_name` is not one of the ten rules the current
// spec's "Default Override Rules" list defines and has been removed from
// default_push_ruleset.cpp (see src/homeserver/default_push_ruleset.cpp and
// tests/unit/test_default_push_ruleset.cpp) -- it was exactly the kind of
// body-text-mention-scanning rule that list's v1.17 change removed, and
// caused a real false positive: a message merely containing someone's name
// as ordinary prose highlighted them regardless of the sender's actual
// `m.mentions` intent. This scenario now proves the inverse: neither bob's
// room-specific membership displayname nor his stale account-wide profile
// name, appearing as plain body text, ever produces a highlight -- while
// the message itself is still delivered and recorded as a normal
// (non-highlighted) notification via the underride rules, so the fix is
// "no more false-positive highlight", not "no more delivery at all". The
// room-membership-vs-account-profile distinction this scenario's setup
// exercises (room_service.cpp's room_member_display_name) remains live
// infrastructure feeding PushEvaluationContext::receiving_user_display_name
// on every evaluation, ready for any future rule (default or user-defined)
// that references the contains_display_name condition kind, even though no
// current default rule consumes it.
SCENARIO("a message body naming the recipient (room-specific or stale account-wide) never highlights, "
         "only via a default rule",
         "[integration][push]")
{
    GIVEN("alice and bob in a room, and bob's account profile displayname differs from his current room-membership "
          "displayname")
    {
        auto started = merovingian::homeserver::start_client_server(push_test_config());
        REQUIRE(started.started);

        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        // Account-wide profile: a name that will not appear anywhere in the
        // room's current membership state below.
        auto const profile_update = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"PUT", "/_matrix/client/v3/profile/%40bob%3Aexample.org/displayname", bob,
                              R"({"displayname":"StaleAccountBob"})"});
        REQUIRE(profile_update.response.status == 200U);

        // Room-specific membership displayname: overwrite bob's current
        // m.room.member state event content directly, simulating what a
        // per-room display-name override would leave behind, distinct from
        // the account profile above.
        auto& store = started.runtime.homeserver.database.persistent_store;
        auto const state_it =
            std::ranges::find_if(store.state, [&](merovingian::database::PersistentStateEvent const& state) {
                return state.room_id == room_id && state.event_type == "m.room.member" &&
                       state.state_key == "@bob:example.org";
            });
        REQUIRE(state_it != store.state.end());

        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        content.push_back(merovingian::canonicaljson::make_member(
            "displayname", merovingian::canonicaljson::Value{std::string{"RoomOnlyBob"}}));
        auto event_obj = merovingian::canonicaljson::Object{};
        event_obj.push_back(merovingian::canonicaljson::make_member(
            "type", merovingian::canonicaljson::Value{std::string{"m.room.member"}}));
        event_obj.push_back(
            merovingian::canonicaljson::make_member("room_id", merovingian::canonicaljson::Value{room_id}));
        event_obj.push_back(merovingian::canonicaljson::make_member(
            "sender", merovingian::canonicaljson::Value{std::string{"@bob:example.org"}}));
        event_obj.push_back(merovingian::canonicaljson::make_member(
            "state_key", merovingian::canonicaljson::Value{std::string{"@bob:example.org"}}));
        event_obj.push_back(
            merovingian::canonicaljson::make_member("content", merovingian::canonicaljson::Value{std::move(content)}));
        event_obj.push_back(merovingian::canonicaljson::make_member(
            "origin_server_ts", merovingian::canonicaljson::Value{static_cast<std::int64_t>(500)}));
        auto const serialized =
            merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{event_obj});
        REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
        auto const overridden_member_event_id = room_id + ":bob-room-displayname-override";
        store.events.push_back(
            {overridden_member_event_id, room_id, "@bob:example.org", serialized.output, 0U, 0U, {}, {}, {}});
        state_it->event_id = overridden_member_event_id;

        WHEN("alice sends a message containing bob's room-specific display name")
        {
            auto const send_room_name =
                send_text_message(started.runtime, alice, room_id, "txn-displayname-room", "hey RoomOnlyBob");
            REQUIRE(send_room_name.response.status == 200U);
            auto const room_name_body = parse_object(send_room_name.response.body);
            auto const* room_name_event_id = string_member(room_name_body, "event_id");
            REQUIRE(room_name_event_id != nullptr);

            THEN("the notification is recorded but NOT highlighted -- no default rule scans the body for a name")
            {
                auto const body = get_notifications(started.runtime, bob);
                auto const* notifications = object_member_as_array(body, "notifications");
                REQUIRE(notifications != nullptr);
                // Positive counterpart: the event IS present in the history
                // (delivered via .m.rule.room_one_to_one/.m.rule.message),
                // so the highlight absence below cannot vacuously pass
                // because the whole entry was missing.
                REQUIRE(notifications_contain_event(*notifications, *room_name_event_id));
                REQUIRE_FALSE(notification_actions_have_highlight(*notifications, *room_name_event_id));
            }
        }

        WHEN("alice sends a message containing only bob's stale account-wide profile name")
        {
            auto const send_stale_name =
                send_text_message(started.runtime, alice, room_id, "txn-displayname-stale", "hey StaleAccountBob");
            REQUIRE(send_stale_name.response.status == 200U);
            auto const stale_body = parse_object(send_stale_name.response.body);
            auto const* stale_event_id = string_member(stale_body, "event_id");
            REQUIRE(stale_event_id != nullptr);

            THEN("the notification is recorded but NOT highlighted, exactly as for the room-specific name")
            {
                auto const body = get_notifications(started.runtime, bob);
                auto const* notifications = object_member_as_array(body, "notifications");
                REQUIRE(notifications != nullptr);
                REQUIRE(notifications_contain_event(*notifications, *stale_event_id));
                REQUIRE_FALSE(notification_actions_have_highlight(*notifications, *stale_event_id));
            }
        }
    }
}
