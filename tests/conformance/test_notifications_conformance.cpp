// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            GET /_matrix/client/v3/notifications — CONFORMANCE           |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 §push-notifications               |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3notifications |
// |                                                                         |
// |  Covers the endpoint's own MUST/SHOULD behaviour: a notification        |
// |  appears once a matching event has been evaluated, `only=highlight`     |
// |  filters to highlight-tweaked notifications, `limit` bounds the page,   |
// |  `from`/`next_token` paginate without gap or overlap, and `read`        |
// |  reflects the caller's own read receipts. Routing/shape and the         |
// |  unauthenticated case are covered by the "GET /notifications ..."       |
// |  scenarios in test_client_server_conformance.cpp; the ignored-sender    |
// |  suppression case is covered end to end in                              |
// |  tests/integration/test_push_delivery_flow.cpp (it needs the ignore-    |
// |  list + push-rule-evaluation pipeline together).                        |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
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

// Creates a private_chat room inviting bob and has bob join it. A 2-member
// room with a plain m.room.message event reliably fires the server-default
// `.m.rule.message` underride rule (notify:true), regardless of any
// member-count-scoped rule.
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

// PUT /rooms/{roomId}/send/m.room.message/{txnId} — a plain text message.
[[nodiscard]] auto send_text_message(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                     std::string const& room_id, std::string const& txn_id, std::string const& body)
    -> std::string
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn_id, token,
                  R"({"msgtype":"m.text","body":")" + body + R"("})"});
    REQUIRE(response.response.status == 200U);
    auto const parsed = parse_object(response.response.body);
    auto const* event_id = string_member(parsed, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

// PUT .../send/m.room.message/{txnId} whose content names `mentioned_user`
// in `m.mentions.user_ids` — fires the default `.m.rule.is_user_mention`
// override rule, which sets the highlight tweak (see
// src/homeserver/default_push_ruleset.cpp).
[[nodiscard]] auto send_mention_message(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                        std::string const& room_id, std::string const& txn_id,
                                        std::string const& mentioned_user) -> std::string
{
    auto const body =
        std::string{R"({"msgtype":"m.text","body":"hey you","m.mentions":{"user_ids":[")"} + mentioned_user + R"("]}})";
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn_id, token, body});
    REQUIRE(response.response.status == 200U);
    auto const parsed = parse_object(response.response.body);
    auto const* event_id = string_member(parsed, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

// POST /rooms/{roomId}/receipt/m.read/{eventId}.
auto send_read_receipt(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                       std::string const& room_id, std::string const& event_id) -> void
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/" + event_id, token, "{}"});
    REQUIRE(response.response.status == 200U);
}

// GET /_matrix/client/v3/notifications[?query], parsed into an object.
[[nodiscard]] auto get_notifications(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                     std::string const& query = {}) -> merovingian::canonicaljson::Object
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/notifications" + query, token, {}});
    REQUIRE(response.response.status == 200U);
    return parse_object(response.response.body);
}

// Finds the notification entry (an object in `notifications`) whose
// `event.event_id` equals `event_id`, or nullptr. Never matches by substring
// search over serialized JSON -- parses each element's own `event.event_id`
// field, so a value that merely appears elsewhere (e.g. inside another
// event's prev_events) cannot produce a false positive.
[[nodiscard]] auto find_notification(merovingian::canonicaljson::Array const& notifications,
                                     std::string const& event_id) -> merovingian::canonicaljson::Object const*
{
    for (auto const& entry : notifications)
    {
        auto const* entry_object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        if (entry_object == nullptr)
        {
            continue;
        }
        auto const* event_object = object_member_as_object(*entry_object, "event");
        if (event_object == nullptr)
        {
            continue;
        }
        auto const* found_event_id = string_member(*event_object, "event_id");
        if (found_event_id != nullptr && *found_event_id == event_id)
        {
            return entry_object;
        }
    }
    return nullptr;
}

} // namespace

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3notifications
//
// Spec MUST: every Notification field below ("actions", "event",
// "profile_tag", "read", "room_id", "ts") is Required (profile_tag excepted
// -- optional per the field table, but always present as a string here).
SCENARIO("a notification appears in GET /notifications after a matching event", "[conformance][client-server][push]")
{
    GIVEN("alice and bob in a room, and bob has never sent a read receipt")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        WHEN("alice sends a message that matches the default .m.rule.message rule")
        {
            auto const event_id = send_text_message(started.runtime, alice, room_id, "notif-basic", "hello bob");

            THEN("GET /notifications (as bob) returns exactly that notification with every required field")
            {
                auto const body = get_notifications(started.runtime, bob);
                auto const* notifications = object_member_as_array(body, "notifications");
                REQUIRE(notifications != nullptr);
                REQUIRE(notifications->size() == 1U);

                auto const* entry = find_notification(*notifications, event_id);
                REQUIRE(entry != nullptr);

                // Spec MUST: actions is Required.
                auto const* actions = object_member_as_array(*entry, "actions");
                REQUIRE(actions != nullptr);
                REQUIRE(!actions->empty());
                auto const* first_action = std::get_if<std::string>(&(*actions)[0U].storage());
                REQUIRE(first_action != nullptr);
                REQUIRE(*first_action == "notify");

                // Spec MUST: room_id is Required.
                auto const* room_id_field = string_member(*entry, "room_id");
                REQUIRE(room_id_field != nullptr);
                REQUIRE(*room_id_field == room_id);

                // Spec MUST: ts is Required ("unix timestamp ... in milliseconds").
                auto const* ts = int_member(*entry, "ts");
                REQUIRE(ts != nullptr);
                REQUIRE(*ts > 0);

                // Spec MUST: read is Required — bob never sent a receipt.
                auto const* read = bool_member(*entry, "read");
                REQUIRE(read != nullptr);
                REQUIRE_FALSE(*read);

                // Spec MUST: profile_tag is present (empty string is valid —
                // this notification was not attributed to any one pusher).
                REQUIRE(string_member(*entry, "profile_tag") != nullptr);

                // Spec MUST: event is Required and carries the sent event's shape.
                auto const* event_object = object_member_as_object(*entry, "event");
                REQUIRE(event_object != nullptr);
                auto const* sender = string_member(*event_object, "sender");
                REQUIRE(sender != nullptr);
                REQUIRE(*sender == "@alice:example.org");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3notifications
//
// Spec MUST (`only` param): "Supply `highlight` to return only events where
// the notification had the highlight tweak set."
SCENARIO("GET /notifications?only=highlight returns only highlight-tweaked notifications",
         "[conformance][client-server][push]")
{
    GIVEN("alice and bob in a room; alice sends a plain message, then one that mentions bob")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        auto const plain_event_id = send_text_message(started.runtime, alice, room_id, "notif-highlight-plain", "hi");
        auto const mention_event_id =
            send_mention_message(started.runtime, alice, room_id, "notif-highlight-mention", "@bob:example.org");

        WHEN("GET /notifications is called without a filter")
        {
            auto const body = get_notifications(started.runtime, bob);
            auto const* notifications = object_member_as_array(body, "notifications");
            REQUIRE(notifications != nullptr);

            THEN("both notifications are present (the positive counterpart to the filtered request below)")
            {
                REQUIRE(notifications->size() == 2U);
                REQUIRE(find_notification(*notifications, plain_event_id) != nullptr);
                REQUIRE(find_notification(*notifications, mention_event_id) != nullptr);
            }
        }

        WHEN("GET /notifications?only=highlight is called")
        {
            auto const body = get_notifications(started.runtime, bob, "?only=highlight");
            auto const* notifications = object_member_as_array(body, "notifications");
            REQUIRE(notifications != nullptr);

            THEN("only the highlight-tweaked (mention) notification is returned")
            {
                // Spec MUST: only=highlight filters to highlight-tweaked events.
                REQUIRE(notifications->size() == 1U);
                REQUIRE(find_notification(*notifications, mention_event_id) != nullptr);
                // Structural absence check (not substring search): the plain
                // message's own event_id must not appear as any entry's
                // event.event_id.
                REQUIRE(find_notification(*notifications, plain_event_id) == nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3notifications
//
// Spec MUST (`limit` param): "Limit on the number of events to return in
// this request."
SCENARIO("GET /notifications honours the limit query parameter", "[conformance][client-server][push]")
{
    GIVEN("alice and bob in a room, and alice sends three messages")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        std::ignore = send_text_message(started.runtime, alice, room_id, "notif-limit-1", "one");
        std::ignore = send_text_message(started.runtime, alice, room_id, "notif-limit-2", "two");
        std::ignore = send_text_message(started.runtime, alice, room_id, "notif-limit-3", "three");

        WHEN("GET /notifications?limit=2 is called")
        {
            auto const body = get_notifications(started.runtime, bob, "?limit=2");

            THEN("exactly two notifications are returned and next_token is present")
            {
                auto const* notifications = object_member_as_array(body, "notifications");
                REQUIRE(notifications != nullptr);
                REQUIRE(notifications->size() == 2U);
                // Spec MUST: next_token is present when more results remain.
                REQUIRE(string_member(body, "next_token") != nullptr);
            }
        }

        WHEN("GET /notifications is called without a limit and there are only three notifications")
        {
            auto const body = get_notifications(started.runtime, bob);

            THEN("all three are returned and next_token is absent (positive counterpart)")
            {
                auto const* notifications = object_member_as_array(body, "notifications");
                REQUIRE(notifications != nullptr);
                REQUIRE(notifications->size() == 3U);
                // Spec MUST: "If this is absent, there are no more results."
                REQUIRE(string_member(body, "next_token") == nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3notifications
//
// Spec MUST (`from`/`next_token`): "This API is used to paginate through the
// list of events" and next_token "should be the from param of the next
// request in order to request more events."
SCENARIO("GET /notifications from/next_token paginate without gap or overlap", "[conformance][client-server][push]")
{
    GIVEN("alice and bob in a room, and alice sends five messages")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        auto sent_event_ids = std::vector<std::string>{};
        for (auto index = 0; index < 5; ++index)
        {
            sent_event_ids.push_back(send_text_message(started.runtime, alice, room_id,
                                                       "notif-page-" + std::to_string(index),
                                                       "message " + std::to_string(index)));
        }

        WHEN("the full list is collected by paginating with limit=2")
        {
            auto collected = std::vector<std::string>{};
            auto query = std::string{"?limit=2"};
            auto pages = 0;
            for (;;)
            {
                auto const body = get_notifications(started.runtime, bob, query);
                auto const* notifications = object_member_as_array(body, "notifications");
                REQUIRE(notifications != nullptr);
                for (auto const& entry : *notifications)
                {
                    auto const* entry_object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
                    REQUIRE(entry_object != nullptr);
                    auto const* event_object = object_member_as_object(*entry_object, "event");
                    REQUIRE(event_object != nullptr);
                    auto const* event_id = string_member(*event_object, "event_id");
                    REQUIRE(event_id != nullptr);
                    collected.push_back(*event_id);
                }
                auto const* next_token = string_member(body, "next_token");
                ++pages;
                REQUIRE(pages < 10); // guard against an infinite loop if pagination regresses
                if (next_token == nullptr)
                {
                    break;
                }
                query = "?limit=2&from=" + *next_token;
            }

            THEN("every notification was returned exactly once, with no gap or overlap")
            {
                REQUIRE(collected.size() == sent_event_ids.size());
                auto const distinct = std::set<std::string>{collected.begin(), collected.end()};
                REQUIRE(distinct.size() == collected.size());
                for (auto const& sent_id : sent_event_ids)
                {
                    REQUIRE(distinct.contains(sent_id));
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3notifications
// "Marking notifications as read": "When the user updates their read
// receipt ..., notifications prior to and including that event MUST be
// marked as read."
SCENARIO("GET /notifications read reflects the caller's own read receipts", "[conformance][client-server][push]")
{
    GIVEN("alice and bob in a room, and alice sends two messages")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        auto const first_event_id = send_text_message(started.runtime, alice, room_id, "notif-read-1", "first");
        auto const second_event_id = send_text_message(started.runtime, alice, room_id, "notif-read-2", "second");

        WHEN("bob has not sent any read receipt yet")
        {
            auto const body = get_notifications(started.runtime, bob);
            auto const* notifications = object_member_as_array(body, "notifications");
            REQUIRE(notifications != nullptr);

            THEN("both notifications report read:false (positive counterpart to the receipted case below)")
            {
                auto const* first_entry = find_notification(*notifications, first_event_id);
                auto const* second_entry = find_notification(*notifications, second_event_id);
                REQUIRE(first_entry != nullptr);
                REQUIRE(second_entry != nullptr);
                auto const* first_read = bool_member(*first_entry, "read");
                auto const* second_read = bool_member(*second_entry, "read");
                REQUIRE(first_read != nullptr);
                REQUIRE(second_read != nullptr);
                REQUIRE_FALSE(*first_read);
                REQUIRE_FALSE(*second_read);
            }
        }

        WHEN("bob sends an m.read receipt for the first message only")
        {
            send_read_receipt(started.runtime, bob, room_id, first_event_id);
            auto const body = get_notifications(started.runtime, bob);
            auto const* notifications = object_member_as_array(body, "notifications");
            REQUIRE(notifications != nullptr);

            THEN("the first notification (at or before the receipt) is read, the second (after it) is not")
            {
                // Spec MUST: "notifications prior to and including that event
                // MUST be marked as read" — the second message is strictly
                // after the receipted event, so it must remain unread.
                auto const* first_entry = find_notification(*notifications, first_event_id);
                auto const* second_entry = find_notification(*notifications, second_event_id);
                REQUIRE(first_entry != nullptr);
                REQUIRE(second_entry != nullptr);
                auto const* first_read = bool_member(*first_entry, "read");
                auto const* second_read = bool_member(*second_entry, "read");
                REQUIRE(first_read != nullptr);
                REQUIRE(second_read != nullptr);
                REQUIRE(*first_read);
                REQUIRE_FALSE(*second_read);
            }
        }
    }
}
