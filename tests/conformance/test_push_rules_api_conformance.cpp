// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |                 PUSH RULES API AND EVENTS — CONFORMANCE                 |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19, "Push Rules: API" and           |
// |  "Push Rules: Events"                                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#push-rules-api |
// |                                                                         |
// |  Audit R19 (ADR-0204): user-defined rules can be created, ordered,     |
// |  deleted, enabled and given actions; the server refuses what the spec  |
// |  reserves; a change reaches clients as m.push_rules account data; and  |
// |  delivery and unread counts follow the user's stored rules.            |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config(std::uint32_t max_push_rules = 200U) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    server.client_api.max_push_rules_per_user = max_push_rules;
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
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

[[nodiscard]] auto request(merovingian::homeserver::ClientServerRuntime& runtime, std::string method,
                           std::string target, std::string const& token, std::string body = {})
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {std::move(method), std::move(target), token, std::move(body)})
        .response;
}

[[nodiscard]] auto errcode_of(merovingian::homeserver::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

// The rule IDs of `kind` in the order GET /pushrules/global/ serves them.
[[nodiscard]] auto served_rule_ids(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                   std::string const& kind) -> std::vector<std::string>
{
    auto const response = request(runtime, "GET", "/_matrix/client/v3/pushrules/global/", token);
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* rules = object_member_as_array(body, kind);
    REQUIRE(rules != nullptr);
    auto ids = std::vector<std::string>{};
    for (auto const& rule : *rules)
    {
        auto const* rule_object = std::get_if<merovingian::canonicaljson::Object>(&rule.storage());
        REQUIRE(rule_object != nullptr);
        auto const* rule_id = string_member(*rule_object, "rule_id");
        REQUIRE(rule_id != nullptr);
        ids.push_back(*rule_id);
    }
    return ids;
}

auto put_content_rule(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                      std::string const& rule_id, std::string const& query = {}) -> std::uint16_t
{
    return request(runtime, "PUT", "/_matrix/client/v3/pushrules/global/content/" + rule_id + query, token,
                   R"({"pattern":"cake","actions":["notify"]})")
        .status;
}

[[nodiscard]] auto room_with_alice_and_bob(merovingian::homeserver::ClientServerRuntime& runtime,
                                           std::string const& alice, std::string const& bob) -> std::string
{
    auto const create = request(runtime, "POST", "/_matrix/client/v3/createRoom", alice,
                                R"({"preset":"private_chat","invite":["@bob:example.org"]})");
    REQUIRE(create.status == 200U);
    auto const create_body = parse_object(create.body);
    auto const* room_id = string_member(create_body, "room_id");
    REQUIRE(room_id != nullptr);
    REQUIRE(request(runtime, "POST", "/_matrix/client/v3/rooms/" + *room_id + "/join", bob, "{}").status == 200U);
    return *room_id;
}

auto send_text(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
               std::string const& room_id, std::string const& txn_id, std::string const& text) -> void
{
    REQUIRE(request(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn_id, token,
                    R"({"msgtype":"m.text","body":")" + text + R"("})")
                .status == 200U);
}

[[nodiscard]] auto notification_count(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::size_t
{
    auto const response = request(runtime, "GET", "/_matrix/client/v3/notifications", token);
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* notifications = object_member_as_array(body, "notifications");
    REQUIRE(notifications != nullptr);
    return notifications->size();
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/pushrules/global/{kind}/{ruleId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3pushrulesglobalkindruleid
//
// "If neither after nor before are provided and the rule is created, it should be added as the
// most important user defined rule among rules of the same kind." `after` "makes the new rule the
// next-less important rule relative to the given user defined rule"; `before` makes it "the
// next-most important rule"; "If both after and before are provided, the new or updated rule must
// be the next most important rule with respect to the rule identified by before."
SCENARIO("PUT /pushrules orders user-defined rules by before and after", "[conformance][client-server][push][r19]")
{
    GIVEN("a user who creates content rules one, then two")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        REQUIRE(put_content_rule(started.runtime, alice, "one") == 200U);
        REQUIRE(put_content_rule(started.runtime, alice, "two") == 200U);

        WHEN("three is put after two, and four with before=one&after=two")
        {
            REQUIRE(put_content_rule(started.runtime, alice, "three", "?after=two") == 200U);
            REQUIRE(put_content_rule(started.runtime, alice, "four", "?before=one&after=two") == 200U);

            THEN("the newest rule without placement leads, and before wins over after")
            {
                // Spec SHOULD: a created rule with no placement is the most important user rule.
                REQUIRE(served_rule_ids(started.runtime, alice, "content") ==
                        std::vector<std::string>{"two", "three", "four", "one"});
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/pushrules/global/{kind}/{ruleId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3pushrulesglobalkindruleid
//
// ruleId: "If the string starts with a dot ("."), the request MUST be rejected as this is reserved
// for server-default rules. Slashes ("/") and backslashes ("\") are also not allowed."
// before/after: "It is not possible to add a rule relative to a predefined server rule." 400
// example: M_UNKNOWN "before/after rule not found".
SCENARIO("PUT /pushrules refuses reserved IDs and unknown or server-default placements",
         "[conformance][client-server][push][r19]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");

        WHEN("such rules are put")
        {
            auto const dotted = request(started.runtime, "PUT", "/_matrix/client/v3/pushrules/global/content/.mine",
                                        alice, R"({"pattern":"x","actions":[]})");
            auto const slashed = request(started.runtime, "PUT", "/_matrix/client/v3/pushrules/global/content/a%2Fb",
                                         alice, R"({"pattern":"x","actions":[]})");
            auto const unknown_before =
                request(started.runtime, "PUT", "/_matrix/client/v3/pushrules/global/content/a?before=nope", alice,
                        R"({"pattern":"x","actions":[]})");
            auto const default_after = request(
                started.runtime, "PUT", "/_matrix/client/v3/pushrules/global/override/a?after=.m.rule.suppress_notices",
                alice, R"({"actions":[]})");
            auto const delete_default = request(started.runtime, "DELETE",
                                                "/_matrix/client/v3/pushrules/global/override/.m.rule.master", alice);

            THEN("each is refused with 400 and nothing is created")
            {
                // Spec MUST: a dotted rule ID is rejected.
                REQUIRE(dotted.status == 400U);
                // Spec: slashes are not allowed.
                REQUIRE(slashed.status == 400U);
                // Spec: 400 "There was a problem configuring this push rule." (M_UNKNOWN example)
                REQUIRE(unknown_before.status == 400U);
                REQUIRE(errcode_of(unknown_before) == "M_UNKNOWN");
                // Spec: "It is not possible to add a rule relative to a predefined server rule."
                REQUIRE(default_after.status == 400U);
                // Server-default rules exist and cannot be removed (ADR-0204).
                REQUIRE(delete_default.status == 400U);
                REQUIRE(served_rule_ids(started.runtime, alice, "content").empty());
                REQUIRE(served_rule_ids(started.runtime, alice, "override").front() == ".m.rule.master");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/pushrules/global/{kind}/{ruleId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3pushrulesglobalkindruleid
//
// Security audit run-1 and ADR-0204: rules are evaluated under the runtime lock for every event,
// so the number a user may hold is capped (`server.client_api.max_push_rules_per_user`). The spec
// allows a 400 "There was a problem configuring this push rule."
SCENARIO("PUT /pushrules refuses a rule past the per-user cap but still updates existing rules",
         "[conformance][client-server][push][r19][security]")
{
    GIVEN("a user at a cap of two rules")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config(2U));
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        REQUIRE(put_content_rule(started.runtime, alice, "one") == 200U);
        REQUIRE(put_content_rule(started.runtime, alice, "two") == 200U);

        WHEN("a third rule is created and an existing one updated")
        {
            auto const third = request(started.runtime, "PUT", "/_matrix/client/v3/pushrules/global/content/three",
                                       alice, R"({"pattern":"x","actions":[]})");
            auto const update = put_content_rule(started.runtime, alice, "one");

            THEN("the third is refused with M_TOO_LARGE and the update succeeds")
            {
                REQUIRE(third.status == 400U);
                REQUIRE(errcode_of(third) == "M_TOO_LARGE");
                REQUIRE(update == 200U);
                REQUIRE(served_rule_ids(started.runtime, alice, "content").size() == 2U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Push Rules: Events; Client Config, Server Behaviour
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#push-rules-events
//
// "When a user changes their push rules a m.push_rules event is sent to all clients in the
// account_data section of their next /sync request. The content of the event is the current push
// rules for the user." "Servers MUST reject setting account data for event types that the server
// manages by using a 405 error response. Currently, this only includes m.fully_read and
// m.push_rules." "Servers must allow clients to read the above event types as normal."
SCENARIO("A push rule change reaches /sync as m.push_rules account data that clients cannot set",
         "[conformance][client-server][push][r19]")
{
    GIVEN("a user who adds a content rule")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        REQUIRE(put_content_rule(started.runtime, alice, "cake") == 200U);

        WHEN("the user syncs, reads the account data, and tries to set it")
        {
            auto const sync = request(started.runtime, "GET", "/_matrix/client/v3/sync?timeout=0", alice);
            auto const read =
                request(started.runtime, "GET",
                        "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.push_rules", alice);
            auto const write_rules = request(started.runtime, "PUT",
                                             "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.push_rules",
                                             alice, R"({"global":{}})");
            auto const write_fully_read = request(
                started.runtime, "PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.fully_read",
                alice, R"({"event_id":"$x"})");

            THEN("sync carries the current rules, reads succeed, and writes are refused with 405")
            {
                REQUIRE(sync.status == 200U);
                auto const sync_body = parse_object(sync.body);
                auto const* account_data = object_member_as_object(sync_body, "account_data");
                REQUIRE(account_data != nullptr);
                auto const* events = object_member_as_array(*account_data, "events");
                REQUIRE(events != nullptr);
                auto found = false;
                for (auto const& event : *events)
                {
                    auto const& object = std::get<merovingian::canonicaljson::Object>(event.storage());
                    auto const* type = string_member(object, "type");
                    if (type != nullptr && *type == "m.push_rules")
                    {
                        auto const* content = object_member_as_object(object, "content");
                        REQUIRE(content != nullptr);
                        auto const* global = object_member_as_object(*content, "global");
                        REQUIRE(global != nullptr);
                        auto const* content_rules = object_member_as_array(*global, "content");
                        REQUIRE(content_rules != nullptr);
                        REQUIRE(content_rules->size() == 1U);
                        found = true;
                    }
                }
                // Spec: "a m.push_rules event is sent to all clients in the account_data section".
                REQUIRE(found);
                // Spec MUST: "Servers must allow clients to read the above event types as normal."
                REQUIRE(read.status == 200U);
                // Spec MUST: "Servers MUST reject setting account data for event types that the
                // server manages by using a 405 error response."
                REQUIRE(write_rules.status == 405U);
                REQUIRE(write_fully_read.status == 405U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Push Rules; Push Rules: API
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#push-rules
//
// "Each rule can be enabled or disabled. Disabled rules never match." .m.rule.master "can be
// enabled to turn off all push notifications". GET /notifications lists the events "the user has
// been, or would have been notified about", so it shows what delivery decided.
SCENARIO("Delivery follows the user's stored push rules, not the read-only defaults",
         "[conformance][client-server][push][r19]")
{
    GIVEN("alice and bob in a room, and alice's default rules notify her of bob's messages")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);
        send_text(started.runtime, bob, room_id, "t1", "hello");
        REQUIRE(notification_count(started.runtime, alice) == 1U);

        WHEN("alice enables .m.rule.master and bob sends another message")
        {
            REQUIRE(request(started.runtime, "PUT",
                            "/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled", alice,
                            R"({"enabled":true})")
                        .status == 200U);
            send_text(started.runtime, bob, room_id, "t2", "hello again");

            THEN("no notification is recorded for it")
            {
                // Spec: "Disabled rules never match"; an enabled master rule with no actions wins.
                REQUIRE(notification_count(started.runtime, alice) == 1U);
            }
        }

        WHEN("alice mutes bob with a sender rule and bob sends another message")
        {
            REQUIRE(request(started.runtime, "PUT", "/_matrix/client/v3/pushrules/global/sender/%40bob%3Aexample.org",
                            alice, R"({"actions":[]})")
                        .status == 200U);
            send_text(started.runtime, bob, room_id, "t3", "still here");

            THEN("no notification is recorded for it")
            {
                REQUIRE(notification_count(started.runtime, alice) == 1U);
            }
        }
    }
}

namespace
{

struct UnreadCounts final
{
    std::int64_t notifications{-1};
    std::int64_t highlights{-1};
};

// The room's `unread_notifications` in an initial /sync for `token`'s user.
[[nodiscard]] auto unread_counts(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                 std::string const& room_id) -> UnreadCounts
{
    auto const sync = request(runtime, "GET", "/_matrix/client/v3/sync?timeout=0", token);
    REQUIRE(sync.status == 200U);
    auto const body = parse_object(sync.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* join = object_member_as_object(*rooms, "join");
    REQUIRE(join != nullptr);
    auto const* room = object_member_as_object(*join, room_id);
    REQUIRE(room != nullptr);
    auto const* unread = object_member_as_object(*room, "unread_notifications");
    REQUIRE(unread != nullptr);
    auto const* notifications = int_member(*unread, "notification_count");
    auto const* highlights = int_member(*unread, "highlight_count");
    return {notifications == nullptr ? 0 : *notifications, highlights == nullptr ? 0 : *highlights};
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Receiving notifications; GET /sync unread_notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#receiving-notifications
//
// "Servers MUST include the number of unread notifications in a client's /sync stream, and MUST
// update it as it changes. Notifications are determined by the push rules which apply to an
// event." highlight_count: "The number of unread notifications for this room with the highlight
// flag set." (R15, ADR-0205)
SCENARIO("Unread notification counts are decided by the user's push rules", "[conformance][client-server][push][r15]")
{
    GIVEN("alice and bob in a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const room_id = room_with_alice_and_bob(started.runtime, alice, bob);

        WHEN("alice mutes the room with a room rule and bob sends a message")
        {
            REQUIRE(request(started.runtime, "PUT", "/_matrix/client/v3/pushrules/global/room/" + room_id, alice,
                            R"({"actions":[]})")
                        .status == 200U);
            send_text(started.runtime, bob, room_id, "m1", "hello");

            THEN("the message is not an unread notification")
            {
                // Spec MUST: notifications are determined by the push rules; the room rule
                // matches first and does not notify.
                REQUIRE(unread_counts(started.runtime, alice, room_id).notifications == 0);
            }
        }

        WHEN("alice adds a highlighting keyword and bob sends one message with it and one without")
        {
            REQUIRE(request(started.runtime, "PUT", "/_matrix/client/v3/pushrules/global/content/cake", alice,
                            R"({"pattern":"cake","actions":["notify",{"set_tweak":"highlight"}]})")
                        .status == 200U);
            send_text(started.runtime, bob, room_id, "m2", "I like cake");
            send_text(started.runtime, bob, room_id, "m3", "and tea");

            THEN("both notify and only the keyword message highlights")
            {
                auto const counts = unread_counts(started.runtime, alice, room_id);
                REQUIRE(counts.notifications == 2);
                // Spec: highlight_count counts unread notifications "with the highlight flag set".
                REQUIRE(counts.highlights == 1);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Receiving notifications; Server behaviour (Push Notifications)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#receiving-notifications
//
// "When receiving a new event homeservers process push rules for each of the local users in the
// room (excluding the sender). This may result in: Generating a new number of unread
// notifications for the user." A user who was not in the room had no rules processed for its
// earlier events, so they are not that user's notifications (audit concern 1, ADR-0205).
SCENARIO("Unread notification counts start at the user's join", "[conformance][client-server][push][r15]")
{
    GIVEN("bob's public room with two messages sent before alice joins")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const create =
            request(started.runtime, "POST", "/_matrix/client/v3/createRoom", bob, R"({"preset":"public_chat"})");
        REQUIRE(create.status == 200U);
        auto const create_body = parse_object(create.body);
        auto const* room_id = string_member(create_body, "room_id");
        REQUIRE(room_id != nullptr);
        send_text(started.runtime, bob, *room_id, "before1", "one");
        send_text(started.runtime, bob, *room_id, "before2", "two");

        WHEN("alice joins and bob sends one more message")
        {
            REQUIRE(request(started.runtime, "POST", "/_matrix/client/v3/rooms/" + *room_id + "/join", alice, "{}")
                        .status == 200U);
            send_text(started.runtime, bob, *room_id, "after", "three");

            THEN("only the message sent after the join is unread")
            {
                REQUIRE(unread_counts(started.runtime, alice, *room_id).notifications == 1);
            }
        }
    }
}
