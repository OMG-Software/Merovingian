// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            MATRIX v1.19 "IGNORING USERS" CONFORMANCE TESTS              |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 §Ignoring Users                   |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#ignoring-users |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST/SHOULD from the spec's       |
// |  "Ignoring Users" module. If a test fails:                              |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                    |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass. |
// |                                                                         |
// |  Drives real /sync, /messages, and /context requests through a live    |
// |  in-process server (no mocks) — the same style as                       |
// |  test_client_server_conformance.cpp.                                    |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto ignoring_users_config() -> merovingian::config::Config
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

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& rt, std::string const& localpart)
    -> std::string
{
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                rt, {"POST",
                     "/_matrix/client/v3/register",
                     {},
                     merovingian::tests::registration_json(localpart, "CorrectHorse7!")})
                .response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        rt, {"POST",
             "/_matrix/client/v3/login",
             {},
             std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                 R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})"});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// PUT the m.ignored_user_list account-data event for `token`'s own user.
// `percent_encoded_user_id` is the caller's own mxid, percent-encoded for the
// path segment (spec: PUT /user/{userId}/account_data/{type} requires
// userId == the authenticated caller).
auto set_ignored_users(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                       std::string const& percent_encoded_user_id, std::string const& ignored_users_body) -> void
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"PUT", "/_matrix/client/v3/user/" + percent_encoded_user_id + "/account_data/m.ignored_user_list", token,
             ignored_users_body});
    REQUIRE(resp.response.status == 200U);
}

// PUT a deliberately non-JSON m.ignored_user_list body — proves malformed
// account data is treated as "nothing ignored" rather than erroring.
auto set_malformed_ignored_users(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                                 std::string const& percent_encoded_user_id) -> void
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"PUT", "/_matrix/client/v3/user/" + percent_encoded_user_id + "/account_data/m.ignored_user_list", token,
             "this is not valid JSON at all"});
    REQUIRE(resp.response.status == 200U);
}

[[nodiscard]] auto create_room_with_invite(merovingian::homeserver::ClientServerRuntime& rt,
                                           std::string const& owner_token, std::string const& invitee_user_id)
    -> std::string
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"POST", "/_matrix/client/v3/createRoom", owner_token,
             R"({"preset":"public_chat","invite":[")" + invitee_user_id + R"("]})"});
    REQUIRE(resp.response.status == 200U);
    auto const body = parse_object(resp.response.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

auto join_room(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token, std::string const& room_id)
    -> void
{
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", token, "{}"})
                .response.status == 200U);
}

[[nodiscard]] auto send_text_message(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                                     std::string const& room_id, std::string const& txn_id, std::string const& body)
    -> std::string
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn_id, token,
             R"({"msgtype":"m.text","body":")" + body + R"("})"});
    REQUIRE(resp.response.status == 200U);
    auto const parsed = parse_object(resp.response.body);
    auto const* event_id = string_member(parsed, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

[[nodiscard]] auto sync_full(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token)
    -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token, {}},
                                                                 /*can_wait=*/false);
}

[[nodiscard]] auto sync_since(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                              std::string const& since) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        rt, {"GET", "/_matrix/client/v3/sync?since=" + since, token, {}}, /*can_wait=*/false);
}

[[nodiscard]] auto next_batch_of(std::string const& sync_body) -> std::string
{
    auto const obj = parse_object(sync_body);
    auto const* nb = string_member(obj, "next_batch");
    REQUIRE(nb != nullptr);
    return *nb;
}

// Returns the room's timeline events array, structurally, from a /sync
// response body. Deliberately NOT re-serialized to text for substring
// assertions: every event's own "prev_events"/"auth_events" fields name the
// event_ids of earlier events in the room's DAG verbatim, including a
// suppressed ignored-sender event that a later, legitimately-delivered event
// happens to chain from. Ignoring is a client-delivery filter — it never
// touches the event graph itself — so those DAG-linkage fields are correct
// and unavoidable, and a naive `text.find(some_event_id)` would find an
// ignored sender's event_id inside a DIFFERENT, correctly-delivered event's
// prev_events even when the ignored sender's own event object was withheld.
// Callers must therefore check per-event top-level fields (event_id,
// sender/type, content.*) via array_has_event_id/array_has_message_from/
// array_has_content_field below, not raw substring search.
[[nodiscard]] auto room_timeline_events(std::string const& sync_body, std::string const& room_id)
    -> merovingian::canonicaljson::Array
{
    auto const obj = parse_object(sync_body);
    auto const* rooms = object_member_as_object(obj, "rooms");
    if (rooms == nullptr)
        return {};
    auto const* join = object_member_as_object(*rooms, "join");
    if (join == nullptr)
        return {};
    auto const* room = object_member_as_object(*join, room_id);
    if (room == nullptr)
        return {};
    auto const* timeline = object_member_as_object(*room, "timeline");
    if (timeline == nullptr)
        return {};
    auto const* events = object_member_as_array(*timeline, "events");
    if (events == nullptr)
        return {};
    return *events; // copy before the local `obj` parse tree is destroyed
}

// True when some event in `events` has the given top-level "event_id" —
// i.e. that exact event was actually delivered as an element of the array,
// not merely referenced by another event's prev_events/auth_events.
[[nodiscard]] auto array_has_event_id(merovingian::canonicaljson::Array const& events, std::string const& event_id)
    -> bool
{
    return std::ranges::any_of(events, [&](merovingian::canonicaljson::Value const& value) {
        auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        auto const* id = obj != nullptr ? string_member(*obj, "event_id") : nullptr;
        return id != nullptr && *id == event_id;
    });
}

// True when some event in `events` is an m.room.message with the given
// top-level "sender" — precise enough to survive a sender's own (legitimate,
// spec-exempt) state events, such as their m.room.member join, appearing in
// the same array.
[[nodiscard]] auto array_has_message_from(merovingian::canonicaljson::Array const& events, std::string_view sender)
    -> bool
{
    return std::ranges::any_of(events, [&](merovingian::canonicaljson::Value const& value) {
        auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        auto const* type = obj != nullptr ? string_member(*obj, "type") : nullptr;
        auto const* s = obj != nullptr ? string_member(*obj, "sender") : nullptr;
        return type != nullptr && *type == "m.room.message" && s != nullptr && *s == sender;
    });
}

// True when some event in `events` has content.<field> == `expected` — e.g.
// ("body", "hello") for a message, or ("topic", "new topic") for an
// m.room.topic state event.
[[nodiscard]] auto array_has_content_field(merovingian::canonicaljson::Array const& events, std::string_view field,
                                           std::string_view expected) -> bool
{
    return std::ranges::any_of(events, [&](merovingian::canonicaljson::Value const& value) {
        auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        auto const* content = obj != nullptr ? object_member_as_object(*obj, "content") : nullptr;
        auto const* field_value = content != nullptr ? string_member(*content, field) : nullptr;
        return field_value != nullptr && *field_value == expected;
    });
}

[[nodiscard]] auto invite_room_ids(std::string const& sync_body) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    auto const obj = parse_object(sync_body);
    auto const* rooms = object_member_as_object(obj, "rooms");
    if (rooms == nullptr)
        return ids;
    auto const* invite = object_member_as_object(*rooms, "invite");
    if (invite == nullptr)
        return ids;
    for (auto const& member : *invite)
    {
        ids.push_back(member.key);
    }
    return ids;
}

} // namespace

// ── /sync: non-state events from an ignored sender are withheld ────────────

// Spec MUST (Server behaviour): "Following an update of the
// m.ignored_user_list, the sync API for all clients should immediately
// start ignoring ... the user" — a message from an ignored sender must not
// reach the ignoring user's /sync timeline, while a message from someone NOT
// ignored is unaffected.
SCENARIO("an ignored user's message does not appear in the ignoring user's /sync timeline, but an unignored user's "
         "message does",
         "[ignoring-users][conformance][sync]")
{
    GIVEN("alice, bob, and carol in a room, and alice has ignored bob")
    {
        auto started = merovingian::homeserver::start_client_server(ignoring_users_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room_with_invite(rt, alice, "@bob:example.org");
        join_room(rt, bob, room_id);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                         R"({"user_id":"@carol:example.org"})"})
                    .response.status == 200U);
        join_room(rt, carol, room_id);

        auto const baseline = sync_full(rt, alice);
        REQUIRE(baseline.response.status == 200U);
        auto const since = next_batch_of(baseline.response.body);

        set_ignored_users(rt, alice, "%40alice%3Aexample.org", R"({"ignored_users":{"@bob:example.org":{}}})");

        WHEN("bob and carol both send a message, and alice syncs incrementally")
        {
            auto const bob_event_id = send_text_message(rt, bob, room_id, "txn-bob", "hello from bob");
            auto const carol_event_id = send_text_message(rt, carol, room_id, "txn-carol", "hello from carol");

            auto const alice_sync = sync_since(rt, alice, since);
            REQUIRE(alice_sync.response.status == 200U);
            auto const timeline_events = room_timeline_events(alice_sync.response.body, room_id);

            THEN("bob's message is absent and carol's message is present")
            {
                // Spec MUST: no longer receive events sent by an ignored user.
                // Checked structurally (per-event event_id/sender/content.body),
                // not by substring search over the serialized array: carol's
                // event legitimately names bob's event_id in its own
                // "prev_events" DAG-linkage field (ignoring never touches the
                // event graph, only client-facing delivery of bob's own event
                // object), so a raw text search would find bob's event_id even
                // when his event was correctly withheld.
                REQUIRE_FALSE(array_has_event_id(timeline_events, bob_event_id));
                REQUIRE_FALSE(array_has_message_from(timeline_events, "@bob:example.org"));
                REQUIRE_FALSE(array_has_content_field(timeline_events, "body", "hello from bob"));
                // Unignored senders are unaffected.
                REQUIRE(array_has_event_id(timeline_events, carol_event_id));
                REQUIRE(array_has_content_field(timeline_events, "body", "hello from carol"));
            }
        }
    }
}

// Spec MUST (Server behaviour): "Servers must still send state events sent
// by ignored users to clients."
SCENARIO("a state event from an ignored sender is still delivered via /sync, unlike a message from the same sender",
         "[ignoring-users][conformance][sync]")
{
    GIVEN("bob owns a room (so he has permission to change the topic), alice has joined it and ignores bob")
    {
        auto started = merovingian::homeserver::start_client_server(ignoring_users_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room_with_invite(rt, bob, "@alice:example.org");
        join_room(rt, alice, room_id);

        auto const baseline = sync_full(rt, alice);
        REQUIRE(baseline.response.status == 200U);
        auto const since = next_batch_of(baseline.response.body);

        set_ignored_users(rt, alice, "%40alice%3Aexample.org", R"({"ignored_users":{"@bob:example.org":{}}})");

        WHEN("bob (the room owner) changes the topic and also sends a message")
        {
            auto const topic_resp = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic/", bob,
                     R"({"topic":"new topic set by an ignored user"})"});
            REQUIRE(topic_resp.response.status == 200U);
            auto const bob_event_id = send_text_message(rt, bob, room_id, "txn-bob-state", "a message from bob");

            auto const alice_sync = sync_since(rt, alice, since);
            REQUIRE(alice_sync.response.status == 200U);
            auto const timeline_events = room_timeline_events(alice_sync.response.body, room_id);

            THEN("the topic change is present but the message is not")
            {
                REQUIRE(array_has_content_field(timeline_events, "topic", "new topic set by an ignored user"));
                REQUIRE_FALSE(array_has_event_id(timeline_events, bob_event_id));
                REQUIRE_FALSE(array_has_content_field(timeline_events, "body", "a message from bob"));
            }
        }
    }
}

// Spec MUST (Server behaviour): "Servers must not send room invites from
// ignored users to clients."
SCENARIO("a room invite from an ignored user is withheld from /sync, but an invite from an unignored user is not",
         "[ignoring-users][conformance][sync][invites]")
{
    GIVEN("alice has ignored bob, and both bob and carol have rooms to invite her to")
    {
        auto started = merovingian::homeserver::start_client_server(ignoring_users_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");

        set_ignored_users(rt, alice, "%40alice%3Aexample.org", R"({"ignored_users":{"@bob:example.org":{}}})");

        WHEN("bob invites alice to his room and carol invites alice to hers")
        {
            auto const bob_room = create_room_with_invite(rt, bob, "@alice:example.org");
            auto const carol_room = create_room_with_invite(rt, carol, "@alice:example.org");

            auto const alice_sync = sync_full(rt, alice);
            REQUIRE(alice_sync.response.status == 200U);
            auto const invites = invite_room_ids(alice_sync.response.body);

            THEN("bob's room is absent from the invite list and carol's is present")
            {
                REQUIRE(std::ranges::find(invites, bob_room) == invites.end());
                REQUIRE(std::ranges::find(invites, carol_room) != invites.end());
            }
        }
    }
}

// Spec: "To remove a user from the ignored users list, remove them from the
// account data event. The server will resume sending events from the
// previously ignored user" — this proves events sent AFTER un-ignoring flow
// through again; it deliberately does not assert anything about events sent
// while the user was ignored, per the spec's "it should not send events that
// were missed while the user was ignored. To receive the events that were
// sent while the user was ignored the client should perform a fresh sync."
SCENARIO("un-ignoring a user restores delivery of events that user sends afterward",
         "[ignoring-users][conformance][sync]")
{
    GIVEN("alice ignored bob, then removes him from her ignore list")
    {
        auto started = merovingian::homeserver::start_client_server(ignoring_users_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room_with_invite(rt, alice, "@bob:example.org");
        join_room(rt, bob, room_id);

        set_ignored_users(rt, alice, "%40alice%3Aexample.org", R"({"ignored_users":{"@bob:example.org":{}}})");
        auto const baseline = sync_full(rt, alice);
        REQUIRE(baseline.response.status == 200U);
        auto const since = next_batch_of(baseline.response.body);

        // Un-ignore: an empty ignored_users map.
        set_ignored_users(rt, alice, "%40alice%3Aexample.org", R"({"ignored_users":{}})");

        WHEN("bob sends a message after being un-ignored")
        {
            auto const bob_event_id = send_text_message(rt, bob, room_id, "txn-unignored", "hello again from bob");

            auto const alice_sync = sync_since(rt, alice, since);
            REQUIRE(alice_sync.response.status == 200U);
            auto const timeline_events = room_timeline_events(alice_sync.response.body, room_id);

            THEN("the message is delivered normally")
            {
                REQUIRE(array_has_event_id(timeline_events, bob_event_id));
                REQUIRE(array_has_content_field(timeline_events, "body", "hello again from bob"));
            }
        }
    }
}

// Design constraint: "Fail safe: a malformed or absent m.ignored_user_list
// must behave as 'nothing ignored' and must never throw or drop legitimate
// events."
SCENARIO("a malformed m.ignored_user_list is treated as empty rather than blocking delivery",
         "[ignoring-users][conformance][sync][security]")
{
    GIVEN("alice has stored a non-JSON m.ignored_user_list account-data body")
    {
        auto started = merovingian::homeserver::start_client_server(ignoring_users_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room_with_invite(rt, alice, "@bob:example.org");
        join_room(rt, bob, room_id);

        auto const baseline = sync_full(rt, alice);
        REQUIRE(baseline.response.status == 200U);
        auto const since = next_batch_of(baseline.response.body);

        set_malformed_ignored_users(rt, alice, "%40alice%3Aexample.org");

        WHEN("bob sends a message and alice syncs")
        {
            auto const bob_event_id =
                send_text_message(rt, bob, room_id, "txn-malformed", "hello despite malformed list");

            auto const alice_sync = sync_since(rt, alice, since);
            REQUIRE(alice_sync.response.status == 200U);
            auto const timeline_events = room_timeline_events(alice_sync.response.body, room_id);

            THEN("the message is delivered as if nothing were ignored, and the request did not fail")
            {
                REQUIRE(array_has_event_id(timeline_events, bob_event_id));
            }
        }
    }
}

// ── GET /messages ────────────────────────────────────────────────────────

SCENARIO("GET /messages omits messages from an ignored sender", "[ignoring-users][conformance][messages]")
{
    GIVEN("alice has ignored bob, and both bob and carol have sent messages in a shared room")
    {
        auto started = merovingian::homeserver::start_client_server(ignoring_users_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room_with_invite(rt, alice, "@bob:example.org");
        join_room(rt, bob, room_id);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                         R"({"user_id":"@carol:example.org"})"})
                    .response.status == 200U);
        join_room(rt, carol, room_id);

        set_ignored_users(rt, alice, "%40alice%3Aexample.org", R"({"ignored_users":{"@bob:example.org":{}}})");

        auto const bob_event_id = send_text_message(rt, bob, room_id, "txn-messages-bob", "bob says hi");
        auto const carol_event_id = send_text_message(rt, carol, room_id, "txn-messages-carol", "carol says hi");

        WHEN("alice calls GET /messages")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=20", alice, {}});
            REQUIRE(resp.response.status == 200U);

            THEN("bob's message is absent from the chunk and carol's is present")
            {
                // Structural check (see room_timeline_events' comment): carol's
                // message legitimately names bob's event_id in its own
                // "prev_events" field, so a raw body substring search would
                // find it even when bob's event object was correctly omitted.
                auto const body = parse_object(resp.response.body);
                auto const* chunk = object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
                REQUIRE_FALSE(array_has_event_id(*chunk, bob_event_id));
                REQUIRE_FALSE(array_has_message_from(*chunk, "@bob:example.org"));
                REQUIRE(array_has_event_id(*chunk, carol_event_id));
            }
        }
    }
}

// ── GET /context/{eventId} ──────────────────────────────────────────────────

// Judgement call (documented in room_context_json): the requested event
// itself is always returned even if authored by an ignored sender — the
// caller explicitly asked for context around that exact event_id (e.g. a
// permalink) — but events_before/events_after are filtered the same as
// /messages.
SCENARIO("GET /context filters events_before/events_after by the ignore list but always returns the target event",
         "[ignoring-users][conformance][context]")
{
    GIVEN("carol, bob (ignored by alice), and alice in a room with a bob message sandwiched between carol messages")
    {
        auto started = merovingian::homeserver::start_client_server(ignoring_users_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room_with_invite(rt, alice, "@bob:example.org");
        join_room(rt, bob, room_id);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                         R"({"user_id":"@carol:example.org"})"})
                    .response.status == 200U);
        join_room(rt, carol, room_id);

        set_ignored_users(rt, alice, "%40alice%3Aexample.org", R"({"ignored_users":{"@bob:example.org":{}}})");

        auto const carol_before_id = send_text_message(rt, carol, room_id, "txn-ctx-before", "carol before");
        auto const bob_target_id = send_text_message(rt, bob, room_id, "txn-ctx-target", "bob target message");
        auto const bob_after_id = send_text_message(rt, bob, room_id, "txn-ctx-after-bob", "bob after");
        auto const carol_after_id = send_text_message(rt, carol, room_id, "txn-ctx-after-carol", "carol after");

        WHEN("alice requests context around bob's target message")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/context/" + bob_target_id, alice, {}});
            REQUIRE(resp.response.status == 200U);
            auto const body = parse_object(resp.response.body);

            THEN("the target event field is bob's message even though he is ignored")
            {
                auto const* event = object_member_as_object(body, "event");
                REQUIRE(event != nullptr);
                auto const* event_id = string_member(*event, "event_id");
                REQUIRE(event_id != nullptr);
                REQUIRE(*event_id == bob_target_id);
            }

            THEN("events_before contains carol's message but not any from bob")
            {
                auto const* before = object_member_as_array(body, "events_before");
                REQUIRE(before != nullptr);
                REQUIRE(array_has_event_id(*before, carol_before_id));
                REQUIRE_FALSE(array_has_message_from(*before, "@bob:example.org"));
            }

            THEN("events_after contains carol's message but not bob's")
            {
                // Structural check (see room_timeline_events' comment above):
                // carol's after-message legitimately names bob's
                // txn-ctx-after-bob event_id in its own "prev_events" field, so
                // a raw substring search over the serialized array would find
                // bob's event_id even though his event object was correctly
                // withheld.
                auto const* after = object_member_as_array(body, "events_after");
                REQUIRE(after != nullptr);
                REQUIRE(array_has_event_id(*after, carol_after_id));
                REQUIRE_FALSE(array_has_event_id(*after, bob_after_id));
                REQUIRE_FALSE(array_has_message_from(*after, "@bob:example.org"));
            }
        }
    }
}
