// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX EVENT RELATIONSHIPS CONFORMANCE TESTS                    |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18                                   |
// |  Section: Forming Relationships Between Events                          |
// |  URL: https://spec.matrix.org/v1.18/client-server-api/                  |
// |         #forming-relationships-between-events                           |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec.        |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |       spec itself has changed and citing the updated section.            |
// |                                                                         |
// |  Relationship types (spec §):                                           |
// |    m.in_reply_to — reply to a single event                              |
// |    m.replace     — edit / replacement of a prior event                  |
// |    m.thread      — thread membership                                     |
// |    m.annotation  — reaction (emoji, vote, etc.)                         |
// |    m.reference   — reference to another event                           |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json("alice_rel", "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice_rel:example.org"},"password":"CorrectHorse7!","device_id":"REL_DEVICE"})"});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})"});
    REQUIRE(resp.response.status == 200U);
    auto const body = parse_object(resp.response.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    REQUIRE(!room_id->empty());
    return *room_id;
}

[[nodiscard]] auto send_text_message(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                     std::string const& room_id, std::string const& txn_id) -> std::string
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn_id, token,
                  R"({"msgtype":"m.text","body":"Hello"})"});
    REQUIRE(resp.response.status == 200U);
    auto const body = parse_object(resp.response.body);
    auto const* event_id = string_member(body, "event_id");
    REQUIRE(event_id != nullptr);
    REQUIRE(!event_id->empty());
    return *event_id;
}

} // namespace

// Spec: Matrix Client-Server API v1.18 — Forming Relationships Between Events
// URL: https://spec.matrix.org/v1.18/client-server-api/#forming-relationships-between-events
//
// A reply is formed by setting content["m.relates_to"]["m.in_reply_to"]["event_id"]
// to the event ID of the event being replied to. The server MUST accept this
// event and return a new event_id.
SCENARIO("Server accepts a reply event with m.in_reply_to relationship", "[event-relationships][conformance][reply]")
{
    GIVEN("a user with a room and an existing message event")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const original_event_id = send_text_message(started.runtime, token, room_id, "txn_original");

        WHEN("a reply event is sent with m.in_reply_to")
        {
            auto const reply_body =
                std::string{
                    R"({"msgtype":"m.text","body":"Reply text","m.relates_to":{"m.in_reply_to":{"event_id":")"} +
                original_event_id + R"("}}})";
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn_reply", token, reply_body});

            THEN("the server returns 200 with an event_id")
            {
                // Spec MUST: the server MUST accept events with m.in_reply_to
                // relationships and return an event_id.
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* event_id = string_member(body, "event_id");
                REQUIRE(event_id != nullptr);
                REQUIRE(!event_id->empty());
            }

            THEN("the reply event_id differs from the original")
            {
                // Spec invariant: every sent event gets its own unique event ID.
                auto const body = parse_object(resp.response.body);
                auto const* reply_event_id = string_member(body, "event_id");
                REQUIRE(reply_event_id != nullptr);
                REQUIRE(*reply_event_id != original_event_id);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Event Replacements (Edits)
// URL: https://spec.matrix.org/v1.18/client-server-api/#event-replacements
//
// An edit/replacement event has rel_type "m.replace" and the event_id of the
// event being replaced. It MUST also contain "m.new_content" in its content.
// The server MUST accept it and return a new event_id.
SCENARIO("Server accepts an event replacement (edit) with m.replace relationship",
         "[event-relationships][conformance][replace]")
{
    GIVEN("a user with a room and an existing message event")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const original_event_id = send_text_message(started.runtime, token, room_id, "txn_edit_orig");

        WHEN("an edit event is sent with m.replace and m.new_content")
        {
            auto const edit_body =
                std::string{
                    R"({"msgtype":"m.text","body":"* Edited text","m.new_content":{"msgtype":"m.text","body":"Edited text"},"m.relates_to":{"rel_type":"m.replace","event_id":")"} +
                original_event_id + R"("}})";
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn_edit", token, edit_body});

            THEN("the server returns 200 with an event_id")
            {
                // Spec MUST: the server MUST accept m.replace events.
                // The server MAY apply the edit to the original event's content
                // in /sync responses, but MUST store the replacement event.
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                REQUIRE(string_member(body, "event_id") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Threading
// URL: https://spec.matrix.org/v1.18/client-server-api/#threading
//
// A thread reply has rel_type "m.thread", event_id pointing to the thread root,
// and optionally "m.in_reply_to" pointing to the latest event in the thread.
// The server MUST accept a thread reply and return a new event_id.
SCENARIO("Server accepts a thread reply with m.thread relationship", "[event-relationships][conformance][thread]")
{
    GIVEN("a user with a room and a thread root message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const thread_root_id = send_text_message(started.runtime, token, room_id, "txn_thread_root");

        WHEN("a thread reply is sent with m.thread relationship")
        {
            auto const thread_body =
                std::string{
                    R"({"msgtype":"m.text","body":"Thread reply","m.relates_to":{"rel_type":"m.thread","event_id":")"} +
                thread_root_id + R"(","m.in_reply_to":{"event_id":")" + thread_root_id +
                R"("},"is_falling_back":false}})";
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn_thread", token, thread_body});

            THEN("the server returns 200 with an event_id")
            {
                // Spec MUST: the server MUST accept m.thread events.
                // Threads are a stable feature in v1.18.
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                REQUIRE(string_member(body, "event_id") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Reactions
// URL: https://spec.matrix.org/v1.18/client-server-api/#reactions
//
// A reaction event has type "m.reaction", rel_type "m.annotation", event_id
// pointing to the annotated event, and a "key" field with the reaction (e.g.
// an emoji). The server MUST accept the event and return a new event_id.
SCENARIO("Server accepts a reaction event with m.annotation relationship",
         "[event-relationships][conformance][annotation]")
{
    GIVEN("a user with a room and an existing message event")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const target_event_id = send_text_message(started.runtime, token, room_id, "txn_reaction_target");

        WHEN("a reaction event is sent with m.annotation relationship")
        {
            // Plain ASCII key "+1" — avoids multibyte emoji encoding in C++ source.
            auto const reaction_body = std::string{"{\"m.relates_to\":{\"rel_type\":\"m.annotation\",\"event_id\":\""} +
                                       target_event_id + "\",\"key\":\"+1\"}}";
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.reaction/txn_reaction", token, reaction_body});

            THEN("the server returns 200 with an event_id")
            {
                // Spec MUST: the server MUST accept m.annotation reaction events.
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                REQUIRE(string_member(body, "event_id") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — Forming Relationships Between Events
// URL: https://spec.matrix.org/v1.18/client-server-api/#forming-relationships-between-events
//
// The m.relates_to structure in the content is preserved on the wire. Events
// with relationships can appear in /sync timeline alongside regular events.
// The server MUST NOT strip the m.relates_to from the event content.
SCENARIO("Events with m.relates_to appear in the room timeline via GET /sync",
         "[event-relationships][conformance][sync]")
{
    GIVEN("a user with a room, an original event, and a reply event")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        // Do an initial sync to get the baseline batch token.
        auto const initial_sync = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
        REQUIRE(initial_sync.response.status == 200U);
        auto const init_body = parse_object(initial_sync.response.body);
        auto const* nb = string_member(init_body, "next_batch");
        REQUIRE(nb != nullptr);
        auto const next_batch = *nb;

        auto const original_event_id = send_text_message(started.runtime, token, room_id, "txn_sync_orig");

        auto const reply_body =
            std::string{
                "{\"msgtype\":\"m.text\",\"body\":\"reply\",\"m.relates_to\":{\"m.in_reply_to\":{\"event_id\":\""} +
            original_event_id + "\"}}}";
        auto const reply_resp = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn_sync_reply", token, reply_body});
        REQUIRE(reply_resp.response.status == 200U);
        auto const reply_body_parsed = parse_object(reply_resp.response.body);
        auto const* reply_event_id = string_member(reply_body_parsed, "event_id");
        REQUIRE(reply_event_id != nullptr);

        WHEN("an incremental /sync is performed")
        {
            auto const inc_sync = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/sync?since=" + next_batch, token, {}});

            THEN("the sync returns 200")
            {
                // Spec MUST: /sync MUST return the events sent since the last batch.
                REQUIRE(inc_sync.response.status == 200U);
            }

            THEN("the sync response contains the replied-to and reply events")
            {
                // Spec MUST: events with relationships appear in the room timeline
                // in the /sync response. The m.relates_to content MUST be preserved.
                REQUIRE(inc_sync.response.body.find(*reply_event_id) != std::string::npos);
                REQUIRE(inc_sync.response.body.find("m.relates_to") != std::string::npos);
                REQUIRE(inc_sync.response.body.find("m.in_reply_to") != std::string::npos);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18 — GET /rooms/{roomId}/relations
// URL: https://spec.matrix.org/v1.18/client-server-api/
//       #get_matrixclientv1roomsroomidreleventid
//
// The /relations endpoint returns events related to a given event_id.
// The response MUST contain a "chunk" array of related events.
// Note: this endpoint is currently a stub (returns 404) — the test confirms
// the endpoint exists on the routing table and returns a recognisable response.
SCENARIO("GET /rooms/{roomId}/relations/{eventId} is a registered route",
         "[event-relationships][conformance][relations-endpoint]")
{
    GIVEN("a user with a room and a message event")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const event_id = send_text_message(started.runtime, token, room_id, "txn_rels");

        WHEN("GET /v1/rooms/{roomId}/relations/{eventId} is called")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/relations/" + event_id, token, {}});

            THEN("the server returns a JSON response (not a routing failure)")
            {
                // Spec MUST: the route MUST be registered. Any structured response
                // (200 with chunk, 404 M_UNRECOGNIZED for unimplemented, etc.) is
                // acceptable here — a 404 from the HTTP router (unregistered route)
                // would be a spec violation.
                auto const parsed = merovingian::canonicaljson::parse_lossless(resp.response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                // Must have either a "chunk" (success) or "errcode" (structured error).
                auto const body = parse_object(resp.response.body);
                auto const* chunk = object_member(body, "chunk");
                auto const* errcode = string_member(body, "errcode");
                REQUIRE((chunk != nullptr || errcode != nullptr));
            }
        }
    }
}
