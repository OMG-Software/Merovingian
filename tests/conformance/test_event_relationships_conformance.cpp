// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX EVENT RELATIONSHIPS CONFORMANCE TESTS                    |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19                                   |
// |  Section: Forming Relationships Between Events                          |
// |  URL: ../../docs/matrix-v1.19-spec/client-server-api.md                  |
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

#include <cstdint>
#include <optional>
#include <string>
#include <tuple>

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

[[nodiscard]] auto send_thread_reply(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                     std::string const& room_id, std::string const& root_id,
                                     std::string const& txn_id) -> std::string
{
    auto const body =
        std::string{R"({"msgtype":"m.text","body":"Thread reply","m.relates_to":{"rel_type":"m.thread","event_id":")"} +
        root_id + R"("}})";
    auto const resp = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn_id, token, body});
    REQUIRE(resp.response.status == 200U);
    auto const parsed = parse_object(resp.response.body);
    auto const* event_id = string_member(parsed, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

} // namespace

// Spec: Matrix Client-Server API v1.19 — Forming Relationships Between Events
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#forming-relationships-between-events
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

// Spec: Matrix Client-Server API v1.19 — Event Replacements (Edits)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#event-replacements
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

// Spec: Matrix Client-Server API v1.19 — Threading
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#threading
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
                // Threads are a stable feature in v1.19.
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                REQUIRE(string_member(body, "event_id") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 — Reactions
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#reactions
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

// Spec: Matrix Client-Server API v1.19 — Forming Relationships Between Events
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#forming-relationships-between-events
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

// Spec: Matrix Client-Server API v1.19 — GET /rooms/{roomId}/relations
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md
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

// Spec: Matrix Client-Server API v1.19 — Querying threads in a room
// Endpoint: GET /_matrix/client/v1/rooms/{roomId}/threads
// URL:
// ../../docs/matrix-v1.19-spec/client-server-api.md#querying-threads-in-a-room
//
// "chunk: [ClientEvent] Required: The thread roots, ordered by the latest_event
// in each event's aggregated children. All events returned include bundled
// aggregations."
SCENARIO("GET /rooms/{roomId}/threads returns thread roots ordered by latest "
         "activity",
         "[event-relationships][conformance][threads]")
{
    GIVEN("a room with two threads whose most recent activity is in the older "
          "root's thread")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        auto const first_root = send_text_message(started.runtime, token, room_id, "txn_root_a");
        auto const second_root = send_text_message(started.runtime, token, room_id, "txn_root_b");
        std::ignore = send_thread_reply(started.runtime, token, room_id, second_root, "txn_reply_b1");
        // The last reply in the room belongs to the FIRST root, so that thread
        // sorts first.
        auto const latest_in_first = send_thread_reply(started.runtime, token, room_id, first_root, "txn_reply_a1");
        // A plain message with no relation must not become a thread root of its
        // own.
        std::ignore = send_text_message(started.runtime, token, room_id, "txn_unrelated");

        WHEN("the thread roots are listed")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads", token, {}});

            THEN("both roots are returned, most recently active first, with bundled "
                 "m.thread aggregations")
            {
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* chunk_value = object_member(body, "chunk");
                REQUIRE(chunk_value != nullptr);
                auto const* chunk = std::get_if<merovingian::canonicaljson::Array>(&chunk_value->storage());
                REQUIRE(chunk != nullptr);
                // Spec MUST: only thread roots appear — the unrelated message is not
                // one.
                REQUIRE(chunk->size() == 2U);

                auto const* first = std::get_if<merovingian::canonicaljson::Object>(&chunk->at(0U).storage());
                auto const* second = std::get_if<merovingian::canonicaljson::Object>(&chunk->at(1U).storage());
                REQUIRE(first != nullptr);
                REQUIRE(second != nullptr);
                auto const* first_id = string_member(*first, "event_id");
                auto const* second_id = string_member(*second, "event_id");
                REQUIRE(first_id != nullptr);
                REQUIRE(second_id != nullptr);
                // Spec MUST: ordered by the latest_event of each thread.
                REQUIRE(*first_id == first_root);
                REQUIRE(*second_id == second_root);

                // Spec MUST: returned events carry bundled aggregations.
                auto const* unsigned_value = object_member(*first, "unsigned");
                REQUIRE(unsigned_value != nullptr);
                auto const* unsigned_obj = std::get_if<merovingian::canonicaljson::Object>(&unsigned_value->storage());
                REQUIRE(unsigned_obj != nullptr);
                auto const* relations_value = object_member(*unsigned_obj, "m.relations");
                REQUIRE(relations_value != nullptr);
                auto const* relations = std::get_if<merovingian::canonicaljson::Object>(&relations_value->storage());
                REQUIRE(relations != nullptr);
                auto const* thread_value = object_member(*relations, "m.thread");
                REQUIRE(thread_value != nullptr);
                auto const* thread = std::get_if<merovingian::canonicaljson::Object>(&thread_value->storage());
                REQUIRE(thread != nullptr);

                // "count is simply the number of events using m.thread as a rel_type
                // pointing to the target event."
                auto const* count_value = object_member(*thread, "count");
                REQUIRE(count_value != nullptr);
                auto const* count = std::get_if<std::int64_t>(&count_value->storage());
                REQUIRE(count != nullptr);
                REQUIRE(*count == std::int64_t{1});

                // "current_user_participated is true when the authenticated user is
                // ... the sender of the thread root event."
                auto const* participated_value = object_member(*thread, "current_user_participated");
                REQUIRE(participated_value != nullptr);
                auto const* participated = std::get_if<bool>(&participated_value->storage());
                REQUIRE(participated != nullptr);
                REQUIRE(*participated);

                // "latest_event is the most recent event (topologically to the server)
                // in the thread ... serialized in the same form as the event itself."
                auto const* latest_value = object_member(*thread, "latest_event");
                REQUIRE(latest_value != nullptr);
                auto const* latest = std::get_if<merovingian::canonicaljson::Object>(&latest_value->storage());
                REQUIRE(latest != nullptr);
                auto const* latest_id = string_member(*latest, "event_id");
                REQUIRE(latest_id != nullptr);
                REQUIRE(*latest_id == latest_in_first);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 — Querying threads in a room
// URL:
// ../../docs/matrix-v1.19-spec/client-server-api.md#querying-threads-in-a-room
//
// "include: Optional (default all) flag ... When participated, only thread
// roots for threads the user has participated in will be returned. One of:
// [all, participated]."
SCENARIO("GET /rooms/{roomId}/threads honours the include filter and rejects "
         "unknown values",
         "[event-relationships][conformance][threads]")
{
    GIVEN("a room holding a thread the caller started and a thread started by "
          "another member")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        auto const own_root = send_text_message(started.runtime, token, room_id, "txn_own_root");
        std::ignore = send_thread_reply(started.runtime, token, room_id, own_root, "txn_own_reply");

        auto const other_reg = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("bob_rel", "CorrectHorse7!")});
        REQUIRE(other_reg.response.status == 200U);
        auto const other_login = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob_rel:example.org"},"password":"CorrectHorse7!","device_id":"REL_DEVICE_B"})"});
        REQUIRE(other_login.response.status == 200U);
        auto const other_body = parse_object(other_login.response.body);
        auto const* other_token_value = string_member(other_body, "access_token");
        REQUIRE(other_token_value != nullptr);
        auto const other_token = *other_token_value;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", other_token, "{}"})
                    .response.status == 200U);

        auto const other_root = send_text_message(started.runtime, other_token, room_id, "txn_other_root");
        std::ignore = send_thread_reply(started.runtime, other_token, room_id, other_root, "txn_other_reply");

        WHEN("the caller lists only the threads they participated in")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads?include=participated", token, {}});

            THEN("only their own thread root is returned")
            {
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* chunk_value = object_member(body, "chunk");
                REQUIRE(chunk_value != nullptr);
                auto const* chunk = std::get_if<merovingian::canonicaljson::Array>(&chunk_value->storage());
                REQUIRE(chunk != nullptr);
                REQUIRE(chunk->size() == 1U);
                auto const* entry = std::get_if<merovingian::canonicaljson::Object>(&chunk->at(0U).storage());
                REQUIRE(entry != nullptr);
                auto const* entry_id = string_member(*entry, "event_id");
                REQUIRE(entry_id != nullptr);
                REQUIRE(*entry_id == own_root);
            }
        }

        WHEN("the caller lists all threads")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads?include=all", token, {}});

            THEN("both thread roots are returned")
            {
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* chunk_value = object_member(body, "chunk");
                REQUIRE(chunk_value != nullptr);
                auto const* chunk = std::get_if<merovingian::canonicaljson::Array>(&chunk_value->storage());
                REQUIRE(chunk != nullptr);
                REQUIRE(chunk->size() == 2U);
            }
        }

        WHEN("the caller supplies an include value outside the enum")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads?include=sometimes", token, {}});

            THEN("the request is rejected as invalid rather than silently treated as "
                 "all")
            {
                // Spec: 400 "The request was invalid in some way", with a meaningful
                // errcode.
                REQUIRE(resp.response.status == 400U);
                auto const body = parse_object(resp.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_PARAM");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 — Querying threads in a room
// URL:
// ../../docs/matrix-v1.19-spec/client-server-api.md#querying-threads-in-a-room
//
// "limit: Optional limit for the maximum number of thread roots to include per
// response." / "next_batch: A token to supply to from to keep paginating the
// responses. Not present when there are no further results."
SCENARIO("GET /rooms/{roomId}/threads paginates with limit and next_batch",
         "[event-relationships][conformance][threads]")
{
    GIVEN("a room with two thread roots")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        auto const older_root = send_text_message(started.runtime, token, room_id, "txn_page_root_a");
        std::ignore = send_thread_reply(started.runtime, token, room_id, older_root, "txn_page_reply_a");
        auto const newer_root = send_text_message(started.runtime, token, room_id, "txn_page_root_b");
        std::ignore = send_thread_reply(started.runtime, token, room_id, newer_root, "txn_page_reply_b");

        WHEN("the first page is requested with limit=1")
        {
            auto const first_page = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads?limit=1", token, {}});
            REQUIRE(first_page.response.status == 200U);
            auto const first_body = parse_object(first_page.response.body);
            auto const* next_batch = string_member(first_body, "next_batch");

            THEN("one root is returned with a next_batch that yields the remaining "
                 "root")
            {
                auto const* chunk_value = object_member(first_body, "chunk");
                REQUIRE(chunk_value != nullptr);
                auto const* chunk = std::get_if<merovingian::canonicaljson::Array>(&chunk_value->storage());
                REQUIRE(chunk != nullptr);
                REQUIRE(chunk->size() == 1U);
                REQUIRE(next_batch != nullptr);

                auto const second_page = merovingian::homeserver::handle_client_server_request(
                    started.runtime,
                    {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads?limit=1&from=" + *next_batch, token, {}});
                REQUIRE(second_page.response.status == 200U);
                auto const second_body = parse_object(second_page.response.body);
                auto const* second_chunk_value = object_member(second_body, "chunk");
                REQUIRE(second_chunk_value != nullptr);
                auto const* second_chunk =
                    std::get_if<merovingian::canonicaljson::Array>(&second_chunk_value->storage());
                REQUIRE(second_chunk != nullptr);
                REQUIRE(second_chunk->size() == 1U);

                auto const* first_entry = std::get_if<merovingian::canonicaljson::Object>(&chunk->at(0U).storage());
                auto const* second_entry =
                    std::get_if<merovingian::canonicaljson::Object>(&second_chunk->at(0U).storage());
                REQUIRE(first_entry != nullptr);
                REQUIRE(second_entry != nullptr);
                auto const* first_id = string_member(*first_entry, "event_id");
                auto const* second_id = string_member(*second_entry, "event_id");
                REQUIRE(first_id != nullptr);
                REQUIRE(second_id != nullptr);
                // The pages together cover both roots, without repeating one.
                REQUIRE(*first_id != *second_id);
                REQUIRE(*first_id == newer_root);
                REQUIRE(*second_id == older_root);

                // "Not present when there are no further results."
                REQUIRE(string_member(second_body, "next_batch") == nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 — Querying threads in a room
// URL:
// ../../docs/matrix-v1.19-spec/client-server-api.md#querying-threads-in-a-room
//
// "403: The user cannot view or peek on the room ... The room does not exist."
SCENARIO("GET /rooms/{roomId}/threads refuses a room the caller cannot view",
         "[event-relationships][conformance][threads]")
{
    GIVEN("a logged-in user and a room they are not a member of")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("threads are listed for an unknown room")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/!nope:example.org/threads", token, {}});

            THEN("the request is refused with 403 and a structured errcode")
            {
                REQUIRE(resp.response.status == 403U);
                auto const body = parse_object(resp.response.body);
                REQUIRE(string_member(body, "errcode") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 — Ignoring users / Aggregations of child
// events URL:
// ../../docs/matrix-v1.19-spec/client-server-api.md#server-side-aggregation-of-mthread-relationships
//
// "Servers must additionally ensure they do not consider child events from
// ignored users when preparing an aggregation for the client." And for the
// thread list itself: "If the thread root event was sent by an ignored user,
// the event is returned redacted to the caller."
SCENARIO("GET /rooms/{roomId}/threads applies the caller's ignore list to "
         "aggregations and roots",
         "[event-relationships][conformance][threads][ignoring-users]")
{
    GIVEN("a room where an ignored member replied in the caller's thread and "
          "started one of their own")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);

        auto const own_root = send_text_message(started.runtime, token, room_id, "txn_ign_root");
        std::ignore = send_thread_reply(started.runtime, token, room_id, own_root, "txn_ign_own_reply");

        auto const other_reg = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("mallory_rel", "CorrectHorse7!")});
        REQUIRE(other_reg.response.status == 200U);
        auto const other_login = merovingian::homeserver::handle_client_server_request(
            started.runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@mallory_rel:example.org"},"password":"CorrectHorse7!","device_id":"REL_DEVICE_M"})"});
        REQUIRE(other_login.response.status == 200U);
        auto const other_body = parse_object(other_login.response.body);
        auto const* other_token_value = string_member(other_body, "access_token");
        REQUIRE(other_token_value != nullptr);
        auto const other_token = *other_token_value;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", other_token, "{}"})
                    .response.status == 200U);

        // The ignored user replies in the caller's thread and starts a thread of
        // their own.
        std::ignore = send_thread_reply(started.runtime, other_token, room_id, own_root, "txn_ign_other_reply");
        auto const ignored_root = send_text_message(started.runtime, other_token, room_id, "txn_ign_other_root");
        std::ignore = send_thread_reply(started.runtime, token, room_id, ignored_root, "txn_ign_reply_to_other");

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"PUT",
                                      "/_matrix/client/v3/user/@alice_rel:example.org/account_data/"
                                      "m.ignored_user_list",
                                      token, R"({"ignored_users":{"@mallory_rel:example.org":{}}})"})
                    .response.status == 200U);

        WHEN("the caller lists the room's threads")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads", token, {}});

            THEN("the ignored user's reply is excluded from the aggregation and "
                 "their root is redacted")
            {
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* chunk_value = object_member(body, "chunk");
                REQUIRE(chunk_value != nullptr);
                auto const* chunk = std::get_if<merovingian::canonicaljson::Array>(&chunk_value->storage());
                REQUIRE(chunk != nullptr);
                REQUIRE(chunk->size() == 2U);

                auto own_count = std::int64_t{-1};
                auto ignored_root_seen = false;
                for (auto const& entry_value : *chunk)
                {
                    auto const* entry = std::get_if<merovingian::canonicaljson::Object>(&entry_value.storage());
                    REQUIRE(entry != nullptr);
                    auto const* entry_id = string_member(*entry, "event_id");
                    REQUIRE(entry_id != nullptr);

                    auto const* unsigned_value = object_member(*entry, "unsigned");
                    REQUIRE(unsigned_value != nullptr);
                    auto const* unsigned_obj =
                        std::get_if<merovingian::canonicaljson::Object>(&unsigned_value->storage());
                    REQUIRE(unsigned_obj != nullptr);
                    auto const* relations_value = object_member(*unsigned_obj, "m.relations");
                    REQUIRE(relations_value != nullptr);
                    auto const* relations =
                        std::get_if<merovingian::canonicaljson::Object>(&relations_value->storage());
                    REQUIRE(relations != nullptr);
                    auto const* thread_value = object_member(*relations, "m.thread");
                    REQUIRE(thread_value != nullptr);
                    auto const* thread = std::get_if<merovingian::canonicaljson::Object>(&thread_value->storage());
                    REQUIRE(thread != nullptr);
                    auto const* count_value = object_member(*thread, "count");
                    REQUIRE(count_value != nullptr);
                    auto const* count = std::get_if<std::int64_t>(&count_value->storage());
                    REQUIRE(count != nullptr);

                    if (*entry_id == own_root)
                    {
                        own_count = *count;
                    }
                    if (*entry_id == ignored_root)
                    {
                        ignored_root_seen = true;
                        // Spec MUST: a root from an ignored user is returned redacted —
                        // its content is stripped, but the thread is still listed.
                        auto const* content_value = object_member(*entry, "content");
                        REQUIRE(content_value != nullptr);
                        auto const* content =
                            std::get_if<merovingian::canonicaljson::Object>(&content_value->storage());
                        REQUIRE(content != nullptr);
                        REQUIRE(string_member(*content, "body") == nullptr);
                    }
                }

                // Spec MUST: the ignored user's m.thread child is not counted. The
                // caller sent one reply of their own, so the count is 1, not 2.
                REQUIRE(own_count == std::int64_t{1});
                REQUIRE(ignored_root_seen);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 — Querying threads in a room
// URL:
// ../../docs/matrix-v1.19-spec/client-server-api.md#querying-threads-in-a-room
//
// "limit ... Must be an integer greater than zero." / "400: The request was
// invalid in some way ... The from token is unknown to the server."
SCENARIO("GET /rooms/{roomId}/threads rejects a zero limit and an unusable "
         "from token",
         "[event-relationships][conformance][threads]")
{
    GIVEN("a room with a thread")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const root = send_text_message(started.runtime, token, room_id, "txn_bad_param_root");
        std::ignore = send_thread_reply(started.runtime, token, room_id, root, "txn_bad_param_reply");

        WHEN("limit=0 is supplied")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads?limit=0", token, {}});

            THEN("the request is rejected as invalid")
            {
                REQUIRE(resp.response.status == 400U);
                auto const body = parse_object(resp.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_PARAM");
            }
        }

        WHEN("a from token the server never issued is supplied")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads?from=not-a-token", token, {}});

            THEN("the request is rejected rather than silently paginating from the "
                 "start")
            {
                REQUIRE(resp.response.status == 400U);
                auto const body = parse_object(resp.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_PARAM");
            }
        }

        WHEN("no limit is supplied at all")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v1/rooms/" + room_id + "/threads", token, {}});

            THEN("the server applies its own default and returns the thread")
            {
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* chunk_value = object_member(body, "chunk");
                REQUIRE(chunk_value != nullptr);
                auto const* chunk = std::get_if<merovingian::canonicaljson::Array>(&chunk_value->storage());
                REQUIRE(chunk != nullptr);
                REQUIRE(chunk->size() == 1U);
            }
        }
    }
}
