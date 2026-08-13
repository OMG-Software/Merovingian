// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            POST /_matrix/client/v3/search — CONFORMANCE                 |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 §Server Side Search               |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#server-side-search |
// |                                                                         |
// |  The most important scenarios here are the access-control ones: search  |
// |  scans every event the caller is joined to across every room, so a      |
// |  membership mistake is a server-wide disclosure rather than a           |
// |  single-room bug. Every "must not appear" assertion is paired with a    |
// |  "must appear" assertion in the same scenario so a vacuously empty      |
// |  result set cannot pass the negative check by accident.                 |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto search_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
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

// Reads a JSON number member as a double regardless of how it round-tripped.
// JSON draws no int/float distinction, and the canonical serializer emits the
// shortest form that round-trips -- so an integral rank such as 1.0 is written
// as `1` and parsed back as an integer. Asserting purely on the double
// alternative would therefore fail for correct integral ranks. Returns nullopt
// when the member is absent or not a number at all.
[[nodiscard]] auto number_member(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> std::optional<double>
{
    if (auto const* as_double = double_member(object, key); as_double != nullptr)
    {
        return *as_double;
    }
    if (auto const* as_int = int_member(object, key); as_int != nullptr)
    {
        return static_cast<double>(*as_int);
    }
    return std::nullopt;
}

// Creates a room with `preset` and optionally invites `invitee_user_id`
// (does not join them). `preset == "private_chat"` auto-enables
// m.room.encryption (see room_service.cpp); `preset == "public_chat"` never
// does.
[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& rt, std::string const& owner_token,
                               std::string const& preset, std::string const& invitee_user_id = {}) -> std::string
{
    auto body = std::string{"{\"preset\":\""} + preset + "\"";
    if (!invitee_user_id.empty())
    {
        body += ",\"invite\":[\"" + invitee_user_id + "\"]";
    }
    body += "}";
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"POST", "/_matrix/client/v3/createRoom", owner_token, body});
    REQUIRE(resp.response.status == 200U);
    auto const parsed = parse_object(resp.response.body);
    auto const* room_id = string_member(parsed, "room_id");
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
             "{\"msgtype\":\"m.text\",\"body\":\"" + body + "\"}"});
    REQUIRE(resp.response.status == 200U);
    auto const parsed = parse_object(resp.response.body);
    auto const* event_id = string_member(parsed, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

auto set_ignored_users(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                       std::string const& percent_encoded_user_id, std::string const& ignored_users_body) -> void
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"PUT", "/_matrix/client/v3/user/" + percent_encoded_user_id + "/account_data/m.ignored_user_list", token,
             ignored_users_body});
    REQUIRE(resp.response.status == 200U);
}

// POSTs /search and returns the raw DispatchResult, for scenarios that need
// to inspect the status code themselves (unauthenticated / malformed body).
[[nodiscard]] auto raw_search(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                              std::string const& request_body, std::string const& query = {})
    -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        rt, {"POST", "/_matrix/client/v3/search" + query, token, request_body});
}

// POSTs /search, requires 200, and returns the parsed
// `search_categories.room_events` object.
[[nodiscard]] auto search(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                          std::string const& request_body, std::string const& query = {})
    -> merovingian::canonicaljson::Object
{
    auto const resp = raw_search(rt, token, request_body, query);
    REQUIRE(resp.response.status == 200U);
    auto const body = parse_object(resp.response.body);
    auto const* categories = object_member_as_object(body, "search_categories");
    REQUIRE(categories != nullptr);
    auto const* room_events = object_member_as_object(*categories, "room_events");
    REQUIRE(room_events != nullptr);
    return *room_events;
}

// Builds a minimal request body: {"search_categories":{"room_events":{"search_term":"<term>"[,<extra>]}}}
[[nodiscard]] auto body_for_term(std::string const& term, std::string const& extra_fields = {}) -> std::string
{
    auto out = std::string{"{\"search_categories\":{\"room_events\":{\"search_term\":\""} + term + "\"";
    if (!extra_fields.empty())
    {
        out += "," + extra_fields;
    }
    out += "}}}";
    return out;
}

// True when some element of `results` (the `results` array from a search
// response) is a result for `event_id`. Checked via the element's own
// `result.event_id` field, never a substring search over serialized JSON —
// prev_events/auth_events on a *different*, legitimately-returned event can
// quote a suppressed event's id verbatim.
[[nodiscard]] auto results_contain_event(merovingian::canonicaljson::Array const& results, std::string const& event_id)
    -> bool
{
    return std::ranges::any_of(results, [&](merovingian::canonicaljson::Value const& entry) {
        auto const* entry_obj = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        auto const* result_obj = entry_obj != nullptr ? object_member_as_object(*entry_obj, "result") : nullptr;
        auto const* id = result_obj != nullptr ? string_member(*result_obj, "event_id") : nullptr;
        return id != nullptr && *id == event_id;
    });
}

[[nodiscard]] auto find_result(merovingian::canonicaljson::Array const& results, std::string const& event_id)
    -> merovingian::canonicaljson::Object const*
{
    for (auto const& entry : results)
    {
        auto const* entry_obj = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        auto const* result_obj = entry_obj != nullptr ? object_member_as_object(*entry_obj, "result") : nullptr;
        auto const* id = result_obj != nullptr ? string_member(*result_obj, "event_id") : nullptr;
        if (id != nullptr && *id == event_id)
        {
            return entry_obj;
        }
    }
    return nullptr;
}

} // namespace

// ── Basic match shape ───────────────────────────────────────────────────────

// Spec MUST: a search result carries `rank`, `result` (the matched
// ClientEvent, with its required event_id/type/sender/room_id/content
// fields), and `context`.
SCENARIO("a matching event is returned with rank, result, and context fields", "[search][conformance]")
{
    GIVEN("alice has sent a message in her own room")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, alice, "public_chat");
        auto const event_id = send_text_message(rt, alice, room_id, "txn-basic", "the quick brown fox");

        WHEN("alice searches for a word that appears in the message")
        {
            auto const room_events = search(rt, alice, body_for_term("quick"));

            THEN("count is 1 and the result carries the spec-required fields")
            {
                auto const* count = int_member(room_events, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 1); // Spec: "approximate count of the total number of results found"

                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results->size() == 1U);

                auto const* result_entry = find_result(*results, event_id);
                REQUIRE(result_entry != nullptr); // Spec: "result: The event that matched."

                auto const rank = number_member(*result_entry, "rank");
                REQUIRE(rank.has_value()); // Spec: rank is a "number"
                REQUIRE(*rank > 0.0);      // Spec: "Higher is closer."

                auto const* result_obj = object_member_as_object(*result_entry, "result");
                REQUIRE(result_obj != nullptr);
                auto const* type = string_member(*result_obj, "type");
                REQUIRE(type != nullptr);
                REQUIRE(*type == "m.room.message");
                auto const* sender = string_member(*result_obj, "sender");
                REQUIRE(sender != nullptr);
                REQUIRE(*sender == "@alice:example.org");
                auto const* returned_room_id = string_member(*result_obj, "room_id");
                REQUIRE(returned_room_id != nullptr);
                REQUIRE(*returned_room_id == room_id);

                auto const* context = object_member_as_object(*result_entry, "context");
                REQUIRE(context != nullptr); // Spec: "context: Context for result, if requested."
                REQUIRE(object_member_as_array(*context, "events_before") != nullptr);
                REQUIRE(object_member_as_array(*context, "events_after") != nullptr);
                REQUIRE(string_member(*context, "start") != nullptr);
                REQUIRE(string_member(*context, "end") != nullptr);
            }
        }

        WHEN("alice searches for a term that appears nowhere")
        {
            auto const room_events = search(rt, alice, body_for_term("giraffeunicorn"));

            THEN("no results are returned and count is zero")
            {
                auto const* count = int_member(room_events, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 0);
                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results->empty());
                REQUIRE(object_member(room_events, "next_batch") == nullptr); // Spec: absent when no more results
            }
        }
    }
}

// Spec MUST: "An approximate count of the total number of results found."
SCENARIO("count reflects the number of matching events found", "[search][conformance]")
{
    GIVEN("a room with three matching messages and two non-matching ones")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, alice, "public_chat");
        std::ignore = send_text_message(rt, alice, room_id, "txn-c1", "irrelevant message one");
        auto const id_a = send_text_message(rt, alice, room_id, "txn-c2", "banana split please");
        std::ignore = send_text_message(rt, alice, room_id, "txn-c3", "irrelevant message two");
        auto const id_b = send_text_message(rt, alice, room_id, "txn-c4", "another banana story");
        auto const id_c = send_text_message(rt, alice, room_id, "txn-c5", "banana bread recipe");

        WHEN("alice searches for the common word")
        {
            auto const room_events = search(rt, alice, body_for_term("banana"));

            THEN("count is exactly 3 and all three matching events are present")
            {
                auto const* count = int_member(room_events, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 3);
                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results->size() == 3U);
                REQUIRE(results_contain_event(*results, id_a));
                REQUIRE(results_contain_event(*results, id_b));
                REQUIRE(results_contain_event(*results, id_c));
            }
        }
    }
}

// ── Access control ──────────────────────────────────────────────────────────

// The most important scenario in this file: search must never surface an
// event from a room the caller is not joined to, even when the term matches
// perfectly. Paired with a positive assertion (alice's own matching event IS
// found) so an implementation bug that made search return nothing at all
// could not pass this scenario by accident.
SCENARIO("search never returns an event from a room the caller is not a member of", "[search][conformance][security]")
{
    GIVEN("alice and bob each have their own room, and alice is not a member of bob's room")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const alice_room = create_room(rt, alice, "public_chat");
        auto const bob_room = create_room(rt, bob, "public_chat");

        auto const alice_event =
            send_text_message(rt, alice, alice_room, "txn-alice-secret", "the topsecretword is safe here");
        auto const bob_event = send_text_message(rt, bob, bob_room, "txn-bob-secret", "the topsecretword leaks here");

        WHEN("alice searches for the shared term")
        {
            auto const room_events = search(rt, alice, body_for_term("topsecretword"));

            THEN("only alice's own event is returned; bob's event from the room she is not in is absent")
            {
                auto const* count = int_member(room_events, "count");
                REQUIRE(count != nullptr);
                REQUIRE(*count == 1); // Spec: "Only events that the user is allowed to see will be searched."

                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results_contain_event(*results, alice_event)); // positive counterpart
                REQUIRE_FALSE(results_contain_event(*results, bob_event));
            }
        }
    }
}

// Spec: "The search will not include rooms that are end to end encrypted."
SCENARIO("search excludes events from end-to-end encrypted rooms", "[search][conformance][security]")
{
    GIVEN("alice has a plaintext room and an encrypted room, both with a matching message")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const plain_room = create_room(rt, alice, "public_chat");
        auto const encrypted_room = create_room(rt, alice, "private_chat"); // auto-enables m.room.encryption

        auto const plain_event =
            send_text_message(rt, alice, plain_room, "txn-plain", "the encryptedword appears here too");
        auto const encrypted_event =
            send_text_message(rt, alice, encrypted_room, "txn-encrypted", "the encryptedword appears here");

        WHEN("alice searches for the shared term")
        {
            auto const room_events = search(rt, alice, body_for_term("encryptedword"));

            THEN("only the plaintext room's event is returned")
            {
                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results_contain_event(*results, plain_event)); // positive counterpart
                REQUIRE_FALSE(results_contain_event(*results, encrypted_event));
            }
        }
    }
}

// Spec: "Servers must not send events sent by ignored users to clients"
// (Ignoring Users module); search reuses the same
// merovingian::trust_safety::ignore_list suppression /messages and /context
// already apply.
SCENARIO("search never returns an event from an ignored sender", "[search][conformance][security][ignoring-users]")
{
    GIVEN("alice has ignored bob, and both bob and carol send a matching message in a shared room")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice, "public_chat");
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                         "{\"user_id\":\"@bob:example.org\"}"})
                    .response.status == 200U);
        join_room(rt, bob, room_id);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                         "{\"user_id\":\"@carol:example.org\"}"})
                    .response.status == 200U);
        join_room(rt, carol, room_id);

        set_ignored_users(rt, alice, "%40alice%3Aexample.org", "{\"ignored_users\":{\"@bob:example.org\":{}}}");

        auto const bob_event = send_text_message(rt, bob, room_id, "txn-ignored-bob", "the shibboleth is bob's");
        auto const carol_event =
            send_text_message(rt, carol, room_id, "txn-ignored-carol", "the shibboleth is carol's");

        WHEN("alice searches for the shared term")
        {
            auto const room_events = search(rt, alice, body_for_term("shibboleth"));

            THEN("carol's matching event is returned but bob's (ignored) is not")
            {
                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results_contain_event(*results, carol_event)); // positive counterpart
                REQUIRE_FALSE(results_contain_event(*results, bob_event));
            }
        }
    }
}

// ── order_by ────────────────────────────────────────────────────────────────

// Spec: "rank, which returns the most relevant results first" (default) vs.
// "recent, which returns the most recent results first."
SCENARIO("order_by selects rank-first or recency-first ordering", "[search][conformance]")
{
    GIVEN("three messages sent oldest to newest, with the middle one repeating the search term the most")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, alice, "public_chat");
        auto const oldest = send_text_message(rt, alice, room_id, "txn-order-1", "alpha");
        auto const highest_rank = send_text_message(rt, alice, room_id, "txn-order-2", "alpha alpha alpha");
        auto const newest = send_text_message(rt, alice, room_id, "txn-order-3", "alpha alpha");
        std::ignore = oldest;

        WHEN("alice searches with the default order (rank)")
        {
            auto const room_events = search(rt, alice, body_for_term("alpha"));

            THEN("the highest-rank message (three occurrences) is first")
            {
                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results->size() == 3U);
                auto const* first = std::get_if<merovingian::canonicaljson::Object>(&(*results)[0].storage());
                REQUIRE(first != nullptr);
                auto const* first_result = object_member_as_object(*first, "result");
                REQUIRE(first_result != nullptr);
                auto const* first_id = string_member(*first_result, "event_id");
                REQUIRE(first_id != nullptr);
                REQUIRE(*first_id == highest_rank);
            }
        }

        WHEN("alice searches with order_by=recent")
        {
            auto const room_events = search(rt, alice, body_for_term("alpha", "\"order_by\":\"recent\""));

            THEN("the most recently sent message is first")
            {
                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results->size() == 3U);
                auto const* first = std::get_if<merovingian::canonicaljson::Object>(&(*results)[0].storage());
                REQUIRE(first != nullptr);
                auto const* first_result = object_member_as_object(*first, "result");
                REQUIRE(first_result != nullptr);
                auto const* first_id = string_member(*first_result, "event_id");
                REQUIRE(first_id != nullptr);
                REQUIRE(*first_id == newest);
            }
        }
    }
}

// ── event_context ────────────────────────────────────────────────────────────

// Spec: event_context.before_limit/after_limit bound events_before/events_after.
SCENARIO("event_context honours before_limit and after_limit", "[search][conformance]")
{
    GIVEN("five messages in a room, with the middle one matching the search term")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, alice, "public_chat");
        auto const id1 = send_text_message(rt, alice, room_id, "txn-ctx-1", "context one");
        auto const id2 = send_text_message(rt, alice, room_id, "txn-ctx-2", "context two");
        auto const target = send_text_message(rt, alice, room_id, "txn-ctx-3", "the quasar target message");
        auto const id4 = send_text_message(rt, alice, room_id, "txn-ctx-4", "context four");
        auto const id5 = send_text_message(rt, alice, room_id, "txn-ctx-5", "context five");
        std::ignore = id1;
        std::ignore = id5;

        WHEN("alice searches with before_limit=1, after_limit=1")
        {
            auto const room_events =
                search(rt, alice, body_for_term("quasar", "\"event_context\":{\"before_limit\":1,\"after_limit\":1}"));

            THEN("events_before contains exactly the immediately preceding message and events_after the following one")
            {
                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                auto const* entry = find_result(*results, target);
                REQUIRE(entry != nullptr);
                auto const* context = object_member_as_object(*entry, "context");
                REQUIRE(context != nullptr);

                auto const* before = object_member_as_array(*context, "events_before");
                REQUIRE(before != nullptr);
                REQUIRE(before->size() == 1U);
                auto const* before_obj = std::get_if<merovingian::canonicaljson::Object>(&(*before)[0].storage());
                REQUIRE(before_obj != nullptr);
                auto const* before_id = string_member(*before_obj, "event_id");
                REQUIRE(before_id != nullptr);
                REQUIRE(*before_id == id2); // the message immediately before the target, not id1

                auto const* after = object_member_as_array(*context, "events_after");
                REQUIRE(after != nullptr);
                REQUIRE(after->size() == 1U);
                auto const* after_obj = std::get_if<merovingian::canonicaljson::Object>(&(*after)[0].storage());
                REQUIRE(after_obj != nullptr);
                auto const* after_id = string_member(*after_obj, "event_id");
                REQUIRE(after_id != nullptr);
                REQUIRE(*after_id == id4); // the message immediately after the target, not id5
            }
        }
    }
}

// ── Pagination ───────────────────────────────────────────────────────────────

// Spec: "the client should send the same request ... with a next_batch query
// parameter." No result should be skipped (a gap) or repeated (an overlap)
// across the full page sequence.
SCENARIO("pagination via next_batch returns each matching event exactly once", "[search][conformance]")
{
    GIVEN("five matching messages and a page size of two, ordered by recency for a deterministic sequence")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, alice, "public_chat");
        auto ids = std::vector<std::string>{};
        for (auto i = 1; i <= 5; ++i)
        {
            ids.push_back(send_text_message(rt, alice, room_id, "txn-page-" + std::to_string(i),
                                            "needle number " + std::to_string(i)));
        }

        WHEN("alice pages through with limit=2, order_by=recent")
        {
            auto const extra = std::string{"\"order_by\":\"recent\",\"filter\":{\"limit\":2}"};
            auto const request_body = body_for_term("needle", extra);

            auto collected = std::vector<std::string>{};
            auto query = std::string{};
            auto pages = 0;
            for (; pages < 10; ++pages)
            {
                auto const room_events = search(rt, alice, request_body, query);
                auto const* results = object_member_as_array(room_events, "results");
                REQUIRE(results != nullptr);
                for (auto const& entry : *results)
                {
                    auto const* entry_obj = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
                    REQUIRE(entry_obj != nullptr);
                    auto const* result_obj = object_member_as_object(*entry_obj, "result");
                    REQUIRE(result_obj != nullptr);
                    auto const* id = string_member(*result_obj, "event_id");
                    REQUIRE(id != nullptr);
                    collected.push_back(*id);
                }
                auto const* next_batch = string_member(room_events, "next_batch");
                if (next_batch == nullptr)
                {
                    break;
                }
                query = "?next_batch=" + *next_batch;
            }

            THEN("every matching event was returned exactly once, with no gap or overlap")
            {
                REQUIRE(collected.size() == ids.size());
                for (auto const& id : ids)
                {
                    REQUIRE(std::ranges::count(collected, id) == 1);
                }
            }
        }
    }
}

// ── Request validation ──────────────────────────────────────────────────────

// Spec: "Requires authentication: Yes"
SCENARIO("unauthenticated search is rejected", "[search][conformance]")
{
    GIVEN("no access token")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a search request is made without a token")
        {
            auto const resp = raw_search(rt, {}, body_for_term("anything"));

            THEN("the server responds 401")
            {
                REQUIRE(resp.response.status == 401U); // Spec §5.7.2: missing token
            }
        }
    }
}

// Spec: "400: Part of the request was invalid."
SCENARIO("a malformed search body is rejected", "[search][conformance]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(search_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");

        WHEN("search_categories is missing entirely")
        {
            auto const resp = raw_search(rt, alice, "{}");

            THEN("the server responds 400")
            {
                REQUIRE(resp.response.status == 400U);
            }
        }

        WHEN("search_categories.room_events.search_term is missing")
        {
            auto const resp =
                raw_search(rt, alice, "{\"search_categories\":{\"room_events\":{\"keys\":[\"content.body\"]}}}");

            THEN("the server responds 400")
            {
                REQUIRE(resp.response.status == 400U); // Spec: search_term is Required
            }
        }
    }
}
