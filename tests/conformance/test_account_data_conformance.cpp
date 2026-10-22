// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            CLIENT CONFIG (ACCOUNT DATA) — CONFORMANCE                   |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 §Client Config                    |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#client-config  |
// |                                                                         |
// |  Conformance audit 2026-10-17, R10 (room-scoped account data GET/PUT    |
// |  were absent) and R11 (global account data accepted non-object and     |
// |  malformed JSON). Every refusal scenario also checks that nothing was   |
// |  stored, so a refusal that still wrote the row cannot pass.             |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;
using merovingian::homeserver::LocalHttpResponse;

constexpr auto alice_path = std::string_view{"%40alice%3Aexample.org"};

[[nodiscard]] auto account_data_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               rt, {std::move(method), std::move(target), token, std::move(body)})
        .response;
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    // Fixture: registration must succeed before the user can log in.
    REQUIRE(
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!")).status ==
        200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                 R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})");
    // Fixture: login must succeed so later requests are authenticated.
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    // Fixture: the login response must carry the access token later requests use.
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_public_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    // Fixture: room creation must succeed before room account data is exercised.
    REQUIRE(created.status == 200U);
    auto const body = parse_object(created.body);
    auto const* room_id = string_member(body, "room_id");
    // Fixture: the room-creation response must carry the room ID.
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto global_url(std::string_view user_path, std::string_view type) -> std::string
{
    return "/_matrix/client/v3/user/" + std::string{user_path} + "/account_data/" + std::string{type};
}

[[nodiscard]] auto room_url(std::string_view user_path, std::string_view room_id, std::string_view type) -> std::string
{
    return "/_matrix/client/v3/user/" + std::string{user_path} + "/rooms/" + std::string{room_id} + "/account_data/" +
           std::string{type};
}

[[nodiscard]] auto errcode_of(LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

// The `account_data.events` array /sync returns for `room_id` in rooms.join,
// or an empty array when the room or the section is absent.
[[nodiscard]] auto synced_room_account_data(ClientServerRuntime& rt, std::string const& token,
                                            std::string const& room_id) -> merovingian::canonicaljson::Array
{
    auto const synced = call(rt, "GET", "/_matrix/client/v3/sync", token);
    // Fixture: the sync must succeed for its account data to be read.
    REQUIRE(synced.status == 200U);
    auto const body = parse_object(synced.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* join = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "join");
    auto const* room = join == nullptr ? nullptr : object_member_as_object(*join, room_id);
    auto const* account_data = room == nullptr ? nullptr : object_member_as_object(*room, "account_data");
    auto const* events = account_data == nullptr ? nullptr : object_member_as_array(*account_data, "events");
    return events == nullptr ? merovingian::canonicaljson::Array{} : *events;
}

// The content of the event of `type` in an account-data `events` array, or
// nullptr when there is none.
[[nodiscard]] auto event_content_of_type(merovingian::canonicaljson::Array const& events, std::string_view type)
    -> merovingian::canonicaljson::Object const*
{
    for (auto const& event : events)
    {
        auto const* object = std::get_if<merovingian::canonicaljson::Object>(&event.storage());
        auto const* event_type = object == nullptr ? nullptr : string_member(*object, "type");
        if (event_type != nullptr && *event_type == type)
        {
            return object_member_as_object(*object, "content");
        }
    }
    return nullptr;
}

} // namespace

// =============================================================================
// R11 — global account data must be a JSON object
// =============================================================================

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/user/{userId}/account_data/{type}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3useruseridaccount_datatype
//
// "400: The request body is not a JSON object. Errcode: M_BAD_JSON or M_NOT_JSON." The common
// error codes distinguish them: M_NOT_JSON "Request did not contain valid JSON", M_BAD_JSON
// "Request contained valid JSON, but it was malformed in some way".
SCENARIO("global account data that is not a JSON object is refused and not stored",
         "[conformance][client-server][account-data][r11]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(account_data_config());
        // Fixture: the homeserver must start.
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");

        WHEN("the body is not valid JSON")
        {
            auto const refused = call(rt, "PUT", global_url(alice_path, "org.example.bad"), token, R"({"key":)");

            THEN("the server answers 400 M_NOT_JSON and stores nothing")
            {
                // Spec MUST: a body that is not a JSON object is refused with 400.
                REQUIRE(refused.status == 400U);
                // Spec MUST: a request that did not contain valid JSON is M_NOT_JSON.
                REQUIRE(errcode_of(refused) == "M_NOT_JSON");
                // Spec MUST: a refused PUT stores nothing, so GET finds no data (404).
                REQUIRE(call(rt, "GET", global_url(alice_path, "org.example.bad"), token).status == 404U);
            }
        }

        WHEN("the body is valid JSON but an array, a string or a number")
        {
            auto const array = call(rt, "PUT", global_url(alice_path, "org.example.array"), token, R"([1,2])");
            auto const string = call(rt, "PUT", global_url(alice_path, "org.example.string"), token, R"("text")");
            auto const number = call(rt, "PUT", global_url(alice_path, "org.example.number"), token, "42");

            THEN("each is refused with 400 M_BAD_JSON and nothing is stored")
            {
                // Spec MUST: a body that is not a JSON object is refused with 400.
                REQUIRE(array.status == 400U);
                // Spec MUST: valid JSON that is malformed in some way is M_BAD_JSON.
                REQUIRE(errcode_of(array) == "M_BAD_JSON");
                // Spec MUST: a body that is not a JSON object is refused with 400.
                REQUIRE(string.status == 400U);
                // Spec MUST: valid JSON that is malformed in some way is M_BAD_JSON.
                REQUIRE(errcode_of(string) == "M_BAD_JSON");
                // Spec MUST: a body that is not a JSON object is refused with 400.
                REQUIRE(number.status == 400U);
                // Spec MUST: valid JSON that is malformed in some way is M_BAD_JSON.
                REQUIRE(errcode_of(number) == "M_BAD_JSON");
                // Spec MUST: a refused PUT stores nothing, so GET finds no data (404).
                REQUIRE(call(rt, "GET", global_url(alice_path, "org.example.array"), token).status == 404U);
                // Spec MUST: a refused PUT stores nothing, so GET finds no data (404).
                REQUIRE(call(rt, "GET", global_url(alice_path, "org.example.string"), token).status == 404U);
                // Spec MUST: a refused PUT stores nothing, so GET finds no data (404).
                REQUIRE(call(rt, "GET", global_url(alice_path, "org.example.number"), token).status == 404U);
            }
        }

        WHEN("the body is a JSON object")
        {
            auto const stored =
                call(rt, "PUT", global_url(alice_path, "org.example.good"), token, R"({"key":"value"})");

            THEN("it is stored and read back")
            {
                // Spec MUST: a JSON object body is stored (200).
                REQUIRE(stored.status == 200U);
                auto const fetched = call(rt, "GET", global_url(alice_path, "org.example.good"), token);
                // Spec MUST: GET returns the stored account data content (200).
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* value = string_member(body, "key");
                // Spec MUST: the content is returned as it was set.
                REQUIRE(value != nullptr);
                // Spec MUST: the content is returned as it was set.
                REQUIRE(*value == "value");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/user/{userId}/account_data/{type} and
//                    PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3useruseridaccount_datatype
//
// The request body is any JSON object; only "The request body is not a JSON object" is a 400.
// Account data is never signed, so the canonical-JSON ban on fractional numbers does not apply:
// m.tag's own `order` is "A number in a range `[0,1]`" (PR #522 review).
SCENARIO("account data accepts a JSON object holding fractional and exponent numbers",
         "[conformance][client-server][account-data][r10][r11]")
{
    GIVEN("a logged-in user joined to a room")
    {
        auto started = merovingian::homeserver::start_client_server(account_data_config());
        // Fixture: the homeserver must start.
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, token);
        auto const body = std::string{R"({"order":0.5,"weight":1.5e3})"};

        WHEN("the client sets that body as global and as room account data")
        {
            auto const global = call(rt, "PUT", global_url(alice_path, "org.example.numbers"), token, body);
            auto const room = call(rt, "PUT", room_url(alice_path, room_id, "org.example.numbers"), token, body);

            THEN("both are stored and read back with their numbers")
            {
                // Spec MUST: a JSON object body is stored (200), whatever numbers it holds.
                REQUIRE(global.status == 200U);
                // Spec MUST: a JSON object body is stored (200), whatever numbers it holds.
                REQUIRE(room.status == 200U);
                for (auto const& url : {global_url(alice_path, "org.example.numbers"),
                                        room_url(alice_path, room_id, "org.example.numbers")})
                {
                    auto const fetched = call(rt, "GET", url, token);
                    // Spec MUST: GET returns the stored account data content (200).
                    REQUIRE(fetched.status == 200U);
                    auto const content = parse_object_json(fetched.body);
                    auto const* order = double_member(content, "order");
                    // Spec MUST: the content is returned as it was set.
                    REQUIRE(order != nullptr);
                    // Spec MUST: the content is returned as it was set.
                    REQUIRE(*order == 0.5);
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Client Config, Server Behaviour
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#client-config
//
// "Servers MUST reject setting account data for event types that the server manages by using a
// 405 error response. Currently, this only includes m.fully_read and m.push_rules. This applies
// to both global and room-specific account data." The 405 errcode is M_BAD_JSON.
SCENARIO("server-managed account data types are refused with 405 M_BAD_JSON globally and per room",
         "[conformance][client-server][account-data][r10][r11]")
{
    GIVEN("a logged-in user joined to a room")
    {
        auto started = merovingian::homeserver::start_client_server(account_data_config());
        // Fixture: the homeserver must start.
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, token);

        WHEN("the client sets m.fully_read or m.push_rules through either account-data API")
        {
            auto const global_read =
                call(rt, "PUT", global_url(alice_path, "m.fully_read"), token, R"({"event_id":"$x"})");
            auto const global_push = call(rt, "PUT", global_url(alice_path, "m.push_rules"), token, R"({"global":{}})");
            auto const room_read =
                call(rt, "PUT", room_url(alice_path, room_id, "m.fully_read"), token, R"({"event_id":"$x"})");
            auto const room_push =
                call(rt, "PUT", room_url(alice_path, room_id, "m.push_rules"), token, R"({"global":{}})");

            THEN("every request is refused with 405 M_BAD_JSON and nothing is stored")
            {
                for (auto const* response : {&global_read, &global_push, &room_read, &room_push})
                {
                    // Spec MUST: setting a server-managed type is rejected with a 405 error response.
                    REQUIRE(response->status == 405U);
                    // Spec MUST: the 405 errcode is M_BAD_JSON.
                    REQUIRE(errcode_of(*response) == "M_BAD_JSON");
                }
                // Spec MUST: a refused PUT stores nothing, so GET finds no data (404).
                REQUIRE(call(rt, "GET", global_url(alice_path, "m.fully_read"), token).status == 404U);
                // Spec MUST: a refused PUT stores nothing, so GET finds no data (404).
                REQUIRE(call(rt, "GET", room_url(alice_path, room_id, "m.push_rules"), token).status == 404U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Client Config, Server Behaviour
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#client-config
//
// "Servers must allow clients to read the above event types as normal." m.fully_read is set
// through POST /rooms/{roomId}/read_markers and kept in the room's account data.
SCENARIO("a server-managed room account data type is readable through the room account-data API",
         "[conformance][client-server][account-data][r10]")
{
    GIVEN("a user who has set their fully-read marker in a room through /read_markers")
    {
        auto started = merovingian::homeserver::start_client_server(account_data_config());
        // Fixture: the homeserver must start.
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, token);
        auto const sent = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn1", token,
                               R"({"msgtype":"m.text","body":"hello"})");
        // Fixture: a message must be sent for the read marker to point at.
        REQUIRE(sent.status == 200U);
        auto const sent_body = parse_object(sent.body);
        auto const* event_id = string_member(sent_body, "event_id");
        // Fixture: the send response must carry the event ID.
        REQUIRE(event_id != nullptr);
        // Fixture: the fully-read marker is set through /read_markers.
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/read_markers", token,
                     R"({"m.fully_read":")" + *event_id + R"("})")
                    .status == 200U);

        WHEN("the client reads m.fully_read from the room's account data")
        {
            auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "m.fully_read"), token);

            THEN("the server returns the marker's content")
            {
                // Spec MUST: servers must allow clients to read the server-managed types as normal (200).
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* marker = string_member(body, "event_id");
                // Spec MUST: m.fully_read content carries event_id.
                REQUIRE(marker != nullptr);
                // Spec MUST: the marker read back is the one that was set.
                REQUIRE(*marker == *event_id);
            }
        }
    }
}

// =============================================================================
// R10 — room-scoped account data
// =============================================================================

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT and GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3useruseridroomsroomidaccount_datatype
//
// PUT: "Set some account data for the client on a given room ... The config will be delivered to
// clients in the per-room entries via /sync." GET: "200: The account data content for the given
// type." Client Config: "There is no inheritance mechanism here: a given type of data missing
// from a room's account data does not fall back to the global account data with the same type."
SCENARIO("room account data is stored, read back, delivered in the room's /sync entry and kept apart from global data",
         "[conformance][client-server][account-data][r10]")
{
    GIVEN("a logged-in user joined to two rooms")
    {
        auto started = merovingian::homeserver::start_client_server(account_data_config());
        // Fixture: the homeserver must start.
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, token);
        auto const other_room_id = create_public_room(rt, token);

        WHEN("the client sets org.example.custom on the first room")
        {
            auto const stored =
                call(rt, "PUT", room_url(alice_path, room_id, "org.example.custom"), token, R"({"answer":42})");

            THEN("PUT answers 200 {} and GET on that room returns the content")
            {
                // Spec MUST: PUT room account data answers 200.
                REQUIRE(stored.status == 200U);
                // Spec MUST: the 200 response body is {}.
                REQUIRE(parse_object(stored.body).empty());
                auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.custom"), token);
                // Spec MUST: GET returns the account data content for the room and type (200).
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* answer = int_member(body, "answer");
                // Spec MUST: the content is returned as it was set.
                REQUIRE(answer != nullptr);
                // Spec MUST: the content is returned as it was set.
                REQUIRE(*answer == 42);
            }

            THEN("the event appears in that room's account_data in /sync")
            {
                auto const events = synced_room_account_data(rt, token, room_id);
                auto const* content = event_content_of_type(events, "org.example.custom");
                // Spec MUST: room account data is delivered in the room's /sync account_data.
                REQUIRE(content != nullptr);
                auto const* answer = int_member(*content, "answer");
                // Spec MUST: the synced event carries the content as it was set.
                REQUIRE(answer != nullptr);
                // Spec MUST: the synced event carries the content as it was set.
                REQUIRE(*answer == 42);
            }

            THEN("neither the global account data nor the other room has the type")
            {
                // Spec MUST: room account data is not global account data, so the global GET finds nothing (404).
                REQUIRE(call(rt, "GET", global_url(alice_path, "org.example.custom"), token).status == 404U);
                auto const other = call(rt, "GET", room_url(alice_path, other_room_id, "org.example.custom"), token);
                // Spec MUST: account data is scoped to one room, so another room has none (404).
                REQUIRE(other.status == 404U);
                // Spec MUST: no account data for this user, room and type is M_NOT_FOUND.
                REQUIRE(errcode_of(other) == "M_NOT_FOUND");
                // Spec MUST: another room's /sync account_data does not carry the type.
                REQUIRE(event_content_of_type(synced_room_account_data(rt, token, other_room_id),
                                              "org.example.custom") == nullptr);
            }
        }

        WHEN("the client sets a global type and reads the same type from a room")
        {
            // Fixture: alice sets a global type first.
            REQUIRE(call(rt, "PUT", global_url(alice_path, "org.example.global"), token, R"({"g":1})").status == 200U);
            auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.global"), token);

            THEN("the room read does not fall back to the global value")
            {
                // Spec MUST: "There is no inheritance mechanism", so the room read does not fall back (404).
                REQUIRE(fetched.status == 404U);
                // Spec MUST: no account data for this user, room and type is M_NOT_FOUND.
                REQUIRE(errcode_of(fetched) == "M_NOT_FOUND");
            }
        }

        WHEN("the client updates a room type it already holds")
        {
            // Fixture: alice sets the room type once.
            REQUIRE(call(rt, "PUT", room_url(alice_path, room_id, "org.example.custom"), token, R"({"v":1})").status ==
                    200U);
            // Spec MUST: setting the same room type again answers 200.
            REQUIRE(call(rt, "PUT", room_url(alice_path, room_id, "org.example.custom"), token, R"({"v":2})").status ==
                    200U);

            THEN("GET returns the latest content")
            {
                auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.custom"), token);
                // Spec MUST: GET returns the room account data (200).
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* version = int_member(body, "v");
                // Spec MUST: the content is returned as it was set.
                REQUIRE(version != nullptr);
                // Spec MUST: the latest PUT replaces the earlier content.
                REQUIRE(*version == 2);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT and GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3useruseridroomsroomidaccount_datatype
//
// 400 M_NOT_JSON / M_BAD_JSON: "The request body is not a JSON object". 400 M_INVALID_PARAM: "The
// given roomID is not a valid room ID". 403 M_FORBIDDEN: "The access token provided is not
// authorised to retrieve/modify this user's account data". 404 M_NOT_FOUND: "No account data
// has been provided for this user and this room with the given type."
SCENARIO("room account data refuses bad bodies, invalid room IDs and other users",
         "[conformance][client-server][account-data][r10]")
{
    GIVEN("two logged-in users, alice joined to a room")
    {
        auto started = merovingian::homeserver::start_client_server(account_data_config());
        // Fixture: the homeserver must start.
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_public_room(rt, alice);

        WHEN("alice sends a body that is not JSON, and one that is JSON but not an object")
        {
            auto const not_json = call(rt, "PUT", room_url(alice_path, room_id, "org.example.a"), alice, "{oops");
            auto const not_object = call(rt, "PUT", room_url(alice_path, room_id, "org.example.b"), alice, "[]");

            THEN("they are refused with 400 M_NOT_JSON and 400 M_BAD_JSON, and nothing is stored")
            {
                // Spec MUST: a body that is not a JSON object is refused with 400.
                REQUIRE(not_json.status == 400U);
                // Spec MUST: a request that did not contain valid JSON is M_NOT_JSON.
                REQUIRE(errcode_of(not_json) == "M_NOT_JSON");
                // Spec MUST: a body that is not a JSON object is refused with 400.
                REQUIRE(not_object.status == 400U);
                // Spec MUST: valid JSON that is malformed in some way is M_BAD_JSON.
                REQUIRE(errcode_of(not_object) == "M_BAD_JSON");
                // Spec MUST: a refused PUT stores nothing, so GET finds no data (404).
                REQUIRE(call(rt, "GET", room_url(alice_path, room_id, "org.example.a"), alice).status == 404U);
                // Spec MUST: a refused PUT stores nothing, so GET finds no data (404).
                REQUIRE(call(rt, "GET", room_url(alice_path, room_id, "org.example.b"), alice).status == 404U);
            }
        }

        WHEN("alice names something that is not a room ID")
        {
            auto const put = call(rt, "PUT", room_url(alice_path, "%40notaroomid%3Aexample.org", "org.example.c"),
                                  alice, R"({"c":1})");
            auto const get =
                call(rt, "GET", room_url(alice_path, "%40notaroomid%3Aexample.org", "org.example.c"), alice);

            THEN("both are refused with 400 M_INVALID_PARAM")
            {
                // Spec MUST: a roomId that is not a valid room ID is refused with 400.
                REQUIRE(put.status == 400U);
                // Spec MUST: an invalid room ID is M_INVALID_PARAM.
                REQUIRE(errcode_of(put) == "M_INVALID_PARAM");
                // Spec MUST: a roomId that is not a valid room ID is refused with 400.
                REQUIRE(get.status == 400U);
                // Spec MUST: an invalid room ID is M_INVALID_PARAM.
                REQUIRE(errcode_of(get) == "M_INVALID_PARAM");
            }
        }

        WHEN("bob reads or writes alice's room account data")
        {
            // Fixture: alice sets room account data first.
            REQUIRE(call(rt, "PUT", room_url(alice_path, room_id, "org.example.d"), alice, R"({"d":1})").status ==
                    200U);
            auto const get = call(rt, "GET", room_url(alice_path, room_id, "org.example.d"), bob);
            auto const put = call(rt, "PUT", room_url(alice_path, room_id, "org.example.d"), bob, R"({"d":2})");

            THEN("both are refused with 403 M_FORBIDDEN and alice's data is unchanged")
            {
                // Spec MUST: a token not authorised for this user's account data is refused with 403.
                REQUIRE(get.status == 403U);
                // Spec MUST: the 403 errcode is M_FORBIDDEN.
                REQUIRE(errcode_of(get) == "M_FORBIDDEN");
                // Spec MUST: a token not authorised for this user's account data is refused with 403.
                REQUIRE(put.status == 403U);
                // Spec MUST: the 403 errcode is M_FORBIDDEN.
                REQUIRE(errcode_of(put) == "M_FORBIDDEN");
                auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.d"), alice);
                // Spec MUST: the owner still reads the data (200).
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* value = int_member(body, "d");
                // Spec MUST: the content is returned as it was set.
                REQUIRE(value != nullptr);
                // Spec MUST: a refused PUT changes nothing, so the owner's content is unchanged.
                REQUIRE(*value == 1);
            }
        }

        WHEN("alice reads a type she never set in the room")
        {
            auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.never"), alice);

            THEN("the server answers 404 M_NOT_FOUND")
            {
                // Spec MUST: no account data for this user, room and type is a 404.
                REQUIRE(fetched.status == 404U);
                // Spec MUST: the 404 errcode is M_NOT_FOUND.
                REQUIRE(errcode_of(fetched) == "M_NOT_FOUND");
            }
        }
    }
}
