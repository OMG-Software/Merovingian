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
    return merovingian::homeserver::handle_client_server_request(rt, {std::move(method), std::move(target), token,
                                                                      std::move(body)})
        .response;
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!"))
                .status == 200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                 R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_public_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    REQUIRE(created.status == 200U);
    auto const body = parse_object(created.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto global_url(std::string_view user_path, std::string_view type) -> std::string
{
    return "/_matrix/client/v3/user/" + std::string{user_path} + "/account_data/" + std::string{type};
}

[[nodiscard]] auto room_url(std::string_view user_path, std::string_view room_id, std::string_view type)
    -> std::string
{
    return "/_matrix/client/v3/user/" + std::string{user_path} + "/rooms/" + std::string{room_id} +
           "/account_data/" + std::string{type};
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
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");

        WHEN("the body is not valid JSON")
        {
            auto const refused = call(rt, "PUT", global_url(alice_path, "org.example.bad"), token, R"({"key":)");

            THEN("the server answers 400 M_NOT_JSON and stores nothing")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(errcode_of(refused) == "M_NOT_JSON");
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
                REQUIRE(array.status == 400U);
                REQUIRE(errcode_of(array) == "M_BAD_JSON");
                REQUIRE(string.status == 400U);
                REQUIRE(errcode_of(string) == "M_BAD_JSON");
                REQUIRE(number.status == 400U);
                REQUIRE(errcode_of(number) == "M_BAD_JSON");
                REQUIRE(call(rt, "GET", global_url(alice_path, "org.example.array"), token).status == 404U);
                REQUIRE(call(rt, "GET", global_url(alice_path, "org.example.string"), token).status == 404U);
                REQUIRE(call(rt, "GET", global_url(alice_path, "org.example.number"), token).status == 404U);
            }
        }

        WHEN("the body is a JSON object")
        {
            auto const stored = call(rt, "PUT", global_url(alice_path, "org.example.good"), token, R"({"key":"value"})");

            THEN("it is stored and read back")
            {
                REQUIRE(stored.status == 200U);
                auto const fetched = call(rt, "GET", global_url(alice_path, "org.example.good"), token);
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* value = string_member(body, "key");
                REQUIRE(value != nullptr);
                REQUIRE(*value == "value");
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
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, token);

        WHEN("the client sets m.fully_read or m.push_rules through either account-data API")
        {
            auto const global_read = call(rt, "PUT", global_url(alice_path, "m.fully_read"), token, R"({"event_id":"$x"})");
            auto const global_push = call(rt, "PUT", global_url(alice_path, "m.push_rules"), token, R"({"global":{}})");
            auto const room_read =
                call(rt, "PUT", room_url(alice_path, room_id, "m.fully_read"), token, R"({"event_id":"$x"})");
            auto const room_push =
                call(rt, "PUT", room_url(alice_path, room_id, "m.push_rules"), token, R"({"global":{}})");

            THEN("every request is refused with 405 M_BAD_JSON and nothing is stored")
            {
                for (auto const* response : {&global_read, &global_push, &room_read, &room_push})
                {
                    REQUIRE(response->status == 405U);
                    REQUIRE(errcode_of(*response) == "M_BAD_JSON");
                }
                REQUIRE(call(rt, "GET", global_url(alice_path, "m.fully_read"), token).status == 404U);
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
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_public_room(rt, token);
        auto const sent = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn1", token,
                               R"({"msgtype":"m.text","body":"hello"})");
        REQUIRE(sent.status == 200U);
        auto const sent_body = parse_object(sent.body);
        auto const* event_id = string_member(sent_body, "event_id");
        REQUIRE(event_id != nullptr);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/read_markers", token,
                     R"({"m.fully_read":")" + *event_id + R"("})")
                    .status == 200U);

        WHEN("the client reads m.fully_read from the room's account data")
        {
            auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "m.fully_read"), token);

            THEN("the server returns the marker's content")
            {
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* marker = string_member(body, "event_id");
                REQUIRE(marker != nullptr);
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
                REQUIRE(stored.status == 200U);
                REQUIRE(parse_object(stored.body).empty());
                auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.custom"), token);
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* answer = int_member(body, "answer");
                REQUIRE(answer != nullptr);
                REQUIRE(*answer == 42);
            }

            THEN("the event appears in that room's account_data in /sync")
            {
                auto const events = synced_room_account_data(rt, token, room_id);
                auto const* content = event_content_of_type(events, "org.example.custom");
                REQUIRE(content != nullptr);
                auto const* answer = int_member(*content, "answer");
                REQUIRE(answer != nullptr);
                REQUIRE(*answer == 42);
            }

            THEN("neither the global account data nor the other room has the type")
            {
                REQUIRE(call(rt, "GET", global_url(alice_path, "org.example.custom"), token).status == 404U);
                auto const other = call(rt, "GET", room_url(alice_path, other_room_id, "org.example.custom"), token);
                REQUIRE(other.status == 404U);
                REQUIRE(errcode_of(other) == "M_NOT_FOUND");
                REQUIRE(event_content_of_type(synced_room_account_data(rt, token, other_room_id),
                                              "org.example.custom") == nullptr);
            }
        }

        WHEN("the client sets a global type and reads the same type from a room")
        {
            REQUIRE(call(rt, "PUT", global_url(alice_path, "org.example.global"), token, R"({"g":1})").status == 200U);
            auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.global"), token);

            THEN("the room read does not fall back to the global value")
            {
                REQUIRE(fetched.status == 404U);
                REQUIRE(errcode_of(fetched) == "M_NOT_FOUND");
            }
        }

        WHEN("the client updates a room type it already holds")
        {
            REQUIRE(call(rt, "PUT", room_url(alice_path, room_id, "org.example.custom"), token, R"({"v":1})").status ==
                    200U);
            REQUIRE(call(rt, "PUT", room_url(alice_path, room_id, "org.example.custom"), token, R"({"v":2})").status ==
                    200U);

            THEN("GET returns the latest content")
            {
                auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.custom"), token);
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* version = int_member(body, "v");
                REQUIRE(version != nullptr);
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
                REQUIRE(not_json.status == 400U);
                REQUIRE(errcode_of(not_json) == "M_NOT_JSON");
                REQUIRE(not_object.status == 400U);
                REQUIRE(errcode_of(not_object) == "M_BAD_JSON");
                REQUIRE(call(rt, "GET", room_url(alice_path, room_id, "org.example.a"), alice).status == 404U);
                REQUIRE(call(rt, "GET", room_url(alice_path, room_id, "org.example.b"), alice).status == 404U);
            }
        }

        WHEN("alice names something that is not a room ID")
        {
            auto const put = call(rt, "PUT", room_url(alice_path, "%40notaroomid%3Aexample.org", "org.example.c"),
                                  alice, R"({"c":1})");
            auto const get = call(rt, "GET", room_url(alice_path, "%40notaroomid%3Aexample.org", "org.example.c"), alice);

            THEN("both are refused with 400 M_INVALID_PARAM")
            {
                REQUIRE(put.status == 400U);
                REQUIRE(errcode_of(put) == "M_INVALID_PARAM");
                REQUIRE(get.status == 400U);
                REQUIRE(errcode_of(get) == "M_INVALID_PARAM");
            }
        }

        WHEN("bob reads or writes alice's room account data")
        {
            REQUIRE(call(rt, "PUT", room_url(alice_path, room_id, "org.example.d"), alice, R"({"d":1})").status == 200U);
            auto const get = call(rt, "GET", room_url(alice_path, room_id, "org.example.d"), bob);
            auto const put = call(rt, "PUT", room_url(alice_path, room_id, "org.example.d"), bob, R"({"d":2})");

            THEN("both are refused with 403 M_FORBIDDEN and alice's data is unchanged")
            {
                REQUIRE(get.status == 403U);
                REQUIRE(errcode_of(get) == "M_FORBIDDEN");
                REQUIRE(put.status == 403U);
                REQUIRE(errcode_of(put) == "M_FORBIDDEN");
                auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.d"), alice);
                REQUIRE(fetched.status == 200U);
                auto const body = parse_object(fetched.body);
                auto const* value = int_member(body, "d");
                REQUIRE(value != nullptr);
                REQUIRE(*value == 1);
            }
        }

        WHEN("alice reads a type she never set in the room")
        {
            auto const fetched = call(rt, "GET", room_url(alice_path, room_id, "org.example.never"), alice);

            THEN("the server answers 404 M_NOT_FOUND")
            {
                REQUIRE(fetched.status == 404U);
                REQUIRE(errcode_of(fetched) == "M_NOT_FOUND");
            }
        }
    }
}
