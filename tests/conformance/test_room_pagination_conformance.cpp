// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |             ROOM EVENT PAGINATION AND FILTER CONFORMANCE TESTS          |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19, GET /rooms/{roomId}/messages,    |
// |        GET /rooms/{roomId}/relations/{eventId}, GET .../members,        |
// |        RoomEventFilter                                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                 |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                         |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// +-------------------------------------------------------------------------+
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto pagination_config() -> merovingian::config::Config
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

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json(localpart, "CorrectHorse7!"))
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

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto send(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                        std::string const& txn, std::string const& content) -> std::string
{
    auto const reply =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn, token, content);
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* event_id = string_member(body, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

[[nodiscard]] auto text(std::string_view body) -> std::string
{
    return R"({"msgtype":"m.text","body":")" + std::string{body} + R"("})";
}

[[nodiscard]] auto sync_next_batch(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/sync?timeout=0", token);
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* next_batch = string_member(body, "next_batch");
    REQUIRE(next_batch != nullptr);
    return *next_batch;
}

[[nodiscard]] auto chunk_event_ids(Reply const& reply) -> std::vector<std::string>
{
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* chunk = object_member_as_array(body, "chunk");
    REQUIRE(chunk != nullptr);
    auto ids = std::vector<std::string>{};
    for (auto const& entry : *chunk)
    {
        auto const* object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        REQUIRE(object != nullptr);
        auto const* event_id = string_member(*object, "event_id");
        REQUIRE(event_id != nullptr);
        ids.push_back(*event_id);
    }
    return ids;
}

[[nodiscard]] auto query_escape(std::string_view value) -> std::string
{
    auto escaped = std::string{};
    for (auto const character : value)
    {
        switch (character)
        {
        case '{':
            escaped += "%7B";
            break;
        case '}':
            escaped += "%7D";
            break;
        case '"':
            escaped += "%22";
            break;
        case ':':
            escaped += "%3A";
            break;
        case ',':
            escaped += "%2C";
            break;
        case '[':
            escaped += "%5B";
            break;
        case ']':
            escaped += "%5D";
            break;
        default:
            escaped += character;
            break;
        }
    }
    return escaped;
}

} // namespace

// Spec: Matrix Client-Server API v1.19, GET /rooms/{roomId}/messages
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmessages
//
// `from`: "The token to start returning events from. This token can be obtained from a
// prev_batch or next_batch token returned by the /sync endpoint, or from an end token
// returned by a previous request to this endpoint."
SCENARIO("/messages paginates from a /sync next_batch token in both directions",
         "[conformance][client-server][messages][pagination]")
{
    GIVEN("a room whose first message was delivered by a sync, then a second message")
    {
        auto started = merovingian::homeserver::start_client_server(pagination_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);
        auto const before = send(rt, token, room_id, "t1", text("before the sync"));
        auto const next_batch = sync_next_batch(rt, token);
        auto const after = send(rt, token, room_id, "t2", text("after the sync"));

        WHEN("/messages pages forward from next_batch")
        {
            auto const ids = chunk_event_ids(
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=f&from=" + next_batch, token));

            THEN("only events after the sync are returned")
            {
                // Spec MUST: a next_batch token is a valid `from`; forward from it is what came after the sync.
                REQUIRE(ids == std::vector<std::string>{after});
            }
        }

        WHEN("/messages pages backward from next_batch")
        {
            auto const ids = chunk_event_ids(
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=1&from=" + next_batch,
                     token));

            THEN("the newest event the sync delivered comes first, and nothing after it")
            {
                // Spec MUST: backward from the sync's position starts with what the sync last delivered.
                REQUIRE(ids == std::vector<std::string>{before});
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, GET /rooms/{roomId}/messages and RoomEventFilter
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#filtering
//
// /messages `filter`: "A JSON RoomEventFilter to filter returned events with."
// RoomEventFilter `contains_url`: "If true, includes only events with a url key in their
// content. If false, excludes those events." `types` / `senders`: lists of types or senders
// to include.
SCENARIO("/messages applies the RoomEventFilter to the events it returns",
         "[conformance][client-server][messages][filter]")
{
    GIVEN("a room with a plain message and a message carrying a url")
    {
        auto started = merovingian::homeserver::start_client_server(pagination_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);
        auto const plain = send(rt, token, room_id, "t1", text("plain"));
        auto const with_url =
            send(rt, token, room_id, "t2", R"({"msgtype":"m.file","body":"file","url":"mxc://example.org/abc"})");
        auto const messages = [&](std::string_view filter) {
            return chunk_event_ids(
                call(rt, "GET",
                     "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=50&filter=" + query_escape(filter),
                     token));
        };

        WHEN("the filter asks for contains_url true, then false")
        {
            auto const urls = messages(R"({"contains_url":true})");
            auto const no_urls = messages(R"({"contains_url":false,"types":["m.room.message"]})");

            THEN("only the event with a url is returned, then only the one without")
            {
                // Spec MUST: contains_url true includes only events whose content has a url.
                REQUIRE(urls == std::vector<std::string>{with_url});
                // Spec MUST: contains_url false excludes them.
                REQUIRE(no_urls == std::vector<std::string>{plain});
            }
        }

        WHEN("the filter names types and senders")
        {
            auto const by_type = messages(R"({"types":["m.room.message"]})");
            auto const by_other_sender = messages(R"({"senders":["@bob:example.org"]})");

            THEN("only matching events are returned")
            {
                // Spec MUST: `types` includes only the listed event types.
                REQUIRE(by_type == std::vector<std::string>{with_url, plain});
                // Spec MUST: `senders` includes only events from the listed senders.
                REQUIRE(by_other_sender.empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, GET /rooms/{roomId}/relations/{eventId}
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1roomsroomidrelationseventid
//
// `from`: "The pagination token to start returning results from ... Can be a next_batch or
// prev_batch token from a previous call, or a returned start token from /messages, or a
// next_batch token from /sync."
// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/rooms/{roomId}/messages
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmessages
//
// `filter` is "A JSON RoomEventFilter". One that is not JSON, or not an object, is refused
// with 400 M_BAD_JSON, as /context refuses it; serving the page unfiltered would answer a
// request the client did not make.
SCENARIO("/messages refuses a filter that is not a JSON RoomEventFilter",
         "[conformance][client-server][messages][filter]")
{
    GIVEN("a room the user is in")
    {
        auto started = merovingian::homeserver::start_client_server(pagination_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);
        auto const filter = GENERATE(as<std::string>{}, "not-json", "%5B1%2C2%5D", "%22text%22");

        WHEN("/messages is asked with that filter")
        {
            auto const reply =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&filter=" + filter, token);

            THEN("it answers 400 M_BAD_JSON")
            {
                CAPTURE(filter, reply.body);
                // Spec: `filter` is "A JSON RoomEventFilter".
                REQUIRE(reply.status == 400U);
                REQUIRE(*string_member(parse_object(reply.body), "errcode") == "M_BAD_JSON");
            }
        }
    }
}

SCENARIO("/relations paginates from a /sync next_batch token", "[conformance][client-server][relations][pagination]")
{
    GIVEN("a root event with one reply before a sync and one after")
    {
        auto started = merovingian::homeserver::start_client_server(pagination_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);
        auto const root = send(rt, token, room_id, "t0", text("root"));
        auto const reply_to_root = [&](std::string const& txn, std::string_view body) {
            return send(rt, token, room_id, txn,
                        R"({"msgtype":"m.text","body":")" + std::string{body} +
                            R"(","m.relates_to":{"rel_type":"m.thread","event_id":")" + root + R"("}})");
        };
        std::ignore = reply_to_root("t1", "before");
        auto const next_batch = sync_next_batch(rt, token);
        auto const after = reply_to_root("t2", "after");

        WHEN("/relations pages forward from next_batch")
        {
            auto const ids = chunk_event_ids(call(
                rt, "GET", "/_matrix/client/v1/rooms/" + room_id + "/relations/" + root + "?dir=f&from=" + next_batch,
                token));

            THEN("only the relation sent after the sync is returned")
            {
                // Spec MUST: a /sync next_batch is a valid `from`.
                REQUIRE(ids == std::vector<std::string>{after});
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, GET /rooms/{roomId}/messages and GET .../members
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmessages
//
// Both responses list 200 and 403 "You aren't a member of the room" (and, for /members,
// "and weren't previously a member of the room"); neither lists 404. A room this server
// does not know is one the user is not a member of.
SCENARIO("/messages and /members answer 403 for a room the user cannot be a member of",
         "[conformance][client-server][messages][members]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(pagination_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");

        WHEN("they read a room that does not exist")
        {
            auto const endpoint = GENERATE(as<std::string>{}, "messages?dir=b", "members");
            auto const reply =
                call(rt, "GET", "/_matrix/client/v3/rooms/!does-not-exist:example.org/" + endpoint, token);

            THEN("the answer is 403 M_FORBIDDEN, not 404")
            {
                CAPTURE(endpoint);
                // Spec MUST: the response table offers 403 for a non-member, and no 404.
                REQUIRE(reply.status == 403U);
                auto const body = parse_object(reply.body);
                REQUIRE(string_member(body, "errcode") != nullptr);
                REQUIRE(*string_member(body, "errcode") == "M_FORBIDDEN");
            }
        }
    }
}
