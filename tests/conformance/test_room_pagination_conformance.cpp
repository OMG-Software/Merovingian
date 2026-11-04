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
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
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

[[nodiscard]] auto string_field(Reply const& reply, std::string_view name) -> std::optional<std::string>
{
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* value = string_member(body, name);
    return value == nullptr ? std::nullopt : std::optional<std::string>{*value};
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

// Spec: Matrix Client-Server API v1.19, GET /rooms/{roomId}/members
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmembers
//
// Security audit run-2 (F-10, ADR-0344): the current roster is built from the room's member state
// and the membership rows in time linear in the members. The answer is as the spec says: for a
// joined user, "the current members of the room", each as an m.room.member event, once; the
// `membership` and `not_membership` filters pick which.
SCENARIO("/members lists every current member once, whatever the room's size and the filters",
         "[conformance][client-server][members][f10]")
{
    GIVEN("a room whose roster holds hundreds of members with state and hundreds with only a membership row")
    {
        auto started = merovingian::homeserver::start_client_server(pagination_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);
        auto& store = rt.homeserver.database.persistent_store;

        auto const state_backed = std::size_t{300U};
        auto const row_only = std::size_t{300U};
        for (auto index = std::size_t{0U}; index < state_backed; ++index)
        {
            auto const user = "@sb" + std::to_string(index) + ":remote.example";
            auto const event_id = "$member_sb" + std::to_string(index);
            REQUIRE(merovingian::database::store_membership(store, {room_id, user}) ==
                    merovingian::database::MembershipStoreResult::stored);
            REQUIRE(merovingian::database::store_event(
                store,
                {event_id, room_id, user,
                 R"({"type":"m.room.member","state_key":")" + user + R"(","sender":")" + user + R"(","room_id":")" +
                     room_id + R"(","origin_server_ts":1,"content":{"membership":"join"}})"}));
            REQUIRE(merovingian::database::store_state(store, {room_id, "m.room.member", user, event_id}));
        }
        for (auto index = std::size_t{0U}; index < row_only; ++index)
        {
            REQUIRE(merovingian::database::store_membership(
                        store, {room_id, "@ro" + std::to_string(index) + ":remote.example"}) ==
                    merovingian::database::MembershipStoreResult::stored);
        }

        // The state key of each chunk entry, with how often it appears.
        auto const state_keys_of = [](Reply const& reply) {
            REQUIRE(reply.status == 200U);
            auto const body = parse_object(reply.body);
            auto const* chunk = object_member_as_array(body, "chunk");
            REQUIRE(chunk != nullptr);
            auto counts = std::map<std::string, std::size_t>{};
            for (auto const& entry : *chunk)
            {
                auto const* object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
                REQUIRE(object != nullptr);
                // Spec: each chunk entry is an m.room.member event.
                REQUIRE(*string_member(*object, "type") == "m.room.member");
                ++counts[*string_member(*object, "state_key")];
            }
            return counts;
        };

        WHEN("the joined creator lists the members")
        {
            auto const counts =
                state_keys_of(call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members", token));

            THEN("each member appears exactly once: the creator, the state-backed ones, the row-only ones")
            {
                REQUIRE(counts.size() == 1U + state_backed + row_only);
                REQUIRE(std::ranges::all_of(counts, [](auto const& entry) {
                    return entry.second == 1U;
                }));
                REQUIRE(counts.contains("@sb7:remote.example"));
                REQUIRE(counts.contains("@ro7:remote.example"));
            }
        }

        WHEN("the members are listed with not_membership=join")
        {
            auto const counts = state_keys_of(
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members?not_membership=join", token));

            THEN("no joined member is listed")
            {
                // Spec: not_membership - "The kind of membership to exclude from the results."
                REQUIRE(counts.empty());
            }
        }

        WHEN("the members are listed with membership=join")
        {
            auto const counts = state_keys_of(
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/members?membership=join", token));

            THEN("every joined member is listed once")
            {
                REQUIRE(counts.size() == 1U + state_backed + row_only);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, GET /rooms/{roomId}/messages
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmessages
//
// `end`: "A token corresponding to the end of `chunk`. ... If no further events are available (either because we
// have reached the start of the timeline, or because the user does not have permission to see any more events),
// this property is omitted from the response." `chunk`: "Clients should continue to paginate until no `end`
// property is returned."
SCENARIO("/messages omits end when no further events are available",
         "[conformance][client-server][messages][pagination][messages-end]")
{
    GIVEN("a room with several events")
    {
        auto started = merovingian::homeserver::start_client_server(pagination_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);
        for (auto i = 0; i < 4; ++i)
        {
            std::ignore = send(rt, token, room_id, "t" + std::to_string(i), text("m" + std::to_string(i)));
        }
        auto const base = "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b";
        auto const everything = chunk_event_ids(call(rt, "GET", base + "&limit=100", token));
        REQUIRE(everything.size() > 3U);

        WHEN("one request returns the whole timeline")
        {
            auto const reply = call(rt, "GET", base + "&limit=100", token);

            THEN("the response has no end token")
            {
                REQUIRE(string_field(reply, "end") == std::nullopt);
            }
        }

        WHEN("a client pages backward through the room until no end is returned")
        {
            auto collected = std::vector<std::string>{};
            auto from = std::string{};
            auto pages = std::size_t{0U};
            auto ended = false;
            while (pages < everything.size() + 3U)
            {
                ++pages;
                auto const reply = call(rt, "GET", base + "&limit=2" + (from.empty() ? "" : "&from=" + from), token);
                for (auto const& id : chunk_event_ids(reply))
                {
                    collected.push_back(id);
                }
                auto const end = string_field(reply, "end");
                if (!end.has_value())
                {
                    ended = true;
                    break;
                }
                REQUIRE_FALSE(end->empty());
                from = *end;
            }

            THEN("it stops, having seen each event once and in the same order as one large page")
            {
                REQUIRE(ended);
                REQUIRE(collected == everything);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, GET /rooms/{roomId}/messages
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmessages
//
// `to`: "The token to stop returning events at. This token can be obtained from a `prev_batch` or `next_batch`
// token returned by the `/sync` endpoint, or from an `end` token returned by a previous request to this endpoint."
SCENARIO("/messages stops returning events at the to token",
         "[conformance][client-server][messages][pagination][messages-to]")
{
    GIVEN("a room with several events and the end token of a two-event page")
    {
        auto started = merovingian::homeserver::start_client_server(pagination_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, token);
        for (auto i = 0; i < 4; ++i)
        {
            std::ignore = send(rt, token, room_id, "t" + std::to_string(i), text("m" + std::to_string(i)));
        }
        auto const base = "/_matrix/client/v3/rooms/" + room_id + "/messages?limit=100&dir=";
        auto const backward_page =
            call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?limit=2&dir=b", token);
        auto const backward_ids = chunk_event_ids(backward_page);
        auto const backward_end = string_field(backward_page, "end");
        REQUIRE(backward_end.has_value());
        auto const forward_page =
            call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?limit=2&dir=f", token);
        auto const forward_ids = chunk_event_ids(forward_page);
        auto const forward_end = string_field(forward_page, "end");
        REQUIRE(forward_end.has_value());

        WHEN("the newest events are requested backward with to set to that end token")
        {
            auto const reply = call(rt, "GET", base + "b&to=" + *backward_end, token);

            THEN("only the events newer than the token are returned, and no end follows")
            {
                REQUIRE(chunk_event_ids(reply) == std::vector<std::string>{backward_ids.front()});
                REQUIRE(string_field(reply, "end") == std::nullopt);
            }
        }

        WHEN("the oldest events are requested forward with to set to that end token")
        {
            auto const reply = call(rt, "GET", base + "f&to=" + *forward_end, token);

            THEN("only the events older than the token are returned, and no end follows")
            {
                REQUIRE(chunk_event_ids(reply) == std::vector<std::string>{forward_ids.front()});
                REQUIRE(string_field(reply, "end") == std::nullopt);
            }
        }
    }
}
