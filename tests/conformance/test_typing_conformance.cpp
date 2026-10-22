// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            TYPING NOTIFICATIONS — CONFORMANCE                           |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 §Typing Notifications            |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#typing-notifications |
// |                                                                         |
// |  Conformance audit 2026-10-17, R13: a local user's typing never        |
// |  expired, and a `typing` that was not a boolean was treated as true.   |
// |  Expiry is driven through expire_typing_notifications with an explicit |
// |  clock, so no scenario sleeps.                                          |
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
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;
using merovingian::homeserver::LocalHttpResponse;

[[nodiscard]] auto typing_config() -> merovingian::config::Config
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
    REQUIRE(
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!")).status ==
        200U);
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

[[nodiscard]] auto errcode_of(LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

struct TypingRoom final
{
    std::string alice{};
    std::string bob{};
    std::string room_id{};
};

// alice creates a public room and bob joins it.
[[nodiscard]] auto typing_room(ClientServerRuntime& rt) -> TypingRoom
{
    auto out = TypingRoom{register_and_login(rt, "alice"), register_and_login(rt, "bob"), {}};
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", out.alice, R"({"preset":"public_chat"})");
    REQUIRE(created.status == 200U);
    auto const body = parse_object(created.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    out.room_id = *room_id;
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + out.room_id + "/join", out.bob, "{}").status == 200U);
    return out;
}

[[nodiscard]] auto put_typing(ClientServerRuntime& rt, TypingRoom const& room, std::string body) -> LocalHttpResponse
{
    return call(rt, "PUT", "/_matrix/client/v3/rooms/" + room.room_id + "/typing/@alice:example.org", room.alice,
                std::move(body));
}

struct SyncedTyping final
{
    std::string next_batch{};
    // The user_ids of the room's m.typing event, or nullopt when the sync carried none.
    std::optional<std::vector<std::string>> user_ids{};
};

[[nodiscard]] auto sync_typing(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                               std::string const& since) -> SyncedTyping
{
    auto const target = since.empty() ? std::string{"/_matrix/client/v3/sync?timeout=0"}
                                      : "/_matrix/client/v3/sync?timeout=0&since=" + since;
    auto const synced = call(rt, "GET", target, token);
    REQUIRE(synced.status == 200U);
    auto const body = parse_object(synced.body);
    auto out = SyncedTyping{};
    auto const* next_batch = string_member(body, "next_batch");
    REQUIRE(next_batch != nullptr);
    out.next_batch = *next_batch;
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* join = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "join");
    auto const* room = join == nullptr ? nullptr : object_member_as_object(*join, room_id);
    auto const* ephemeral = room == nullptr ? nullptr : object_member_as_object(*room, "ephemeral");
    auto const* events = ephemeral == nullptr ? nullptr : object_member_as_array(*ephemeral, "events");
    if (events == nullptr)
    {
        return out;
    }
    for (auto const& event : *events)
    {
        auto const* object = std::get_if<merovingian::canonicaljson::Object>(&event.storage());
        auto const* type = object == nullptr ? nullptr : string_member(*object, "type");
        if (type == nullptr || *type != "m.typing")
        {
            continue;
        }
        auto const* content = object_member_as_object(*object, "content");
        REQUIRE(content != nullptr);
        auto const* user_ids = object_member_as_array(*content, "user_ids");
        REQUIRE(user_ids != nullptr);
        auto ids = std::vector<std::string>{};
        for (auto const& id : *user_ids)
        {
            auto const* text = std::get_if<std::string>(&id.storage());
            REQUIRE(text != nullptr);
            ids.push_back(*text);
        }
        out.user_ids = std::move(ids);
    }
    return out;
}

[[nodiscard]] auto contains(std::vector<std::string> const& ids, std::string_view id) -> bool
{
    return std::ranges::find(ids, id) != ids.end();
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3roomsroomidtypinguserid
//
// Request body: `typing` (boolean, Required) "Whether the user is typing or not"; `timeout`
// (integer) "The length of time in milliseconds to mark this user as typing". Common error
// codes: M_NOT_JSON "Request did not contain valid JSON", M_BAD_JSON "Request contained valid
// JSON, but it was malformed in some way", M_MISSING_PARAM "A required parameter was missing".
SCENARIO("a typing request whose typing is not a boolean is refused and changes nothing",
         "[conformance][client-server][typing][r13]")
{
    GIVEN("alice and bob in a room, and bob's sync position")
    {
        auto started = merovingian::homeserver::start_client_server(typing_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const room = typing_room(rt);
        auto const before = sync_typing(rt, room.bob, room.room_id, {});

        WHEN("alice sends typing as a string, as a number, without typing, a bad timeout, and a non-JSON body")
        {
            auto const as_string = put_typing(rt, room, R"({"typing":"yes","timeout":30000})");
            auto const as_number = put_typing(rt, room, R"({"typing":1,"timeout":30000})");
            auto const missing = put_typing(rt, room, R"({"timeout":30000})");
            auto const string_timeout = put_typing(rt, room, R"({"typing":true,"timeout":"30000"})");
            auto const negative_timeout = put_typing(rt, room, R"({"typing":true,"timeout":-1})");
            auto const not_json = put_typing(rt, room, R"({"typing":tru)");

            THEN("each is refused with its 400 errcode, and bob sees no typing change")
            {
                REQUIRE(as_string.status == 400U);
                REQUIRE(errcode_of(as_string) == "M_BAD_JSON");
                REQUIRE(as_number.status == 400U);
                REQUIRE(errcode_of(as_number) == "M_BAD_JSON");
                REQUIRE(missing.status == 400U);
                REQUIRE(errcode_of(missing) == "M_MISSING_PARAM");
                REQUIRE(string_timeout.status == 400U);
                REQUIRE(errcode_of(string_timeout) == "M_BAD_JSON");
                REQUIRE(negative_timeout.status == 400U);
                REQUIRE(errcode_of(negative_timeout) == "M_INVALID_PARAM");
                REQUIRE(not_json.status == 400U);
                REQUIRE(errcode_of(not_json) == "M_NOT_JSON");
                auto const after = sync_typing(rt, room.bob, room.room_id, before.next_batch);
                REQUIRE((!after.user_ids.has_value() || !contains(*after.user_ids, "@alice:example.org")));
            }
        }

        WHEN("alice sends a boolean typing")
        {
            REQUIRE(put_typing(rt, room, R"({"typing":true,"timeout":30000})").status == 200U);

            THEN("bob sees her typing (the positive counterpart)")
            {
                auto const after = sync_typing(rt, room.bob, room.room_id, before.next_batch);
                REQUIRE(after.user_ids.has_value());
                REQUIRE(contains(*after.user_ids, "@alice:example.org"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Typing Notifications; PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#typing-notifications
//
// "This tells the server that the user is typing for the next N milliseconds where N is the
// value specified in the timeout key." m.typing `user_ids`: "The list of user IDs typing in this
// room", which a client "MUST use ... to REPLACE its knowledge of every user who is currently
// typing". After N milliseconds the user is no longer typing, so the next m.typing omits them.
SCENARIO("a local user's typing expires after its timeout and other members are told",
         "[conformance][client-server][typing][r13]")
{
    GIVEN("alice and bob in a room")
    {
        auto started = merovingian::homeserver::start_client_server(typing_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const room = typing_room(rt);
        auto const initial = sync_typing(rt, room.bob, room.room_id, {});

        WHEN("alice types with a 1 second timeout")
        {
            REQUIRE(put_typing(rt, room, R"({"typing":true,"timeout":1000})").status == 200U);
            auto const typing = sync_typing(rt, room.bob, room.room_id, initial.next_batch);
            REQUIRE(typing.user_ids.has_value());
            REQUIRE(contains(*typing.user_ids, "@alice:example.org"));

            AND_WHEN("less than the timeout has passed")
            {
                std::ignore = merovingian::homeserver::expire_typing_notifications(
                    rt, std::chrono::steady_clock::now() + std::chrono::milliseconds{200});

                THEN("she is still typing and no update is sent")
                {
                    auto const later = sync_typing(rt, room.bob, room.room_id, typing.next_batch);
                    REQUIRE(!later.user_ids.has_value());
                }
            }

            AND_WHEN("the timeout has passed")
            {
                std::ignore = merovingian::homeserver::expire_typing_notifications(
                    rt, std::chrono::steady_clock::now() + std::chrono::seconds{2});

                THEN("bob's next sync carries an m.typing without her")
                {
                    auto const later = sync_typing(rt, room.bob, room.room_id, typing.next_batch);
                    REQUIRE(later.user_ids.has_value());
                    REQUIRE(!contains(*later.user_ids, "@alice:example.org"));
                }
            }
        }

        WHEN("alice types with a timeout far beyond what the server accepts")
        {
            REQUIRE(put_typing(rt, room, R"({"typing":true,"timeout":4000000000})").status == 200U);
            auto const typing = sync_typing(rt, room.bob, room.room_id, initial.next_batch);
            REQUIRE(typing.user_ids.has_value());
            REQUIRE(contains(*typing.user_ids, "@alice:example.org"));
            std::ignore = merovingian::homeserver::expire_typing_notifications(
                rt, std::chrono::steady_clock::now() + merovingian::homeserver::max_typing_timeout +
                        std::chrono::seconds{1});

            THEN("she stops typing once the server's ceiling has passed, so typing never sticks")
            {
                auto const later = sync_typing(rt, room.bob, room.room_id, typing.next_batch);
                REQUIRE(later.user_ids.has_value());
                REQUIRE(!contains(*later.user_ids, "@alice:example.org"));
            }
        }

        WHEN("alice types without a timeout")
        {
            REQUIRE(put_typing(rt, room, R"({"typing":true})").status == 200U);
            auto const typing = sync_typing(rt, room.bob, room.room_id, initial.next_batch);
            REQUIRE(typing.user_ids.has_value());
            std::ignore = merovingian::homeserver::expire_typing_notifications(
                rt, std::chrono::steady_clock::now() + merovingian::homeserver::default_typing_timeout +
                        std::chrono::seconds{1});

            THEN("the server's default timeout applies")
            {
                auto const later = sync_typing(rt, room.bob, room.room_id, typing.next_batch);
                REQUIRE(later.user_ids.has_value());
                REQUIRE(!contains(*later.user_ids, "@alice:example.org"));
            }
        }
    }
}
