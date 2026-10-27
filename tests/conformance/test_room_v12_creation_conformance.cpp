// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |          ROOM VERSION 12 CREATION AND UPGRADE CONFORMANCE TESTS         |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19, createRoom, POST /upgrade,       |
// |        m.room.create, m.room.power_levels; Room Version 12               |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                 |
// |        ../../docs/matrix-v1.19-spec/rooms/v12.md                         |
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
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto v12_config() -> merovingian::config::Config
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

[[nodiscard]] auto created_room_id(Reply const& reply) -> std::string
{
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto errcode_of(Reply const& reply) -> std::string
{
    auto const body = parse_object(reply.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

[[nodiscard]] auto state_content(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                 std::string_view type) -> merovingian::canonicaljson::Object
{
    auto const reply =
        call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/" + std::string{type} + "/", token);
    REQUIRE(reply.status == 200U);
    return parse_object(reply.body);
}

[[nodiscard]] auto events_level(merovingian::canonicaljson::Object const& power_levels, std::string_view type)
    -> std::optional<std::int64_t>
{
    auto const* events = object_member_as_object(power_levels, "events");
    auto const* level = events == nullptr ? nullptr : int_member(*events, type);
    return level == nullptr ? std::nullopt : std::optional<std::int64_t>{*level};
}

[[nodiscard]] auto state_default_of(merovingian::canonicaljson::Object const& power_levels) -> std::int64_t
{
    auto const* level = int_member(power_levels, "state_default");
    return level == nullptr ? 0 : *level;
}

} // namespace

// Spec: Matrix Client-Server API v1.19, m.room.power_levels `events`, and createRoom
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#mroompower_levels
//
// "when the server sends the initial power levels event during room creation in room
// versions 12 and higher, the m.room.tombstone event MUST be explicitly defined and given a
// power level higher than state_default. For example, power level 150. Clients may override
// this using the described power_level_content_override field."
SCENARIO("A room version 12 room's initial power levels define m.room.tombstone above state_default",
         "[conformance][rooms][room-v12][create-room]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(v12_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");

        WHEN("a version 12 room is created with each preset")
        {
            auto const preset = GENERATE(as<std::string>{}, "private_chat", "public_chat", "trusted_private_chat");
            auto const room_id = created_room_id(call(rt, "POST", "/_matrix/client/v3/createRoom", token,
                                                      R"({"room_version":"12","preset":")" + preset + R"("})"));

            THEN("the tombstone level is explicit and higher than state_default")
            {
                CAPTURE(preset);
                auto const power_levels = state_content(rt, token, room_id, "m.room.power_levels");
                auto const tombstone = events_level(power_levels, "m.room.tombstone");
                REQUIRE(tombstone.has_value());
                REQUIRE(*tombstone > state_default_of(power_levels));
            }
        }

        WHEN("the override raises state_default to 200")
        {
            auto const room_id =
                created_room_id(call(rt, "POST", "/_matrix/client/v3/createRoom", token,
                                     R"({"room_version":"12","power_level_content_override":{"state_default":200}})"));

            THEN("the tombstone level is still higher than state_default")
            {
                auto const power_levels = state_content(rt, token, room_id, "m.room.power_levels");
                auto const tombstone = events_level(power_levels, "m.room.tombstone");
                REQUIRE(tombstone.has_value());
                REQUIRE(*tombstone > 200);
            }
        }

        WHEN("the override sets the tombstone level itself")
        {
            auto const room_id = created_room_id(
                call(rt, "POST", "/_matrix/client/v3/createRoom", token,
                     R"({"room_version":"12","power_level_content_override":{"events":{"m.room.tombstone":175}}})"));

            THEN("the client's level is kept")
            {
                auto const power_levels = state_content(rt, token, room_id, "m.room.power_levels");
                REQUIRE(events_level(power_levels, "m.room.tombstone") == 175);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, m.room.power_levels `users`, and createRoom 400
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3createroom
//
// `users`: "In room versions 12 and higher it is not permitted to specify the room creators
// here." createRoom answers 400 when "The initial state implied by the parameters to the
// request is invalid ... (errcode set to M_INVALID_ROOM_STATE)".
SCENARIO("createRoom refuses a power_level_content_override that names a room version 12 creator",
         "[conformance][rooms][room-v12][create-room]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(v12_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");

        WHEN("the override gives the creator, or an additional creator, a power level")
        {
            auto const body =
                GENERATE(as<std::string>{},
                         R"({"room_version":"12","power_level_content_override":{"users":{"@alice:example.org":100}}})",
                         R"({"room_version":"12","creation_content":{"additional_creators":["@bob:example.org"]},)"
                         R"("power_level_content_override":{"users":{"@bob:example.org":50}}})");
            auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);

            THEN("the request is refused with 400 M_INVALID_ROOM_STATE and no room is created")
            {
                CAPTURE(body, reply.body);
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_INVALID_ROOM_STATE");
                auto const joined = parse_object(call(rt, "GET", "/_matrix/client/v3/joined_rooms", token).body);
                auto const* rooms = object_member_as_array(joined, "joined_rooms");
                REQUIRE(rooms != nullptr);
                REQUIRE(rooms->empty());
            }
        }

        WHEN("the override names an ordinary user")
        {
            auto const reply =
                call(rt, "POST", "/_matrix/client/v3/createRoom", token,
                     R"({"room_version":"12","power_level_content_override":{"users":{"@charlie:example.org":50}}})");

            THEN("the room is created with that user's level")
            {
                auto const room_id = created_room_id(reply);
                auto const power_levels = state_content(rt, token, room_id, "m.room.power_levels");
                auto const* users = object_member_as_object(power_levels, "users");
                REQUIRE(users != nullptr);
                auto const* charlie = int_member(*users, "@charlie:example.org");
                REQUIRE(charlie != nullptr);
                REQUIRE(*charlie == 50);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, m.room.create `additional_creators`; Room Version 12
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#mroomcreate
//       ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// additional_creators: "Each string MUST be a valid user ID for the room version." The v12
// auth rules reject a create event whose additional_creators "is not an array of strings
// where each string passes the same user ID validation applied to sender", so such a
// request implies invalid initial state: 400 M_INVALID_ROOM_STATE, not a server error.
SCENARIO("createRoom refuses additional_creators that are not valid user IDs",
         "[conformance][rooms][room-v12][create-room]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(v12_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");

        WHEN("additional_creators is not an array of valid user IDs")
        {
            auto const value = GENERATE(as<std::string>{}, R"("@bob:example.org")", R"(["@bob:example.org",42])",
                                        R"(["@bob:example.org","not-a-user-id"])", R"(["@invalid:dom$ain$.com"])");
            auto const reply =
                call(rt, "POST", "/_matrix/client/v3/createRoom", token,
                     R"({"room_version":"12","creation_content":{"additional_creators":)" + value + "}}");

            THEN("the request is refused with 400 M_INVALID_ROOM_STATE")
            {
                CAPTURE(value, reply.body);
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_INVALID_ROOM_STATE");
            }
        }

        WHEN("additional_creators lists valid user IDs")
        {
            auto const room_id = created_room_id(
                call(rt, "POST", "/_matrix/client/v3/createRoom", token,
                     R"({"room_version":"12","creation_content":{"additional_creators":["@bob:example.org"]}})"));

            THEN("the create event carries them")
            {
                auto const create = state_content(rt, token, room_id, "m.room.create");
                auto const* creators = object_member_as_array(create, "additional_creators");
                REQUIRE(creators != nullptr);
                REQUIRE(creators->size() == 1U);
                auto const* first = std::get_if<std::string>(&creators->front().storage());
                REQUIRE(first != nullptr);
                REQUIRE(*first == "@bob:example.org");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, ClientEvent `room_id`; Room Version 12 event format
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#room-event-format
//       ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// ClientEvent `room_id`: "Required: The ID of the room associated with this event. Will not
// be present on events that arrive through /sync, despite being required everywhere else."
// Room version 12 omits room_id from the m.room.create PDU only; a client still gets it.
SCENARIO("A room version 12 create event carries room_id in client responses",
         "[conformance][rooms][room-v12][client-event]")
{
    GIVEN("a version 12 room")
    {
        auto started = merovingian::homeserver::start_client_server(v12_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const room_id =
            created_room_id(call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"room_version":"12"})"));

        WHEN("the create event is read through /state, /event, /context and /messages")
        {
            auto const state_reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token);
            REQUIRE(state_reply.status == 200U);
            auto const parsed = merovingian::canonicaljson::parse_lossless(state_reply.body);
            auto const* state = std::get_if<merovingian::canonicaljson::Array>(&parsed.value.storage());
            REQUIRE(state != nullptr);
            auto create_event_id = std::string{};
            auto state_create_room_id = std::string{};
            for (auto const& entry : *state)
            {
                auto const* object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
                REQUIRE(object != nullptr);
                if (auto const* type = string_member(*object, "type"); type != nullptr && *type == "m.room.create")
                {
                    create_event_id = *string_member(*object, "event_id");
                    auto const* event_room_id = string_member(*object, "room_id");
                    state_create_room_id = event_room_id == nullptr ? std::string{} : *event_room_id;
                }
            }
            REQUIRE_FALSE(create_event_id.empty());
            auto const event_reply =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + create_event_id, token);
            auto const context_reply =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/context/" + create_event_id, token);
            auto const messages_reply =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=f&limit=1", token);
            // GET /state/{eventType}/{stateKey} `format`: "`event` will return the entire event in
            // the usual format suitable for clients, including fields like event ID, sender and
            // timestamp." (Added in v1.16.)
            auto const format_event_reply =
                call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.create/?format=event", token);

            THEN("every form names the room")
            {
                REQUIRE(state_create_room_id == room_id);
                REQUIRE(event_reply.status == 200U);
                auto const event_object = parse_object(event_reply.body);
                REQUIRE(string_member(event_object, "room_id") != nullptr);
                REQUIRE(*string_member(event_object, "room_id") == room_id);
                REQUIRE(context_reply.status == 200U);
                auto const context = parse_object(context_reply.body);
                auto const* context_event = object_member_as_object(context, "event");
                REQUIRE(context_event != nullptr);
                REQUIRE(string_member(*context_event, "room_id") != nullptr);
                REQUIRE(*string_member(*context_event, "room_id") == room_id);
                REQUIRE(messages_reply.status == 200U);
                auto const messages = parse_object(messages_reply.body);
                auto const* chunk = object_member_as_array(messages, "chunk");
                REQUIRE(chunk != nullptr);
                REQUIRE(chunk->size() == 1U);
                auto const* first = std::get_if<merovingian::canonicaljson::Object>(&chunk->front().storage());
                REQUIRE(first != nullptr);
                REQUIRE(*string_member(*first, "type") == "m.room.create");
                REQUIRE(string_member(*first, "room_id") != nullptr);
                REQUIRE(*string_member(*first, "room_id") == room_id);
                REQUIRE(format_event_reply.status == 200U);
                auto const format_event = parse_object(format_event_reply.body);
                REQUIRE(string_member(format_event, "event_id") != nullptr);
                REQUIRE(*string_member(format_event, "event_id") == create_event_id);
                REQUIRE(string_member(format_event, "sender") != nullptr);
                REQUIRE(object_member_as_object(format_event, "content") != nullptr);
                REQUIRE(string_member(format_event, "room_id") != nullptr);
                REQUIRE(*string_member(format_event, "room_id") == room_id);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, POST /rooms/{roomId}/upgrade and "Server behaviour"
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidupgrade
//
// additional_creators: "When upgrading to a room version which supports additional creators,
// the user IDs which should be considered room creators in addition to the user performing
// the upgrade. If the room being upgraded has additional creators, they are not
// automatically copied." The server "Replicates transferable state events to the new room",
// recommending m.room.power_levels, m.room.join_rules, m.room.name among others; and the new
// create event carries a `type` "copied from the predecessor room". In a version 12 room the
// creators "cannot be specified in the users field" of the power levels.
SCENARIO("Upgrading to room version 12 applies additional_creators and transfers the room's state",
         "[conformance][rooms][room-v12][room-upgrade]")
{
    GIVEN("a version 11 room with alice, bob and charlie, a name, and power levels for all three")
    {
        auto started = merovingian::homeserver::start_client_server(v12_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const charlie = register_and_login(rt, "charlie");
        auto const room_id = created_room_id(call(rt, "POST", "/_matrix/client/v3/createRoom", alice,
                                                  R"({"room_version":"11","preset":"public_chat","name":"Upgrade me",)"
                                                  R"("creation_content":{"type":"m.space"}})"));
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, bob, "{}").status == 200U);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, charlie, "{}").status == 200U);
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.power_levels/", alice,
                     R"({"users":{"@alice:example.org":100,"@bob:example.org":100,"@charlie:example.org":50}})")
                    .status == 200U);

        WHEN("alice upgrades it to version 12 naming bob as an additional creator")
        {
            auto const reply = call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", alice,
                                    R"({"new_version":"12","additional_creators":["@bob:example.org"]})");
            REQUIRE(reply.status == 200U);
            auto const reply_body = parse_object(reply.body);
            auto const* replacement = string_member(reply_body, "replacement_room");
            REQUIRE(replacement != nullptr);
            auto const new_room = *replacement;

            THEN("bob is an additional creator, and the room type is copied")
            {
                auto const create = state_content(rt, alice, new_room, "m.room.create");
                auto const* creators = object_member_as_array(create, "additional_creators");
                REQUIRE(creators != nullptr);
                REQUIRE(creators->size() == 1U);
                REQUIRE(*std::get_if<std::string>(&creators->front().storage()) == "@bob:example.org");
                REQUIRE(string_member(create, "type") != nullptr);
                REQUIRE(*string_member(create, "type") == "m.space");
            }

            THEN("the power levels are transferred without the new room's creators")
            {
                auto const power_levels = state_content(rt, alice, new_room, "m.room.power_levels");
                auto const* users = object_member_as_object(power_levels, "users");
                REQUIRE(users != nullptr);
                REQUIRE(users->size() == 1U);
                auto const* level = int_member(*users, "@charlie:example.org");
                REQUIRE(level != nullptr);
                REQUIRE(*level == 50);
            }

            THEN("the room name is transferred")
            {
                auto const name = state_content(rt, alice, new_room, "m.room.name");
                REQUIRE(string_member(name, "name") != nullptr);
                REQUIRE(*string_member(name, "name") == "Upgrade me");
            }
        }
    }
}
