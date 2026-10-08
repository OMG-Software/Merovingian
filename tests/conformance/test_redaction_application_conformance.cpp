// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for CSAZ-11: redactions are applied, served in their redacted form on every
// client read path, and `PUT /rooms/{roomId}/redact/{eventId}/{txnId}` exists.
//
// Spec: Matrix Client-Server API v1.19, "Redactions" and
// PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}; room versions' "Handling
// redactions" (rooms/v3.md ... rooms/v12.md).
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#redactions
//
// Spec MUST: "This stripped down event is thereafter returned anytime a client or remote server
// requests it." and "Servers should include a copy of the `m.room.redaction` event under
// `unsigned` as `redacted_because` when serving the redacted event to clients."

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto redaction_config() -> merovingian::config::Config
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

[[nodiscard]] auto sqlite_redaction_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
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

[[nodiscard]] auto user_id(std::string const& localpart) -> std::string
{
    return "@" + localpart + ":example.org";
}

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token, std::string_view room_version)
    -> std::string
{
    auto const reply =
        call(rt, "POST", "/_matrix/client/v3/createRoom", token,
             std::string{R"({"preset":"public_chat","room_version":")"} + std::string{room_version} + R"("})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

auto invite_and_join(ClientServerRuntime& rt, std::string const& inviter_token, std::string const& room_id,
                     std::string const& localpart, std::string const& invitee_token) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", inviter_token,
                 R"({"user_id":")" + user_id(localpart) + R"("})")
                .status == 200U);
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", invitee_token, "{}").status == 200U);
}

// Replaces the room's power levels so `moderator` has level 50 and `admin` 100 (the redact level
// is the default, 50).
auto set_power_levels(ClientServerRuntime& rt, std::string const& admin_token, std::string const& room_id,
                      std::string const& admin, std::string const& moderator) -> void
{
    auto const body = std::string{R"({"users":{")"} + user_id(admin) + R"(":100,")" + user_id(moderator) +
                      R"(":50},"users_default":0,"events_default":0,"state_default":50,"ban":50,"kick":50,)"
                      R"("redact":50,"invite":0})";
    REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.power_levels", admin_token, body)
                .status == 200U);
}

[[nodiscard]] auto send_text(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                             std::string_view text) -> std::string
{
    static auto counter = std::uint64_t{0U};
    auto const reply =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/ra" + std::to_string(++counter),
             token, std::string{R"({"msgtype":"m.text","body":")"} + std::string{text} + R"("})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* event_id = string_member(parsed, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

[[nodiscard]] auto redact(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                          std::string const& event_id, std::string const& txn_id, std::string reason = "spam") -> Reply
{
    return call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/redact/" + event_id + "/" + txn_id, token,
                std::string{R"({"reason":")"} + reason + R"("})");
}

[[nodiscard]] auto event_id_of(Reply const& reply) -> std::string
{
    auto const parsed = parse_object(reply.body);
    auto const* event_id = string_member(parsed, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

[[nodiscard]] auto fetch_event(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                               std::string const& event_id) -> Reply
{
    return call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id, token);
}

// True when `event` is the redacted form of an event whose body was `secret`: no `body`, and
// `unsigned.redacted_because` is an m.room.redaction event with `redaction_id`.
auto require_redacted_form(merovingian::canonicaljson::Object const& event, std::string const& redaction_id) -> void
{
    // Spec MUST: the stripped-down event is returned; `body` is not a key the algorithm keeps.
    auto const* content = object_member_as_object(event, "content");
    REQUIRE(content != nullptr);
    REQUIRE(object_member(*content, "body") == nullptr);
    // Spec: servers include the redaction event under `unsigned` as `redacted_because`.
    auto const* unsigned_data = object_member_as_object(event, "unsigned");
    REQUIRE(unsigned_data != nullptr);
    auto const* because = object_member_as_object(*unsigned_data, "redacted_because");
    REQUIRE(because != nullptr);
    auto const* type = string_member(*because, "type");
    REQUIRE(type != nullptr);
    REQUIRE(*type == "m.room.redaction");
    auto const* because_id = string_member(*because, "event_id");
    REQUIRE(because_id != nullptr);
    REQUIRE(*because_id == redaction_id);
}

auto require_unredacted(merovingian::canonicaljson::Object const& event, std::string_view expected_body) -> void
{
    auto const* content = object_member_as_object(event, "content");
    REQUIRE(content != nullptr);
    auto const* body = string_member(*content, "body");
    REQUIRE(body != nullptr);
    REQUIRE(*body == expected_body);
    auto const* unsigned_data = object_member_as_object(event, "unsigned");
    REQUIRE((unsigned_data == nullptr || object_member(*unsigned_data, "redacted_because") == nullptr));
}

[[nodiscard]] auto find_in_array(merovingian::canonicaljson::Array const* array, std::string const& event_id)
    -> merovingian::canonicaljson::Object const*
{
    if (array == nullptr)
    {
        return nullptr;
    }
    for (auto const& value : *array)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        auto const* id = event == nullptr ? nullptr : string_member(*event, "event_id");
        if (id != nullptr && *id == event_id)
        {
            return event;
        }
    }
    return nullptr;
}

// The stored (federation) JSON of an event, straight from the persistent store.
[[nodiscard]] auto stored_event(ClientServerRuntime& rt, std::string const& event_id)
    -> std::optional<merovingian::canonicaljson::Object>
{
    for (auto const& event : rt.homeserver.database.persistent_store.events)
    {
        if (event.event_id == event_id)
        {
            return parse_object(event.json);
        }
    }
    return std::nullopt;
}

} // namespace

// Spec: Matrix Client-Server API v1.19, PUT /rooms/{roomId}/redact/{eventId}/{txnId} and "Redactions".
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#redactions
//
// "Any user with a power level greater than or equal to the `m.room.redaction` event power level
// may send redactions for their own events in the room." "This stripped down event is thereafter
// returned anytime a client or remote server requests it."
SCENARIO("A redacted message is served in its redacted form on every client read path",
         "[csaz-11][redaction][conformance][client-server]")
{
    GIVEN("a room v10 with alice and bob, and a message from alice")
    {
        auto started = merovingian::homeserver::start_client_server(redaction_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice, "10");
        invite_and_join(rt, alice, room_id, "bob", bob);
        auto const message_id = send_text(rt, alice, room_id, "secret text");

        WHEN("alice redacts her message with PUT /redact")
        {
            auto const first = redact(rt, alice, room_id, message_id, "txn-1");
            auto const replay = redact(rt, alice, room_id, message_id, "txn-1");

            THEN("the response carries the redaction's event_id and the same txnId returns the same event_id")
            {
                // Spec: 200 "An ID for the redaction event."
                REQUIRE(first.status == 200U);
                auto const redaction_id = event_id_of(first);
                REQUIRE(!redaction_id.empty());
                // Spec: the txnId "will be used by the server to ensure idempotency of requests".
                REQUIRE(replay.status == 200U);
                REQUIRE(event_id_of(replay) == redaction_id);
            }

            THEN("GET /event returns the redacted form with unsigned.redacted_because")
            {
                auto const redaction_id = event_id_of(first);
                auto const reply = fetch_event(rt, bob, room_id, message_id);
                REQUIRE(reply.status == 200U);
                auto const event = parse_object(reply.body);
                require_redacted_form(event, redaction_id);
                // The redaction algorithm keeps the sender and type.
                REQUIRE(*string_member(event, "sender") == user_id("alice"));
                REQUIRE(*string_member(event, "type") == "m.room.message");
            }

            THEN("GET /messages returns the redacted form and the redaction event itself")
            {
                auto const redaction_id = event_id_of(first);
                auto const reply =
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=50", bob);
                REQUIRE(reply.status == 200U);
                auto const parsed = parse_object(reply.body);
                auto const* chunk = object_member_as_array(parsed, "chunk");
                auto const* message = find_in_array(chunk, message_id);
                REQUIRE(message != nullptr);
                require_redacted_form(*message, redaction_id);
                // Spec: the redaction event is delivered to clients once it applies.
                REQUIRE(find_in_array(chunk, redaction_id) != nullptr);
            }

            THEN("GET /context returns the redacted form")
            {
                auto const redaction_id = event_id_of(first);
                auto const reply =
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/context/" + message_id + "?limit=5", bob);
                REQUIRE(reply.status == 200U);
                auto const parsed = parse_object(reply.body);
                auto const* target = object_member_as_object(parsed, "event");
                REQUIRE(target != nullptr);
                require_redacted_form(*target, redaction_id);
            }

            THEN("an initial GET /sync returns the redacted form in the timeline")
            {
                auto const redaction_id = event_id_of(first);
                auto const reply = call(rt, "GET", "/_matrix/client/v3/sync", bob);
                REQUIRE(reply.status == 200U);
                auto const parsed = parse_object(reply.body);
                auto const* rooms = object_member_as_object(parsed, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* joined = object_member_as_object(*rooms, "join");
                REQUIRE(joined != nullptr);
                auto const* room = object_member_as_object(*joined, room_id);
                REQUIRE(room != nullptr);
                auto const* timeline = object_member_as_object(*room, "timeline");
                REQUIRE(timeline != nullptr);
                auto const* events = object_member_as_array(*timeline, "events");
                auto const* message = find_in_array(events, message_id);
                REQUIRE(message != nullptr);
                require_redacted_form(*message, redaction_id);
                REQUIRE(find_in_array(events, redaction_id) != nullptr);
            }

            THEN("sliding sync returns the redacted form in the room timeline")
            {
                auto const redaction_id = event_id_of(first);
                auto const reply =
                    call(rt, "POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?timeout=0", bob,
                         R"({"lists":{"all":{"ranges":[[0,9]],"timeline_limit":20,)"
                         R"("required_state":[["m.room.name",""]]}}})");
                REQUIRE(reply.status == 200U);
                auto const parsed = parse_object(reply.body);
                auto const* rooms = object_member_as_object(parsed, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* room = object_member_as_object(*rooms, room_id);
                REQUIRE(room != nullptr);
                auto const* message = find_in_array(object_member_as_array(*room, "timeline"), message_id);
                REQUIRE(message != nullptr);
                require_redacted_form(*message, redaction_id);
            }

            THEN("the original text is not found by POST /search")
            {
                auto const reply = call(rt, "POST", "/_matrix/client/v3/search", bob,
                                        R"({"search_categories":{"room_events":{"search_term":"secret"}}})");
                REQUIRE(reply.status == 200U);
                REQUIRE(reply.body.find("secret text") == std::string::npos);
            }

            THEN("the original content is no longer held in the stored event")
            {
                auto const stored = stored_event(rt, message_id);
                REQUIRE(stored.has_value());
                auto const* content = object_member_as_object(*stored, "content");
                REQUIRE(content != nullptr);
                REQUIRE(object_member(*content, "body") == nullptr);
                // The hashes and signatures survive, so the redacted form still verifies over federation.
                REQUIRE(object_member(*stored, "hashes") != nullptr);
                REQUIRE(object_member(*stored, "signatures") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Events relationships" -> "Aggregations":
// "when a child event is redacted then the relationship is broken."
SCENARIO("A redacted child event is no longer returned by /relations", "[csaz-11][redaction][conformance][relations]")
{
    GIVEN("a message with a thread reply")
    {
        auto started = merovingian::homeserver::start_client_server(redaction_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, alice, "10");
        auto const root_id = send_text(rt, alice, room_id, "root");
        auto const reply_reply =
            call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/rel1", alice,
                 R"({"msgtype":"m.text","body":"child","m.relates_to":{"rel_type":"m.thread","event_id":")" + root_id +
                     R"("}})");
        REQUIRE(reply_reply.status == 200U);
        auto const child_id = event_id_of(reply_reply);

        auto const before = call(rt, "GET", "/_matrix/client/v1/rooms/" + room_id + "/relations/" + root_id, alice);
        REQUIRE(before.status == 200U);
        REQUIRE(find_in_array(object_member_as_array(parse_object(before.body), "chunk"), child_id) != nullptr);

        WHEN("the child is redacted")
        {
            REQUIRE(redact(rt, alice, room_id, child_id, "rel-redact").status == 200U);

            THEN("the relationship is broken: /relations no longer lists the child")
            {
                auto const after =
                    call(rt, "GET", "/_matrix/client/v1/rooms/" + room_id + "/relations/" + root_id, alice);
                REQUIRE(after.status == 200U);
                auto const parsed = parse_object(after.body);
                REQUIRE(find_in_array(object_member_as_array(parsed, "chunk"), child_id) == nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, PUT /rooms/{roomId}/redact/{eventId}/{txnId}:
// "Any user with a power level greater than or equal to the `m.room.redaction` event power level
// may send redactions for their own events in the room. If the user's power level is also greater
// than or equal to the `redact` power level of the room, the user may redact events sent by other
// users."
SCENARIO("Redacting another user's event needs the redact power level",
         "[csaz-11][redaction][conformance][power-levels]")
{
    GIVEN("a room v10 where alice has level 100, carol level 50 and bob level 0, and a message from alice")
    {
        auto started = merovingian::homeserver::start_client_server(redaction_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice, "10");
        invite_and_join(rt, alice, room_id, "bob", bob);
        invite_and_join(rt, alice, room_id, "carol", carol);
        set_power_levels(rt, alice, room_id, "alice", "carol");
        auto const message_id = send_text(rt, alice, room_id, "alice's words");

        WHEN("bob, who has level 0, tries to redact alice's message")
        {
            auto const reply = redact(rt, bob, room_id, message_id, "bob-1");

            THEN("it is refused with 403 M_FORBIDDEN and the message is unchanged")
            {
                // Spec: only a user with the `redact` level may redact another user's event.
                REQUIRE(reply.status == 403U);
                REQUIRE(*string_member(parse_object(reply.body), "errcode") == "M_FORBIDDEN");
                auto const event = fetch_event(rt, alice, room_id, message_id);
                REQUIRE(event.status == 200U);
                require_unredacted(parse_object(event.body), "alice's words");
            }
        }

        WHEN("bob redacts his own message")
        {
            auto const own_id = send_text(rt, bob, room_id, "bob's words");
            auto const reply = redact(rt, bob, room_id, own_id, "bob-2");

            THEN("it applies: a user may redact their own events")
            {
                REQUIRE(reply.status == 200U);
                auto const event = fetch_event(rt, alice, room_id, own_id);
                REQUIRE(event.status == 200U);
                require_redacted_form(parse_object(event.body), event_id_of(reply));
            }
        }

        WHEN("carol, who has the redact level, redacts alice's message")
        {
            auto const reply = redact(rt, carol, room_id, message_id, "carol-1");

            THEN("it applies")
            {
                REQUIRE(reply.status == 200U);
                auto const event = fetch_event(rt, bob, room_id, message_id);
                REQUIRE(event.status == 200U);
                require_redacted_form(parse_object(event.body), event_id_of(reply));
            }
        }

        WHEN("a user who is not in the room tries to redact")
        {
            auto const dave = register_and_login(rt, "dave");
            auto const reply = redact(rt, dave, room_id, message_id, "dave-1");

            THEN("it is refused and the message is unchanged")
            {
                REQUIRE(reply.status == 403U);
                auto const event = fetch_event(rt, alice, room_id, message_id);
                require_unredacted(parse_object(event.body), "alice's words");
            }
        }

        WHEN("the redact request has no access token")
        {
            auto const reply =
                call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/redact/" + message_id + "/u1", {}, "{}");

            THEN("it is refused with 401 M_MISSING_TOKEN")
            {
                REQUIRE(reply.status == 401U);
            }
        }

        WHEN("alice redacts an event id the room does not contain")
        {
            auto const reply = redact(rt, alice, room_id, "$doesNotExist", "alice-x");

            THEN("it is refused with 404 M_NOT_FOUND")
            {
                REQUIRE(reply.status == 404U);
                REQUIRE(*string_member(parse_object(reply.body), "errcode") == "M_NOT_FOUND");
            }
        }
    }
}

// Spec: rooms/v11.md "Moving the `redacts` property of `m.room.redaction` events to a `content`
// property" and Client-Server API PUT /send: "Homeservers MUST allow clients to send
// `m.room.redaction` events with this endpoint for all room versions. In rooms with a version
// older than 11 they MUST move the `redacts` property inside the `content` to the top level of
// the event."
SCENARIO("The redacts property is in content from room v11 and top-level before it",
         "[csaz-11][redaction][conformance][room-versions]")
{
    GIVEN("a v10 room and a v11 room, each with a message from alice")
    {
        auto started = merovingian::homeserver::start_client_server(redaction_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const v10_room = create_room(rt, alice, "10");
        auto const v11_room = create_room(rt, alice, "11");
        auto const v10_message = send_text(rt, alice, v10_room, "ten");
        auto const v11_message = send_text(rt, alice, v11_room, "eleven");

        WHEN("alice redacts both with PUT /redact")
        {
            auto const v10_redaction = event_id_of(redact(rt, alice, v10_room, v10_message, "v10-1"));
            auto const v11_redaction = event_id_of(redact(rt, alice, v11_room, v11_message, "v11-1"));

            THEN("the stored v10 redaction has a top-level redacts and no content.redacts")
            {
                auto const stored = stored_event(rt, v10_redaction);
                REQUIRE(stored.has_value());
                auto const* top_level = string_member(*stored, "redacts");
                REQUIRE(top_level != nullptr);
                REQUIRE(*top_level == v10_message);
                auto const* content = object_member_as_object(*stored, "content");
                REQUIRE(content != nullptr);
                REQUIRE(object_member(*content, "redacts") == nullptr);
            }

            THEN("the stored v11 redaction has redacts in content and none at the top level")
            {
                auto const stored = stored_event(rt, v11_redaction);
                REQUIRE(stored.has_value());
                REQUIRE(object_member(*stored, "redacts") == nullptr);
                auto const* content = object_member_as_object(*stored, "content");
                REQUIRE(content != nullptr);
                auto const* in_content = string_member(*content, "redacts");
                REQUIRE(in_content != nullptr);
                REQUIRE(*in_content == v11_message);
            }

            THEN("both redactions applied, and clients are served both forms of redacts")
            {
                // Spec SHOULD (rooms/v11.md): servers add `redacts` at the top level for v11+ events and
                // in `content` for older versions when serving them over the Client-Server API.
                for (auto const& [room, message, redaction] : {
                         std::tuple{v10_room, v10_message, v10_redaction},
                         std::tuple{v11_room, v11_message, v11_redaction}
                })
                {
                    auto const target = fetch_event(rt, alice, room, message);
                    REQUIRE(target.status == 200U);
                    require_redacted_form(parse_object(target.body), redaction);
                    auto const served = parse_object(fetch_event(rt, alice, room, redaction).body);
                    auto const* top_level = string_member(served, "redacts");
                    REQUIRE(top_level != nullptr);
                    REQUIRE(*top_level == message);
                    auto const* content = object_member_as_object(served, "content");
                    REQUIRE(content != nullptr);
                    auto const* in_content = string_member(*content, "redacts");
                    REQUIRE(in_content != nullptr);
                    REQUIRE(*in_content == message);
                }
            }
        }

        WHEN("alice sends m.room.redaction through PUT /send with redacts in content, in the v10 room")
        {
            auto const reply = call(rt, "PUT", "/_matrix/client/v3/rooms/" + v10_room + "/send/m.room.redaction/sendr1",
                                    alice, R"({"redacts":")" + v10_message + R"(","reason":"via send"})");

            THEN("the redacts property is moved to the top level and the redaction applies")
            {
                REQUIRE(reply.status == 200U);
                auto const redaction_id = event_id_of(reply);
                auto const stored = stored_event(rt, redaction_id);
                REQUIRE(stored.has_value());
                auto const* top_level = string_member(*stored, "redacts");
                REQUIRE(top_level != nullptr);
                REQUIRE(*top_level == v10_message);
                auto const target = fetch_event(rt, alice, v10_room, v10_message);
                require_redacted_form(parse_object(target.body), redaction_id);
            }
        }

        WHEN("a client sends a forbidden redaction through PUT /send")
        {
            auto const bob = register_and_login(rt, "bob");
            invite_and_join(rt, alice, v10_room, "bob", bob);
            auto const reply = call(rt, "PUT", "/_matrix/client/v3/rooms/" + v10_room + "/send/m.room.redaction/sendr2",
                                    bob, R"({"redacts":")" + v10_message + R"("})");

            THEN("the same validity check refuses it and nothing is redacted")
            {
                REQUIRE(reply.status == 403U);
                require_unredacted(parse_object(fetch_event(rt, alice, v10_room, v10_message).body), "ten");
            }
        }
    }
}

// Spec: Client-Server API "Redactions": "Redacted events can still affect the state of the room.
// When redacted, state events behave as though their properties were simply not specified, except
// those protected by the redaction algorithm. For example, a redacted `join` event will still
// result in the user being considered joined. Similarly, a redacted topic does not necessarily
// cause the topic to revert to what it was prior to the event - it causes the topic to be removed
// from the room."
SCENARIO("Redacting a state event keeps the room working and keeps the protected keys",
         "[csaz-11][redaction][conformance][state]")
{
    GIVEN("a room v10 with a topic, and a joined member bob")
    {
        auto started = merovingian::homeserver::start_client_server(redaction_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice, "10");
        invite_and_join(rt, alice, room_id, "bob", bob);
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic", alice,
                     R"({"topic":"a secret topic"})")
                    .status == 200U);
        auto const topic_event_id = [&]() {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state", alice);
            REQUIRE(reply.status == 200U);
            auto const parsed = merovingian::canonicaljson::parse_lossless(reply.body);
            auto const* array = std::get_if<merovingian::canonicaljson::Array>(&parsed.value.storage());
            REQUIRE(array != nullptr);
            for (auto const& value : *array)
            {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                if (event != nullptr && *string_member(*event, "type") == "m.room.topic")
                {
                    return *string_member(*event, "event_id");
                }
            }
            FAIL("the topic state event was not found");
            return std::string{};
        }();

        WHEN("alice redacts the topic event")
        {
            auto const redaction = redact(rt, alice, room_id, topic_event_id, "topic-1");
            REQUIRE(redaction.status == 200U);

            THEN("the topic is removed from the room but the state event remains, redacted")
            {
                auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state", bob);
                REQUIRE(reply.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(reply.body);
                auto const* array = std::get_if<merovingian::canonicaljson::Array>(&parsed.value.storage());
                REQUIRE(array != nullptr);
                auto const* topic = find_in_array(array, topic_event_id);
                REQUIRE(topic != nullptr);
                auto const* content = object_member_as_object(*topic, "content");
                REQUIRE(content != nullptr);
                REQUIRE(object_member(*content, "topic") == nullptr);
                auto const* unsigned_data = object_member_as_object(*topic, "unsigned");
                REQUIRE(unsigned_data != nullptr);
                REQUIRE(object_member_as_object(*unsigned_data, "redacted_because") != nullptr);
                // Protected keys of the redaction algorithm: type and state_key survive.
                REQUIRE(*string_member(*topic, "type") == "m.room.topic");
                REQUIRE(string_member(*topic, "state_key") != nullptr);
            }

            THEN("the room keeps working: members can still send and read")
            {
                REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/after1", bob,
                             R"({"msgtype":"m.text","body":"still here"})")
                            .status == 200U);
                REQUIRE(call(rt, "GET", "/_matrix/client/v3/sync", alice).status == 200U);
            }
        }

        WHEN("alice redacts bob's join event")
        {
            auto const member_event_id = [&]() {
                auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state", alice);
                auto const parsed = merovingian::canonicaljson::parse_lossless(reply.body);
                auto const* array = std::get_if<merovingian::canonicaljson::Array>(&parsed.value.storage());
                REQUIRE(array != nullptr);
                for (auto const& value : *array)
                {
                    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                    if (event != nullptr && *string_member(*event, "type") == "m.room.member" &&
                        *string_member(*event, "state_key") == user_id("bob"))
                    {
                        return *string_member(*event, "event_id");
                    }
                }
                FAIL("bob's member event was not found");
                return std::string{};
            }();
            REQUIRE(redact(rt, alice, room_id, member_event_id, "member-1").status == 200U);

            THEN("bob is still joined: a redacted join still results in the user being considered joined")
            {
                REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/after2", bob,
                             R"({"msgtype":"m.text","body":"I am still joined"})")
                            .status == 200U);
                auto const stored = stored_event(rt, member_event_id);
                REQUIRE(stored.has_value());
                auto const* content = object_member_as_object(*stored, "content");
                REQUIRE(content != nullptr);
                // The protected key survives the redaction algorithm.
                REQUIRE(*string_member(*content, "membership") == "join");
            }
        }
    }
}

// Spec: Client-Server API "Redactions": "Redacting an event cannot be undone, allowing server
// owners to delete the offending content from the databases."
SCENARIO("An applied redaction survives a restart and the original content is gone from the database",
         "[csaz-11][redaction][conformance][sqlite][restart]")
{
    GIVEN("a SQLite-backed homeserver with a redacted message")
    {
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        auto const sqlite_path = merovingian::tests::temporary_directory() /
                                 ("merovingian-redaction-restart-" + std::to_string(now) + ".sqlite3");
        std::filesystem::remove(sqlite_path);
        auto const config = sqlite_redaction_config(sqlite_path);

        auto alice = std::string{};
        auto room_id = std::string{};
        auto message_id = std::string{};
        auto redaction_id = std::string{};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            auto& rt = started.runtime;
            alice = register_and_login(rt, "alice");
            room_id = create_room(rt, alice, "10");
            message_id = send_text(rt, alice, room_id, "restart secret");
            redaction_id = event_id_of(redact(rt, alice, room_id, message_id, "restart-1"));
        }

        WHEN("the runtime is started again from the same SQLite file")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto& rt = restarted.runtime;

            THEN("the message is still served redacted with redacted_because")
            {
                auto const reply = fetch_event(rt, alice, room_id, message_id);
                REQUIRE(reply.status == 200U);
                require_redacted_form(parse_object(reply.body), redaction_id);
            }

            THEN("the redaction event is still delivered to clients")
            {
                auto const reply =
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=50", alice);
                REQUIRE(reply.status == 200U);
                auto const parsed = parse_object(reply.body);
                REQUIRE(find_in_array(object_member_as_array(parsed, "chunk"), redaction_id) != nullptr);
            }

            THEN("no stored event still holds the original text")
            {
                for (auto const& event : rt.homeserver.database.persistent_store.events)
                {
                    REQUIRE(event.json.find("restart secret") == std::string::npos);
                }
            }
        }
        std::filesystem::remove(sqlite_path);
    }
}

// Spec: Client-Server API "Redactions": "Redacting an event cannot be undone". A server upgraded from
// a version that accepted redactions but never applied them holds redactions whose targets are still
// whole; starting up applies them.
SCENARIO("A redaction stored but never applied is applied when the server starts",
         "[csaz-11][redaction][conformance][sqlite][restart][upgrade]")
{
    GIVEN("a SQLite-backed homeserver where a redaction was accepted without being applied")
    {
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        auto const sqlite_path = merovingian::tests::temporary_directory() /
                                 ("merovingian-redaction-upgrade-" + std::to_string(now) + ".sqlite3");
        std::filesystem::remove(sqlite_path);
        auto const config = sqlite_redaction_config(sqlite_path);

        auto alice = std::string{};
        auto room_id = std::string{};
        auto message_id = std::string{};
        auto redaction_id = std::string{};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            auto& rt = started.runtime;
            alice = register_and_login(rt, "alice");
            room_id = create_room(rt, alice, "10");
            message_id = send_text(rt, alice, room_id, "upgrade secret");
            // The previous version stored the redaction and did nothing else with it.
            rt.homeserver.database.persistent_store.redaction_observer = nullptr;
            redaction_id = event_id_of(redact(rt, alice, room_id, message_id, "upgrade-1"));
            auto const unapplied = fetch_event(rt, alice, room_id, message_id);
            REQUIRE(unapplied.status == 200U);
            require_unredacted(parse_object(unapplied.body), "upgrade secret");
        }

        WHEN("the server is started again")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto& rt = restarted.runtime;

            THEN("the message is redacted and the redaction event is delivered")
            {
                auto const reply = fetch_event(rt, alice, room_id, message_id);
                REQUIRE(reply.status == 200U);
                require_redacted_form(parse_object(reply.body), redaction_id);
                REQUIRE(fetch_event(rt, alice, room_id, redaction_id).status == 200U);
            }

            THEN("the original text is gone from the stored events")
            {
                for (auto const& event : rt.homeserver.database.persistent_store.events)
                {
                    REQUIRE(event.json.find("upgrade secret") == std::string::npos);
                }
            }
        }
        std::filesystem::remove(sqlite_path);
    }
}

// Spec: the suspension rules allow "redact their own events" while suspended.
SCENARIO("A suspended user may redact their own events but not anyone else's",
         "[csaz-11][redaction][conformance][suspension]")
{
    GIVEN("a room v10 where bob is suspended, with messages from alice and bob")
    {
        auto started = merovingian::homeserver::start_client_server(redaction_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice, "10");
        invite_and_join(rt, alice, room_id, "bob", bob);
        set_power_levels(rt, alice, room_id, "alice", "bob");
        auto const alice_message = send_text(rt, alice, room_id, "alice words");
        auto const bob_message = send_text(rt, bob, room_id, "bob words");
        for (auto& account : rt.homeserver.database.persistent_store.users)
        {
            if (account.user_id == user_id("bob"))
            {
                account.suspended = true;
            }
        }

        WHEN("bob, who has the redact level, redacts alice's message")
        {
            auto const reply = redact(rt, bob, room_id, alice_message, "susp-1");

            THEN("it is refused with M_USER_SUSPENDED and nothing is redacted")
            {
                REQUIRE(reply.status == 403U);
                REQUIRE(*string_member(parse_object(reply.body), "errcode") == "M_USER_SUSPENDED");
                require_unredacted(parse_object(fetch_event(rt, alice, room_id, alice_message).body), "alice words");
            }
        }

        WHEN("bob redacts his own message")
        {
            auto const reply = redact(rt, bob, room_id, bob_message, "susp-2");

            THEN("it applies")
            {
                REQUIRE(reply.status == 200U);
                require_redacted_form(parse_object(fetch_event(rt, alice, room_id, bob_message).body),
                                      event_id_of(reply));
            }
        }
    }
}

// Spec (PUT /redact): "Server administrators may redact events sent by users on their server."
SCENARIO("A server administrator may redact an event sent by a user on their server",
         "[csaz-11][redaction][conformance][admin]")
{
    GIVEN("a room v10 where bob, a server administrator, has level 0, and a message from alice")
    {
        auto started = merovingian::homeserver::start_client_server(redaction_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice, "10");
        invite_and_join(rt, alice, room_id, "bob", bob);
        invite_and_join(rt, alice, room_id, "carol", carol);
        auto const alice_message = send_text(rt, alice, room_id, "alice words");
        for (auto& account : rt.homeserver.database.persistent_store.users)
        {
            if (account.user_id == user_id("bob"))
            {
                account.admin = true;
            }
        }
        for (auto& account : rt.homeserver.database.users)
        {
            if (account.user_id == user_id("bob"))
            {
                account.admin = true;
            }
        }

        WHEN("the administrator redacts alice's message")
        {
            auto const reply = redact(rt, bob, room_id, alice_message, "admin-1");

            THEN("it applies although bob's power level is below the redact level")
            {
                REQUIRE(reply.status == 200U);
                require_redacted_form(parse_object(fetch_event(rt, alice, room_id, alice_message).body),
                                      event_id_of(reply));
            }
        }

        WHEN("a user who is not an administrator redacts alice's message")
        {
            auto const reply = redact(rt, carol, room_id, alice_message, "admin-2");

            THEN("it is refused")
            {
                REQUIRE(reply.status == 403U);
            }
        }
    }
}

// Spec: rooms/v12.md "Handling redactions" and MSC4289: a room creator's power level is infinite, so it
// is at least the redact level.
SCENARIO("In a room v12 the creator may redact another user's event and others only their own",
         "[csaz-11][redaction][conformance][room-versions][v12]")
{
    GIVEN("a room v12 created by alice, with a message from bob")
    {
        auto started = merovingian::homeserver::start_client_server(redaction_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice, "12");
        invite_and_join(rt, alice, room_id, "bob", bob);
        invite_and_join(rt, alice, room_id, "carol", carol);
        auto const bob_message = send_text(rt, bob, room_id, "bob words");

        WHEN("carol, who has level 0, tries to redact bob's message")
        {
            auto const reply = redact(rt, carol, room_id, bob_message, "v12-1");

            THEN("it is refused and the message is unchanged")
            {
                REQUIRE(reply.status == 403U);
                require_unredacted(parse_object(fetch_event(rt, alice, room_id, bob_message).body), "bob words");
            }
        }

        WHEN("alice, the creator, redacts bob's message")
        {
            auto const reply = redact(rt, alice, room_id, bob_message, "v12-2");

            THEN("it applies, with redacts in content")
            {
                REQUIRE(reply.status == 200U);
                auto const redaction_id = event_id_of(reply);
                require_redacted_form(parse_object(fetch_event(rt, bob, room_id, bob_message).body), redaction_id);
                auto const stored = stored_event(rt, redaction_id);
                REQUIRE(stored.has_value());
                REQUIRE(object_member(*stored, "redacts") == nullptr);
                auto const* content = object_member_as_object(*stored, "content");
                REQUIRE(content != nullptr);
                REQUIRE(string_member(*content, "redacts") != nullptr);
            }
        }
    }
}
