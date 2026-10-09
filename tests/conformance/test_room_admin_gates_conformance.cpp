// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for CSAZ-12: event reports, room upgrades, directory visibility and room
// aliases are refused to users who may not perform them, and refused before anything changes.
//
// Spec: Matrix Client-Server API v1.19 — POST /rooms/{roomId}/report/{eventId}, POST
// /rooms/{roomId}/upgrade, PUT /directory/list/room/{roomId}, PUT and DELETE
// /directory/room/{roomAlias}; Appendices, "Room aliases".
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto gates_config() -> merovingian::config::Config
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

[[nodiscard]] auto errcode_of(Reply const& reply) -> std::string
{
    auto const body = parse_object(reply.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
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

auto make_server_admin(ClientServerRuntime& rt, std::string const& localpart) -> void
{
    for (auto& account : rt.homeserver.database.persistent_store.users)
    {
        if (account.user_id == user_id(localpart))
        {
            account.admin = true;
        }
    }
    for (auto& account : rt.homeserver.database.users)
    {
        if (account.user_id == user_id(localpart))
        {
            account.admin = true;
        }
    }
}

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

auto join(ClientServerRuntime& rt, std::string const& token, std::string const& room_id) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", token, "{}").status == 200U);
}

[[nodiscard]] auto send_text(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                             std::string const& txn) -> std::string
{
    auto const reply = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn, token,
                            R"({"msgtype":"m.text","body":"reportable"})");
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* event_id = string_member(body, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

// Sets the room's power levels: `levels` is the `users` object's members, e.g. "\"@bob:example.org\":50".
auto set_users_power(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                     std::string const& levels) -> void
{
    REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.power_levels", token,
                 R"({"users":{)" + levels +
                     R"(},"users_default":0,"events_default":0,"state_default":50,"ban":50,"kick":50,)"
                     R"("redact":50,"invite":0})")
                .status == 200U);
}

[[nodiscard]] auto alias_path(std::string const& alias) -> std::string
{
    return "/_matrix/client/v3/directory/room/" + merovingian::core::percent_encode_path_component(alias);
}

[[nodiscard]] auto put_alias(ClientServerRuntime& rt, std::string const& token, std::string const& alias,
                             std::string const& room_id) -> Reply
{
    return call(rt, "PUT", alias_path(alias), token, R"({"room_id":")" + room_id + R"("})");
}

// Reads the store directly: a GET for a foreign-domain alias would be proxied over federation.
[[nodiscard]] auto database_alias_absent(ClientServerRuntime& rt, std::string const& alias) -> bool
{
    return !merovingian::database::find_room_alias(rt.homeserver.database.persistent_store, alias).has_value();
}

[[nodiscard]] auto alias_resolves(ClientServerRuntime& rt, std::string const& token, std::string const& alias) -> bool
{
    return call(rt, "GET", alias_path(alias), token).status == 200U;
}

[[nodiscard]] auto joined_room_count(ClientServerRuntime& rt, std::string const& token) -> std::size_t
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/joined_rooms", token);
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* rooms = object_member_as_array(body, "joined_rooms");
    REQUIRE(rooms != nullptr);
    return rooms->size();
}

[[nodiscard]] auto report(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                          std::string const& event_id) -> Reply
{
    return call(rt, "POST",
                "/_matrix/client/v3/rooms/" + merovingian::core::percent_encode_path_component(room_id) + "/report/" +
                    merovingian::core::percent_encode_path_component(event_id),
                token, R"({"reason":"spam"})");
}

[[nodiscard]] auto reports_naming(ClientServerRuntime& rt, std::string const& admin_token, std::string const& event_id)
    -> std::size_t
{
    auto const listing = call(rt, "GET", "/_matrix/client/v3/admin/safety/reports", admin_token);
    REQUIRE(listing.status == 200U);
    auto count = std::size_t{0U};
    for (auto position = listing.body.find(event_id); position != std::string::npos;
         position = listing.body.find(event_id, position + 1U))
    {
        ++count;
    }
    return count;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidreporteventid
//
// Spec: "The caller must be joined to the room to report it." 404: "The event was not found or you
// are not joined to the room where the event resides."
SCENARIO("An event report is accepted only from a joined member about an event in that room",
         "[conformance][client-server][report][csaz-12]")
{
    GIVEN("alice's room with bob joined, a message from alice, and carol outside the room")
    {
        auto started = merovingian::homeserver::start_client_server(gates_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice);
        join(rt, bob, room_id);
        auto const message = send_text(rt, alice, room_id, "r1");
        make_server_admin(rt, "alice");

        WHEN("carol, who is not joined, reports the message")
        {
            auto const reply = report(rt, carol, room_id, message);

            THEN("the server answers 404 M_NOT_FOUND and records no report")
            {
                REQUIRE(reply.status == 404U);
                REQUIRE(errcode_of(reply) == "M_NOT_FOUND");
                REQUIRE(reports_naming(rt, alice, message) == 0U);
            }
        }

        WHEN("bob reports an event that does not exist")
        {
            auto const reply = report(rt, bob, room_id, "$doesnotexist");

            THEN("the server answers 404 M_NOT_FOUND and records no report")
            {
                REQUIRE(reply.status == 404U);
                REQUIRE(errcode_of(reply) == "M_NOT_FOUND");
                REQUIRE(reports_naming(rt, alice, "$doesnotexist") == 0U);
            }
        }

        WHEN("bob reports the message")
        {
            auto const reply = report(rt, bob, room_id, message);

            THEN("the report is accepted and recorded once")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(reports_naming(rt, alice, message) == 1U);
            }
            AND_WHEN("bob reports the same message again")
            {
                auto const again = report(rt, bob, room_id, message);

                THEN("it is acknowledged without a second record")
                {
                    REQUIRE(again.status == 200U);
                    REQUIRE(reports_naming(rt, alice, message) == 1U);
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/rooms/{roomId}/upgrade
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidupgrade
//
// Spec: 403 "The user is not permitted to upgrade the room." Upgrading sends an m.room.tombstone
// into the old room, so a user who may not send that event may not upgrade.
SCENARIO("A room upgrade by a user without tombstone power is refused before a new room is created",
         "[conformance][client-server][upgrade][csaz-12]")
{
    GIVEN("alice's room with bob joined at power level 0")
    {
        auto started = merovingian::homeserver::start_client_server(gates_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice);
        join(rt, bob, room_id);
        auto const rooms_before = rt.homeserver.database.rooms.size();

        WHEN("bob upgrades the room")
        {
            auto const reply =
                call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", bob, R"({"new_version":"12"})");

            THEN("the server answers 403 M_FORBIDDEN and no room was created")
            {
                REQUIRE(reply.status == 403U);
                REQUIRE(errcode_of(reply) == "M_FORBIDDEN");
                REQUIRE(rt.homeserver.database.rooms.size() == rooms_before);
                REQUIRE(joined_room_count(rt, bob) == 1U);
                REQUIRE(
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.tombstone", alice).status ==
                    404U);
            }
        }

        WHEN("alice, the creator, upgrades the room")
        {
            auto const reply =
                call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", alice, R"({"new_version":"12"})");

            THEN("the upgrade succeeds and the old room is tombstoned")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(rt.homeserver.database.rooms.size() == rooms_before + 1U);
                REQUIRE(
                    call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.tombstone", alice).status ==
                    200U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/directory/list/room/{roomId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3directorylistroomroomid
//
// Spec: "Servers MAY implement additional access control checks, for instance, to ensure that a
// room's visibility can only be changed by the room creator or a server administrator." This server
// requires the power to send m.room.canonical_alias, or a server administrator.
SCENARIO("Only a user with canonical-alias power or a server administrator may change directory visibility",
         "[conformance][client-server][directory][csaz-12]")
{
    GIVEN("alice's room with bob joined at power level 0")
    {
        auto started = merovingian::homeserver::start_client_server(gates_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice);
        join(rt, bob, room_id);
        auto const visibility_path = "/_matrix/client/v3/directory/list/room/" + room_id;

        WHEN("bob publishes the room")
        {
            auto const reply = call(rt, "PUT", visibility_path, bob, R"({"visibility":"public"})");

            THEN("the server answers 403 M_FORBIDDEN and the room stays private")
            {
                REQUIRE(reply.status == 403U);
                REQUIRE(errcode_of(reply) == "M_FORBIDDEN");
                REQUIRE(call(rt, "GET", visibility_path, bob).body.find("\"private\"") != std::string::npos);
            }
        }

        WHEN("alice publishes the room")
        {
            THEN("it is published")
            {
                REQUIRE(call(rt, "PUT", visibility_path, alice, R"({"visibility":"public"})").status == 200U);
                REQUIRE(call(rt, "GET", visibility_path, bob).body.find("\"public\"") != std::string::npos);
            }
        }

        WHEN("bob is a server administrator")
        {
            make_server_admin(rt, "bob");

            THEN("he may publish the room")
            {
                REQUIRE(call(rt, "PUT", visibility_path, bob, R"({"visibility":"public"})").status == 200U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/directory/room/{roomAlias}; Appendices "Room aliases"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3directoryroomroomalias
//
// Spec: 400 M_INVALID_PARAM "The given `roomAlias` is not a valid room alias." A room alias is
// `#room_alias:domain`, and this server only creates aliases on its own domain.
SCENARIO("Room alias creation validates the alias and requires canonical-alias power",
         "[conformance][client-server][directory][alias][csaz-12]")
{
    GIVEN("alice's room with bob joined at power level 0")
    {
        auto started = merovingian::homeserver::start_client_server(gates_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice);
        join(rt, bob, room_id);

        WHEN("alice creates an alias with no sigil")
        {
            auto const reply = put_alias(rt, alice, "general:example.org", room_id);

            THEN("the server answers 400 M_INVALID_PARAM")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_INVALID_PARAM");
            }
        }

        WHEN("alice creates an alias on another server's domain")
        {
            auto const reply = put_alias(rt, alice, "#general:other.example", room_id);

            THEN("the server answers 400 M_INVALID_PARAM and no alias exists")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_INVALID_PARAM");
                REQUIRE(database_alias_absent(rt, "#general:other.example"));
            }
        }

        WHEN("bob, without the power to send m.room.canonical_alias, creates an alias")
        {
            auto const reply = put_alias(rt, bob, "#admin:example.org", room_id);

            THEN("the server answers 403 M_FORBIDDEN and the alias does not resolve")
            {
                REQUIRE(reply.status == 403U);
                REQUIRE(errcode_of(reply) == "M_FORBIDDEN");
                REQUIRE_FALSE(alias_resolves(rt, alice, "#admin:example.org"));
            }
        }

        WHEN("alice creates a valid local alias")
        {
            THEN("it resolves to the room")
            {
                REQUIRE(put_alias(rt, alice, "#general:example.org", room_id).status == 200U);
                REQUIRE(alias_resolves(rt, bob, "#general:example.org"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: DELETE /_matrix/client/v3/directory/room/{roomAlias}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#delete_matrixclientv3directoryroomroomalias
//
// Spec: "Servers may choose to implement additional access control checks here, for instance that
// room aliases can only be deleted by their creator or a server administrator." This server allows
// the alias's creator, a user with canonical-alias power in the room, or a server administrator.
// 404: "There is no mapped room ID for this room alias."
SCENARIO("A room alias may be deleted by its creator, a user with canonical-alias power, or an administrator",
         "[conformance][client-server][directory][alias][csaz-12]")
{
    GIVEN("alice's room with an alias alice created, bob joined at power level 0, and carol outside it")
    {
        auto started = merovingian::homeserver::start_client_server(gates_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice);
        join(rt, bob, room_id);
        REQUIRE(put_alias(rt, alice, "#general:example.org", room_id).status == 200U);

        WHEN("bob deletes it")
        {
            auto const reply = call(rt, "DELETE", alias_path("#general:example.org"), bob);

            THEN("the server answers 403 M_FORBIDDEN and the alias still resolves")
            {
                REQUIRE(reply.status == 403U);
                REQUIRE(errcode_of(reply) == "M_FORBIDDEN");
                REQUIRE(alias_resolves(rt, bob, "#general:example.org"));
            }
        }

        WHEN("alice deletes it")
        {
            auto const reply = call(rt, "DELETE", alias_path("#general:example.org"), alice);

            THEN("it is removed")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE_FALSE(alias_resolves(rt, bob, "#general:example.org"));
            }
        }

        WHEN("carol, a server administrator outside the room, deletes it")
        {
            make_server_admin(rt, "carol");
            auto const reply = call(rt, "DELETE", alias_path("#general:example.org"), carol);

            THEN("it is removed")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE_FALSE(alias_resolves(rt, bob, "#general:example.org"));
            }
        }

        WHEN("an alias that does not exist is deleted")
        {
            auto const reply = call(rt, "DELETE", alias_path("#missing:example.org"), alice);

            THEN("the server answers 404 M_NOT_FOUND")
            {
                REQUIRE(reply.status == 404U);
                REQUIRE(errcode_of(reply) == "M_NOT_FOUND");
            }
        }

        WHEN("bob is given canonical-alias power, creates an alias, and then loses that power")
        {
            set_users_power(rt, alice, room_id, "\"" + user_id("bob") + "\":50");
            REQUIRE(put_alias(rt, bob, "#bobs:example.org", room_id).status == 200U);
            set_users_power(rt, alice, room_id, "\"" + user_id("bob") + "\":0");
            auto const reply = call(rt, "DELETE", alias_path("#bobs:example.org"), bob);

            THEN("he may still delete the alias he created")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE_FALSE(alias_resolves(rt, alice, "#bobs:example.org"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT and DELETE /_matrix/client/v3/directory/room/{roomAlias}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3directoryroomroomalias
//
// Spec: PUT answers 409 "A room alias with that name already exists"; an alias that is not valid is
// 400 M_INVALID_PARAM on both methods. A server administrator may map an alias for a room they are
// not in (ADR-0127).
SCENARIO("Room alias requests are refused on malformed input, unknown rooms and conflicts",
         "[conformance][client-server][directory][alias][csaz-12]")
{
    GIVEN("alice's room with an alias, and carol outside it")
    {
        auto started = merovingian::homeserver::start_client_server(gates_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const carol = register_and_login(rt, "carol");
        auto const room_id = create_room(rt, alice);
        auto const other_room = create_room(rt, alice);
        REQUIRE(put_alias(rt, alice, "#general:example.org", room_id).status == 200U);

        WHEN("the alias is put again for the same room")
        {
            THEN("the request succeeds without change")
            {
                REQUIRE(put_alias(rt, alice, "#general:example.org", room_id).status == 200U);
            }
        }
        WHEN("the alias is put for a different room")
        {
            auto const reply = put_alias(rt, alice, "#general:example.org", other_room);

            THEN("the server answers 409 and the alias still names the first room")
            {
                // Spec: 409 "A room alias with that name already exists."
                REQUIRE(reply.status == 409U);
                REQUIRE(merovingian::database::find_room_alias(rt.homeserver.database.persistent_store,
                                                               "#general:example.org")
                            ->room_id == room_id);
            }
        }
        WHEN("the request body is not a JSON object, or names no room")
        {
            auto const not_json = call(rt, "PUT", alias_path("#a:example.org"), alice, "[]");
            auto const no_room = call(rt, "PUT", alias_path("#b:example.org"), alice, "{}");

            THEN("the server answers 400 M_BAD_JSON")
            {
                REQUIRE(not_json.status == 400U);
                REQUIRE(errcode_of(not_json) == "M_BAD_JSON");
                REQUIRE(no_room.status == 400U);
                REQUIRE(errcode_of(no_room) == "M_BAD_JSON");
            }
        }
        WHEN("the alias names a room this server does not know")
        {
            auto const reply = put_alias(rt, alice, "#ghost:example.org", "!unknown:example.org");

            THEN("the server answers 404 M_NOT_FOUND")
            {
                REQUIRE(reply.status == 404U);
                REQUIRE(errcode_of(reply) == "M_NOT_FOUND");
            }
        }
        WHEN("carol, a server administrator outside the room, maps an alias to it")
        {
            make_server_admin(rt, "carol");

            THEN("it is created")
            {
                REQUIRE(put_alias(rt, carol, "#admins:example.org", room_id).status == 200U);
                REQUIRE(alias_resolves(rt, alice, "#admins:example.org"));
            }
        }
        WHEN("a malformed alias is deleted")
        {
            auto const reply = call(rt, "DELETE", alias_path("general:example.org"), alice);

            THEN("the server answers 400 M_INVALID_PARAM")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_INVALID_PARAM");
            }
        }
        WHEN("carol, outside the room and not an administrator, deletes the alias")
        {
            auto const reply = call(rt, "DELETE", alias_path("#general:example.org"), carol);

            THEN("the server answers 403 M_FORBIDDEN")
            {
                REQUIRE(reply.status == 403U);
                REQUIRE(alias_resolves(rt, alice, "#general:example.org"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/directory/list/room/{roomId}, POST
// /_matrix/client/v3/rooms/{roomId}/upgrade, POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3directorylistroomroomid
//
// Malformed requests and unknown rooms are refused before any permission is considered.
SCENARIO("Directory visibility, upgrade and report requests are refused on malformed input and unknown rooms",
         "[conformance][client-server][directory][upgrade][report][csaz-12]")
{
    GIVEN("alice's room")
    {
        auto started = merovingian::homeserver::start_client_server(gates_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, alice);
        auto const visibility_path = "/_matrix/client/v3/directory/list/room/" + room_id;

        WHEN("the visibility is not public or private, or the body is not an object")
        {
            auto const bad_value = call(rt, "PUT", visibility_path, alice, R"({"visibility":"everyone"})");
            auto const not_object = call(rt, "PUT", visibility_path, alice, "[]");

            THEN("the server answers 400")
            {
                REQUIRE(bad_value.status == 400U);
                REQUIRE(not_object.status == 400U);
            }
        }
        WHEN("the visibility of an unknown room is set")
        {
            auto const reply = call(rt, "PUT", "/_matrix/client/v3/directory/list/room/!unknown:example.org", alice,
                                    R"({"visibility":"public"})");

            THEN("the server answers 404 M_NOT_FOUND")
            {
                REQUIRE(reply.status == 404U);
                REQUIRE(errcode_of(reply) == "M_NOT_FOUND");
            }
        }
        WHEN("an upgrade names an unsupported room version")
        {
            auto const reply = call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", alice,
                                    R"({"new_version":"not-a-version"})");

            THEN("the server answers 400 M_UNSUPPORTED_ROOM_VERSION")
            {
                // Spec: 400 "if the room version requested is not supported by the homeserver".
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_UNSUPPORTED_ROOM_VERSION");
            }
        }
        WHEN("a report is made about an event in a room this server does not know")
        {
            auto const message = send_text(rt, alice, room_id, "r-unknown-room");
            auto const reply = report(rt, alice, "!unknown:example.org", message);

            THEN("the server answers 404 M_NOT_FOUND")
            {
                REQUIRE(reply.status == 404U);
                REQUIRE(errcode_of(reply) == "M_NOT_FOUND");
            }
        }
        WHEN("a report names an event that is in a different room")
        {
            auto const other_room = create_room(rt, alice);
            auto const message = send_text(rt, alice, other_room, "r-other-room");
            auto const reply = report(rt, alice, room_id, message);

            THEN("the server answers 404 M_NOT_FOUND")
            {
                REQUIRE(reply.status == 404U);
                REQUIRE(errcode_of(reply) == "M_NOT_FOUND");
            }
        }
    }
}
