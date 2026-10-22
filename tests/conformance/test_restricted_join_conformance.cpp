// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance audit 2026-10-17, R04 (ADR-0185): a local user joins a local restricted
// room through one of its allow conditions. Every scenario drives the real
// client-server dispatcher.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <variant>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto restricted_config() -> merovingian::config::Config
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

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token,
                               std::string const& body) -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto member_content(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                  std::string const& user) -> Reply
{
    return call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.member/" + user, token);
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Section: Restricted rooms
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#restricted-rooms
//
// "When joining without an invite, the server MUST verify that the requesting user meets
// at least one of the conditions. If no conditions can be verified or no conditions are
// satisfied, the user will not be able to join." The join this server composes names one
// of its users who can invite (join_authorised_via_users_server, rooms/v10.md 4.3.5.2)
// and carries this server's signature as that user's server's (4.2.1).
SCENARIO("A local user joins a local restricted room through an allow condition",
         "[client-server][conformance][restricted_join][r04]")
{
    GIVEN("a room alice and bob are in, and a restricted room of alice's that allows its members")
    {
        auto started = merovingian::homeserver::start_client_server(restricted_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const carol = register_and_login(rt, "carol");
        auto const allowed = create_room(rt, alice, R"({"preset":"public_chat"})");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + allowed + "/join", bob, "{}").status == 200U);
        auto const restricted = create_room(
            rt, alice,
            std::string{R"({"room_version":"10","initial_state":[{"type":"m.room.join_rules","state_key":"",)"
                        R"("content":{"join_rule":"restricted","allow":[{"type":"m.room_membership","room_id":")"} +
                allowed + R"("}]}}]})");

        WHEN("bob, a member of the allowed room, joins the restricted room")
        {
            auto const joined = call(rt, "POST", "/_matrix/client/v3/rooms/" + restricted + "/join", bob, "{}");

            THEN("he is joined, by a join that names alice as its authorising user")
            {
                // Spec MUST: the user meets a condition, so the join succeeds.
                REQUIRE(joined.status == 200U);
                auto const member = member_content(rt, bob, restricted, "@bob:example.org");
                REQUIRE(member.status == 200U);
                auto const content = parse_object(member.body);
                auto const* membership = string_member(content, "membership");
                REQUIRE(membership != nullptr);
                REQUIRE(*membership == "join");
                auto const* authoriser = string_member(content, "join_authorised_via_users_server");
                REQUIRE(authoriser != nullptr);
                REQUIRE(*authoriser == "@alice:example.org");
            }
        }

        WHEN("carol, who is in no allowed room, tries to join")
        {
            auto const refused = call(rt, "POST", "/_matrix/client/v3/rooms/" + restricted + "/join", carol, "{}");

            THEN("she is refused and stays out")
            {
                // Spec MUST: "If ... no conditions are satisfied, the user will not be able to join."
                REQUIRE(refused.status == 403U);
                REQUIRE(member_content(rt, alice, restricted, "@carol:example.org").status != 200U);
            }
        }

        WHEN("carol sends her own join naming alice as the authorising user through the state API")
        {
            auto const forged =
                call(rt, "PUT", "/_matrix/client/v3/rooms/" + restricted + "/state/m.room.member/@carol:example.org",
                     carol, R"({"membership":"join","join_authorised_via_users_server":"@alice:example.org"})");

            THEN("this server does not sign it on alice's behalf, and carol stays out")
            {
                REQUIRE(forged.status != 200U);
                REQUIRE(member_content(rt, alice, restricted, "@carol:example.org").status != 200U);
            }
        }
    }
}
