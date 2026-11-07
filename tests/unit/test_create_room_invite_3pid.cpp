// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/identity/identity_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>

// POST /createRoom `invite_3pid` (ADR-0474). The spec says the room holds the invite events the
// parameter implies, and says nothing of a request whose entry is malformed, names an identity server this
// server does not trust, or whose identity server cannot be reached. This server's choices: a request it can
// refuse before creating anything is refused whole (400); an identity server that fails once the room exists
// does not undo the room, as for a remote invitee (ADR-0307).

namespace
{

[[nodiscard]] auto config_with_registration() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto entry(std::string const& id_server, std::string const& address) -> std::string
{
    return R"({"id_server":")" + id_server + R"(","medium":"email","address":")" + address +
           R"(","id_access_token":"opaque"})";
}

[[nodiscard]] auto has_third_party_invite(merovingian::database::PersistentStore const& store,
                                          std::string const& room_id) -> bool
{
    return std::ranges::any_of(store.state, [&room_id](merovingian::database::PersistentStateEvent const& state) {
        return state.room_id == room_id && state.event_type == "m.room.third_party_invite";
    });
}

} // namespace

SCENARIO("createRoom judges invite_3pid before creating the room, and keeps the room if the identity server fails",
         "[rooms][create-room][3pid][security]")
{
    GIVEN("a registered user and no trusted identity server")
    {
        // Arrange: boot an isolated homeserver instance and create a user who can create rooms.
        auto started = merovingian::homeserver::start_client_server(config_with_registration());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST",
                         "/_matrix/client/v3/register",
                         {},
                         merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"D"})"});
        // Capture the bearer token used by all createRoom requests in this scenario.
        auto const login_body = merovingian::tests::parse_object(login.response.body);
        auto const* token_member = merovingian::tests::string_member(login_body, "access_token");
        REQUIRE(token_member != nullptr);
        auto const token = *token_member;
        auto const& store = rt.homeserver.database.persistent_store;
        auto const rooms_before = store.rooms.size();
        auto const create = [&](std::string const& body) {
            return merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/createRoom", token, body});
        };

        WHEN("the entry names an identity server this server does not trust")
        {
            auto const answered =
                create(R"({"invite_3pid":[)" + entry("untrusted.example:8448", "bob@example.org") + "]}");

            THEN("it is 400 M_SERVER_NOT_TRUSTED and no room is made")
            {
                REQUIRE(answered.response.status == 400U);
                REQUIRE(answered.response.body.find("M_SERVER_NOT_TRUSTED") != std::string::npos);
                REQUIRE(store.rooms.size() == rooms_before);
            }
        }

        WHEN("an entry lacks its address")
        {
            auto const answered = create(R"({"invite_3pid":[{"id_server":"is.example","medium":"email"}]})");

            THEN("it is 400 M_BAD_JSON and no room is made")
            {
                REQUIRE(answered.response.status == 400U);
                REQUIRE(answered.response.body.find("M_BAD_JSON") != std::string::npos);
                REQUIRE(store.rooms.size() == rooms_before);
            }
        }

        WHEN("invite_3pid is not a list")
        {
            auto const answered = create(R"({"invite_3pid":"bob@example.org"})");

            THEN("it is 400 M_BAD_JSON and no room is made")
            {
                REQUIRE(answered.response.status == 400U);
                REQUIRE(store.rooms.size() == rooms_before);
            }
        }

        WHEN("invite and invite_3pid together are one past max_create_room_invites")
        {
            auto const cap = static_cast<std::size_t>(rt.limits.max_create_room_invites);
            auto invites = std::string{"["};
            for (auto index = std::size_t{0U}; index + 1U < cap; ++index)
            {
                invites += (index == 0U ? "\"@u" : ",\"@u") + std::to_string(index) + ":example.org\"";
            }
            invites += "]";
            auto const answered = create(R"({"invite":)" + invites + R"(,"invite_3pid":[)" +
                                         entry("untrusted.example:8448", "a@example.org") + "," +
                                         entry("untrusted.example:8448", "b@example.org") + "]}");

            THEN("it is 400 M_TOO_LARGE, ahead of any other judgement, and no room is made")
            {
                REQUIRE(answered.response.status == 400U);
                REQUIRE(answered.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(store.rooms.size() == rooms_before);
            }
        }

        WHEN("the trusted identity server cannot be reached")
        {
            auto cert = merovingian::tests::tls_mock::write_test_tls_certificate("is.localhost.test");
            auto const id_server = std::string{"is.localhost.test:1"};
            rt.homeserver.config.server().identity_server.trusted_servers = {"https://" + id_server};
            rt.homeserver.test_forced_identity_resolution["is.localhost.test"] =
                merovingian::identity::TestForcedIdentityResolution{{"127.0.0.1"}, cert.certificate_pem};
            auto const answered =
                create(R"({"preset":"private_chat","invite_3pid":[)" + entry(id_server, "bob@example.org") + "]}");

            THEN("the room is still created, and holds no third-party invite")
            {
                REQUIRE(answered.response.status == 200U);
                REQUIRE(store.rooms.size() == rooms_before + 1U);
                auto const body = merovingian::tests::parse_object(answered.response.body);
                auto const* room_id = merovingian::tests::string_member(body, "room_id");
                REQUIRE(room_id != nullptr);
                REQUIRE_FALSE(has_third_party_invite(store, *room_id));
            }
        }
    }
}
