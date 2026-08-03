// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX /sync SUMMARY CONFORMANCE TESTS                          |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// |                                                                         |
// |  Covers the `summary` object inside each `rooms.join` entry.             |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime,
                                   std::string_view localpart = "alice") -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} +
        std::string{localpart} + ":example.org\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"DEVICE1\"}";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);

    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    REQUIRE(!token->empty());
    return *token;
}

[[nodiscard]] auto room_id_from_create(std::string const& create_response_body) -> std::string
{
    auto const body = parse_object(create_response_body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    REQUIRE(!room_id->empty());
    return *room_id;
}

[[nodiscard]] auto first_joined_room_summary(merovingian::homeserver::ClientServerRuntime& runtime,
                                             std::string const& token) -> merovingian::canonicaljson::Object
{
    auto const sync =
        merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
    REQUIRE(sync.response.status == 200U);

    auto const body = parse_object(sync.response.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* join = object_member_as_object(*rooms, "join");
    REQUIRE(join != nullptr);
    REQUIRE(!join->empty());

    for (auto const& member : *join)
    {
        if (auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&member.value->storage()); obj != nullptr)
        {
            auto const* summary = object_member_as_object(*obj, "summary");
            REQUIRE(summary != nullptr);
            return *summary;
        }
    }
    REQUIRE(false);
    return {};
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint: GET /_matrix/client/v3/sync
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// Each JoinedRoom MUST include a `summary` object with:
//   m.joined_member_count  - integer
//   m.invited_member_count - integer
//   m.heroes               - array of user IDs
SCENARIO("GET /sync includes a summary object in each joined room", "[conformance][client-server][sync][summary]")
{
    GIVEN("a running client-server with a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the user creates a room and syncs")
        {
            auto const create = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"name":"summary test"})"});
            REQUIRE(create.response.status == 200U);

            auto const summary = first_joined_room_summary(started.runtime, token);

            THEN("the summary contains the required fields with valid types")
            {
                // Spec MUST: summary object is present with these three keys.
                REQUIRE(int_member(summary, "m.joined_member_count") != nullptr);
                REQUIRE(int_member(summary, "m.invited_member_count") != nullptr);
                REQUIRE(object_member_as_array(summary, "m.heroes") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: GET /_matrix/client/v3/sync
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// m.joined_member_count and m.invited_member_count reflect the current room
// membership. m.heroes lists up to 5 users other than the caller who are
// currently joined.
SCENARIO("GET /sync summary reflects joined and invited member counts", "[conformance][client-server][sync][summary]")
{
    GIVEN("a running client-server with two users")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice_token = logged_in_token(started.runtime, "alice");
        auto const bob_token = logged_in_token(started.runtime, "bob");

        WHEN("alice creates a public room, bob joins it, and alice syncs")
        {
            auto const create = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/createRoom", alice_token,
                                  R"({"name":"public room","preset":"public_chat"})"});
            REQUIRE(create.response.status == 200U);
            auto const room_id = room_id_from_create(create.response.body);

            auto const join = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob_token, {}});
            REQUIRE(join.response.status == 200U);

            auto const summary = first_joined_room_summary(started.runtime, alice_token);

            THEN("the summary shows two joined members and bob as a hero")
            {
                auto const* joined = int_member(summary, "m.joined_member_count");
                auto const* invited = int_member(summary, "m.invited_member_count");
                auto const* heroes = object_member_as_array(summary, "m.heroes");
                REQUIRE(joined != nullptr);
                REQUIRE(invited != nullptr);
                REQUIRE(heroes != nullptr);
                REQUIRE(*joined == 2);
                REQUIRE(*invited == 0);
                REQUIRE(heroes->size() == 1);
                auto const* hero = std::get_if<std::string>(&(*heroes)[0].storage());
                REQUIRE(hero != nullptr);
                REQUIRE(*hero == "@bob:example.org");
            }
        }
    }
}
