// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  APPLICATION SERVICE API — PUBLISHED ROOM DIRECTORIES (WAVE 3 OF THE     |
// |  AUDIT) AND publicRooms third_party_instance_id / include_all_networks  |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19, "Published room            |
// |        directories"; Client-Server API v1.19, POST /publicRooms        |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// +-------------------------------------------------------------------------+

#include "../support/appservice_test_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/mock_appservice.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace
{

using merovingian::homeserver::ClientServerRuntime;
using merovingian::tests::MockAppservice;
using merovingian::tests::TestAppservice;

[[nodiscard]] auto call(ClientServerRuntime& runtime, std::string method, std::string target, std::string const& token,
                        std::string body = {})
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {std::move(method), std::move(target), token, std::move(body)});
}

[[nodiscard]] auto errcode_of(merovingian::homeserver::DispatchResult const& result) -> std::string
{
    auto const body = merovingian::tests::parse_object(result.response.body);
    auto const* errcode = merovingian::tests::string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

[[nodiscard]] auto register_human(ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    auto const registered = call(runtime, "POST", "/_matrix/client/v3/register", {},
                                 merovingian::tests::registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.response.status == 200U);
    return *merovingian::tests::string_member(merovingian::tests::parse_object(registered.response.body),
                                              "access_token");
}

[[nodiscard]] auto create_room(ClientServerRuntime& runtime, std::string const& token, std::string const& body = "{}")
    -> std::string
{
    auto const created = call(runtime, "POST", "/_matrix/client/v3/createRoom", token, body);
    REQUIRE(created.response.status == 200U);
    return *merovingian::tests::string_member(merovingian::tests::parse_object(created.response.body), "room_id");
}

// The room IDs in the `chunk` of a /publicRooms answer.
[[nodiscard]] auto listed_rooms(merovingian::homeserver::DispatchResult const& result) -> std::vector<std::string>
{
    REQUIRE(result.response.status == 200U);
    auto const body = merovingian::tests::parse_object(result.response.body);
    auto const* chunk = merovingian::tests::object_member_as_array(body, "chunk");
    REQUIRE(chunk != nullptr);
    auto rooms = std::vector<std::string>{};
    for (auto const& entry : *chunk)
    {
        auto const* object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        REQUIRE(object != nullptr);
        auto const* room_id = merovingian::tests::string_member(*object, "room_id");
        REQUIRE(room_id != nullptr);
        rooms.push_back(*room_id);
    }
    return rooms;
}

constexpr auto irc_protocol_json = std::string_view{R"({
    "field_types": {"network": {"placeholder": "irc.example.org", "regexp": "[a-z.]+"}},
    "icon": "mxc://example.org/icon",
    "instances": [{"desc": "Freenode", "fields": {"network": "freenode"}, "network_id": "freenode"}],
    "location_fields": ["network"],
    "user_fields": ["network"]
})"};

// The instance_id the homeserver minted for the first instance of the `irc` protocol, read the way a
// client reads it: from GET /thirdparty/protocol/irc.
[[nodiscard]] auto irc_instance_id(ClientServerRuntime& runtime, std::string const& token) -> std::string
{
    auto const protocol = call(runtime, "GET", "/_matrix/client/v3/thirdparty/protocol/irc", token);
    REQUIRE(protocol.response.status == 200U);
    auto const body = merovingian::tests::parse_object(protocol.response.body);
    auto const* instances = merovingian::tests::object_member_as_array(body, "instances");
    REQUIRE(instances != nullptr);
    REQUIRE_FALSE(instances->empty());
    auto const* instance = std::get_if<merovingian::canonicaljson::Object>(&instances->front().storage());
    REQUIRE(instance != nullptr);
    auto const* instance_id = merovingian::tests::string_member(*instance, "instance_id");
    REQUIRE(instance_id != nullptr);
    return *instance_id;
}

[[nodiscard]] auto directory_target(std::string const& network, std::string const& room_id) -> std::string
{
    // Room IDs contain '!' and ':' which a client percent-encodes in a path segment.
    auto encoded = std::string{};
    for (auto const character : room_id)
    {
        encoded += (character == '!') ? "%21" : (character == ':') ? "%3A" : std::string{character};
    }
    return "/_matrix/client/v3/directory/list/appservice/" + network + "/" + encoded;
}

} // namespace

// Spec: Application Service API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#published-room-directories
//
// "Updates the visibility of a given room in the application service's published room directory ... This
// API requires the use of an application service access token (as_token) instead of a typical client's
// access_token. This API cannot be invoked by users who are not identified as application services."
// 200: "The room's directory visibility has been updated."; body `visibility` "public" or "private".
// Clients "may be accessed ... through additional parameters on the /publicRooms client-server endpoint":
// `third_party_instance_id` ("the instance_id of a Protocol Instance returned by GET /thirdparty/protocols")
// and `include_all_networks`.
SCENARIO("an appservice publishes a room to its network's directory and publicRooms lists it for that network",
         "[appservice][conformance][directory]")
{
    GIVEN("an appservice declaring the irc protocol that is interested in every room, and a room")
    {
        auto bridge = TestAppservice{.id = "bridge", .rooms_regex = ".*", .protocols = {"irc"}};
        auto mock = MockAppservice{};
        mock.set_answer("/_matrix/app/v1/thirdparty/protocol/irc", 200U, std::string{irc_protocol_json});
        bridge.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_human(runtime, "alice");
        auto const network_room = create_room(runtime, alice);
        auto const ordinary_room = create_room(runtime, alice);
        auto const published_room = create_room(runtime, alice);
        REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/directory/list/room/" + published_room, alice,
                     R"({"visibility":"public"})")
                    .response.status == 200U);
        auto const instance_id = irc_instance_id(runtime, alice);

        WHEN("the appservice lists the room in its irc network directory")
        {
            auto const result = call(runtime, "PUT", directory_target("irc", network_room), bridge.as_token(),
                                     R"({"visibility":"public"})");

            THEN("the answer is 200 with an empty object")
            {
                REQUIRE(result.response.status == 200U);
                CHECK(result.response.body == "{}");
            }

            THEN("POST /publicRooms with that network's instance_id lists the room, and only that room")
            {
                auto const listed = listed_rooms(call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice,
                                                      R"({"third_party_instance_id":")" + instance_id + R"("})"));
                CHECK(listed == std::vector<std::string>{network_room});
            }

            THEN("the homeserver's own directory (no network named) does not list it")
            {
                auto const listed =
                    listed_rooms(call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice, R"({})"));
                CHECK(listed == std::vector<std::string>{published_room});
                auto const listed_by_get = listed_rooms(call(runtime, "GET", "/_matrix/client/v3/publicRooms", alice));
                CHECK(listed_by_get == std::vector<std::string>{published_room});
            }

            THEN("include_all_networks lists the homeserver's directory and the network's, each room once")
            {
                auto listed = listed_rooms(
                    call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice, R"({"include_all_networks":true})"));
                std::ranges::sort(listed);
                auto expected = std::vector<std::string>{published_room, network_room};
                std::ranges::sort(expected);
                CHECK(listed == expected);
            }

            THEN("an instance_id that names no network of any appservice lists nothing")
            {
                auto const listed = listed_rooms(call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice,
                                                      R"({"third_party_instance_id":"nobody:irc:0"})"));
                CHECK(listed.empty());
            }

            THEN("naming a network and asking for all networks is refused, as the spec forbids the combination")
            {
                auto const result_both =
                    call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice,
                         R"({"include_all_networks":true,"third_party_instance_id":")" + instance_id + R"("})");
                CHECK(result_both.response.status == 400U);
                CHECK(errcode_of(result_both) == "M_INVALID_PARAM");
            }

            THEN("the two parameters are type-checked")
            {
                CHECK(
                    call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice, R"({"include_all_networks":"yes"})")
                        .response.status == 400U);
                CHECK(call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice, R"({"third_party_instance_id":5})")
                          .response.status == 400U);
            }

            AND_WHEN("the appservice makes the room private again")
            {
                auto const unlisted = call(runtime, "PUT", directory_target("irc", network_room), bridge.as_token(),
                                           R"({"visibility":"private"})");

                THEN("the room leaves the network's directory")
                {
                    REQUIRE(unlisted.response.status == 200U);
                    auto const listed = listed_rooms(call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice,
                                                          R"({"third_party_instance_id":")" + instance_id + R"("})"));
                    CHECK(listed.empty());
                }
            }
        }

        WHEN("the same room is listed twice")
        {
            auto const first = call(runtime, "PUT", directory_target("irc", network_room), bridge.as_token(),
                                    R"({"visibility":"public"})");
            auto const second = call(runtime, "PUT", directory_target("irc", network_room), bridge.as_token(),
                                     R"({"visibility":"public"})");

            THEN("it is idempotent and the room is listed once")
            {
                CHECK(first.response.status == 200U);
                CHECK(second.response.status == 200U);
                auto const listed = listed_rooms(call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice,
                                                      R"({"third_party_instance_id":")" + instance_id + R"("})"));
                CHECK(listed.size() == 1U);
            }
        }

        WHEN("an ordinary room is not published to any network")
        {
            THEN("it is absent from the network's listing")
            {
                auto const listed = listed_rooms(call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice,
                                                      R"({"third_party_instance_id":")" + instance_id + R"("})"));
                CHECK(std::ranges::find(listed, ordinary_room) == listed.end());
            }
        }
    }
}

// Spec: Application Service API v1.19
// Endpoint / Section: PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#published-room-directories
//
// "This API cannot be invoked by users who are not identified as application services", it "Requires
// authentication", and `visibility` is "Required ... One of: [public, private]". The refusals the spec gives
// no status for (an undeclared protocol, a missing room, a room the appservice has no interest in) are
// project policy (ADR-0192) and are covered in tests/integration/test_appservice_wave3_flow.cpp.
SCENARIO("only an appservice may publish to a network directory, with a valid visibility",
         "[appservice][conformance][directory][security]")
{
    GIVEN("two appservices and an ordinary user")
    {
        auto bridge = TestAppservice{.id = "bridge", .users_regex = "@_bridge_.*", .protocols = {"irc"}};
        auto other = TestAppservice{.id = "other", .rooms_regex = ".*", .protocols = {"slack"}};
        auto mock = MockAppservice{};
        auto other_mock = MockAppservice{};
        bridge.url = mock.url();
        other.url = other_mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge, other}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_human(runtime, "alice");
        auto const room = create_room(runtime, alice);

        WHEN("an ordinary user's token tries to publish")
        {
            auto const result =
                call(runtime, "PUT", directory_target("irc", room), alice, R"({"visibility":"public"})");

            THEN("403 M_FORBIDDEN")
            {
                CHECK(result.response.status == 403U);
                CHECK(errcode_of(result) == "M_FORBIDDEN");
            }
        }

        WHEN("no token is presented")
        {
            auto const result = call(runtime, "PUT", directory_target("irc", room), {}, R"({"visibility":"public"})");

            THEN("401 M_MISSING_TOKEN")
            {
                CHECK(result.response.status == 401U);
                CHECK(errcode_of(result) == "M_MISSING_TOKEN");
            }
        }

        WHEN("the visibility is missing or not public or private")
        {
            auto const missing = call(runtime, "PUT", directory_target("slack", room), other.as_token(), R"({})");
            auto const wrong =
                call(runtime, "PUT", directory_target("slack", room), other.as_token(), R"({"visibility":"hidden"})");

            THEN("400")
            {
                CHECK(missing.response.status == 400U);
                CHECK(wrong.response.status == 400U);
            }
        }
    }
}
