// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/federation_request_routing.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using merovingian::homeserver::federation_worker_room_id_from_request;
using merovingian::homeserver::LocalHttpRequest;

[[nodiscard]] auto make_request(std::string target, std::string body = {}) -> LocalHttpRequest
{
    auto request = LocalHttpRequest{};
    request.method = "GET";
    request.target = std::move(target);
    request.body = std::move(body);
    request.remote_addr = "203.0.113.1";
    return request;
}

} // namespace

SCENARIO("Room ID is extracted from room-scoped federation path endpoints", "[federation][routing][room-id]")
{
    GIVEN("a request to a room-scoped federation endpoint")
    {
        auto const room_id = std::string{"!room:example.com"};

        WHEN("the target is /_matrix/federation/v1/state/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/state/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/state_ids/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/state_ids/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/event_auth/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/event_auth/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/backfill/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/backfill/" + room_id + "?limit=10");
            THEN("the room ID is extracted without the query string")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/make_join/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/make_join/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/send_join/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/send_join/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/make_leave/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/make_leave/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/send_leave/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/send_leave/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/make_knock/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/make_knock/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/send_knock/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/send_knock/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/invite/{roomId}/{eventId}")
        {
            auto const request = make_request("/_matrix/federation/v1/invite/" + room_id + "/$event");
            THEN("only the room ID segment is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/invite2/{roomId}/{eventId}")
        {
            auto const request = make_request("/_matrix/federation/v1/invite2/" + room_id + "/$event");
            THEN("only the room ID segment is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/get_missing_events/{roomId}")
        {
            auto const request = make_request("/_matrix/federation/v1/get_missing_events/" + room_id);
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v1/query/directory/{roomAlias}")
        {
            auto const request = make_request("/_matrix/federation/v1/query/directory/%23alias%3Aexample.com");
            THEN("the alias is treated as the room ID for routing")
            {
                REQUIRE_FALSE(federation_worker_room_id_from_request(request).empty());
            }
        }
    }
}

SCENARIO("Room ID is extracted from /send/{txnId} request bodies", "[federation][routing][room-id][send]")
{
    GIVEN("a PUT /send/{txnId} request with one PDU")
    {
        auto const room_id = std::string{"!sendroom:example.com"};
        auto const body =
            std::string{"{\"origin\":\"remote.example\",\"origin_server_ts\":1234,\"pdus\":[{\"room_id\":\""} +
            room_id + std::string{"\",\"event_id\":\"$x:remote.example\",\"type\":\"m.room.message\"}]}"};
        auto const request = make_request("/_matrix/federation/v1/send/txn-1", body);

        WHEN("the room ID is extracted")
        {
            THEN("it comes from the first PDU")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }
    }
}

SCENARIO("Room ID extraction handles malformed /send bodies gracefully", "[federation][routing][room-id][send]")
{
    GIVEN("a PUT /send/{txnId} request with no pdus key")
    {
        auto const request = make_request("/_matrix/federation/v1/send/txn-1", R"({"origin":"x"})");

        WHEN("the room ID is extracted")
        {
            THEN("it returns an empty string so the request routes to shard 0")
            {
                REQUIRE(federation_worker_room_id_from_request(request).empty());
            }
        }
    }

    GIVEN("a PUT /send/{txnId} request with an empty pdus array")
    {
        auto const request = make_request("/_matrix/federation/v1/send/txn-1", R"({"pdus":[]})");

        WHEN("the room ID is extracted")
        {
            THEN("it returns an empty string")
            {
                REQUIRE(federation_worker_room_id_from_request(request).empty());
            }
        }
    }

    GIVEN("a PUT /send/{txnId} request with a PDU missing room_id")
    {
        auto const request = make_request("/_matrix/federation/v1/send/txn-1", R"({"pdus":[{"event_id":"$x"}]})");

        WHEN("the room ID is extracted")
        {
            THEN("it returns an empty string")
            {
                REQUIRE(federation_worker_room_id_from_request(request).empty());
            }
        }
    }
}

SCENARIO("Room ID extraction from /send decodes JSON escape sequences", "[federation][routing][room-id][send]")
{
    GIVEN("a PUT /send/{txnId} body whose first PDU has an escaped backslash in the room_id value")
    {
        auto const request =
            make_request("/_matrix/federation/v1/send/txn-1", R"({"pdus":[{"room_id":"!escaped\\room:example.com"}]})");

        WHEN("the room ID is extracted")
        {
            THEN("the backslash escape is decoded")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == "!escaped\\room:example.com");
            }
        }
    }
}

SCENARIO("Room ID is extracted from v2 federation path endpoints", "[federation][routing][room-id][v2]")
{
    GIVEN("a request to a v2 federation endpoint")
    {
        auto const room_id = std::string{"!v2room:example.com"};

        WHEN("the target is /_matrix/federation/v2/invite/{roomId}/{eventId}")
        {
            auto const request = make_request("/_matrix/federation/v2/invite/" + room_id + "/$eventId");
            THEN("the room ID is extracted for correct shard routing")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v2/send_join/{roomId}/{eventId}")
        {
            auto const request = make_request("/_matrix/federation/v2/send_join/" + room_id + "/$eventId");
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v2/send_leave/{roomId}/{eventId}")
        {
            auto const request = make_request("/_matrix/federation/v2/send_leave/" + room_id + "/$eventId");
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v2/make_knock/{roomId}/{userId}")
        {
            auto const request = make_request("/_matrix/federation/v2/make_knock/" + room_id + "/@user:remote.example");
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }

        WHEN("the target is /_matrix/federation/v2/send_knock/{roomId}/{eventId}")
        {
            auto const request = make_request("/_matrix/federation/v2/send_knock/" + room_id + "/$eventId");
            THEN("the room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }
    }
}

SCENARIO("Non-room federation endpoints return an empty room ID", "[federation][routing][room-id]")
{
    GIVEN("a request to a non-room federation endpoint")
    {
        WHEN("the target is the key server")
        {
            auto const request = make_request("/_matrix/key/v2/server");
            THEN("no room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request).empty());
            }
        }

        WHEN("the target is /_matrix/federation/v1/query/profile")
        {
            auto const request = make_request("/_matrix/federation/v1/query/profile?user_id=@x:y");
            THEN("no room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request).empty());
            }
        }

        WHEN("the target is /_matrix/federation/v1/query/directory without a room alias")
        {
            auto const request = make_request("/_matrix/federation/v1/query/directory");
            THEN("no room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request).empty());
            }
        }

        WHEN("the target is /_matrix/federation/v1/publicRooms")
        {
            auto const request = make_request("/_matrix/federation/v1/publicRooms");
            THEN("no room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request).empty());
            }
        }

        WHEN("the target is an unknown /_matrix/federation path")
        {
            auto const request = make_request("/_matrix/federation/v1/unknown/path");
            THEN("no room ID is extracted")
            {
                REQUIRE(federation_worker_room_id_from_request(request).empty());
            }
        }
    }
}
