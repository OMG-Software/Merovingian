// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/federation_request_routing.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

namespace
{

using merovingian::homeserver::federation_request_should_bypass_worker;
using merovingian::homeserver::federation_worker_room_id_from_request;
using merovingian::homeserver::is_federation_key_server_endpoint;
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

SCENARIO("EDU-only federation send transactions bypass the worker pool", "[federation][routing][worker-bypass]")
{
    GIVEN("a PUT /send transaction carrying only a direct-to-device EDU")
    {
        auto request = make_request(
            "/_matrix/federation/v1/send/txn-to-device",
            R"({"origin":"remote.example.org","origin_server_ts":1,"pdus":[],"edus":[{"edu_type":"m.direct_to_device","content":{"sender":"@bob:remote.example.org","type":"m.room.encrypted","message_id":"m1","messages":{}}}]})");
        request.method = "PUT";

        WHEN("the worker bypass decision is made")
        {
            THEN("the request stays in main instead of being routed to shard 0")
            {
                REQUIRE(federation_worker_room_id_from_request(request).empty());
                REQUIRE(federation_request_should_bypass_worker(request));
            }
        }
    }

    GIVEN("a PUT /send transaction carrying a room PDU")
    {
        auto request = make_request("/_matrix/federation/v1/send/txn-pdu",
                                    R"({"pdus":[{"room_id":"!room:example.org","event_id":"$event"}]})");
        request.method = "PUT";

        WHEN("the worker bypass decision is made")
        {
            THEN("the request still goes to the worker shard for that room")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == "!room:example.org");
                REQUIRE_FALSE(federation_request_should_bypass_worker(request));
            }
        }
    }
}

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
    }
}

SCENARIO("Room ID is percent-decoded for correct shard routing", "[federation][routing][room-id][shard]")
{
    GIVEN("a room ID containing '!' as sent percent-encoded in a real federation path")
    {
        // Real clients (Synapse included) percent-encode '!' as a path segment.
        // notify_room_changed() always uses the plain decoded form (room_service.cpp
        // never touches a URL) — every endpoint below must resolve to the same
        // string or its shard-routing hash disagrees with the notification's,
        // reproducing the make_join 404 this scenario guards against.
        auto const decoded_room_id = std::string{"!room:example.com"};
        auto const encoded_room_id = std::string{"%21room%3Aexample.com"};

        WHEN("the target is a single-room-segment v1 endpoint")
        {
            auto const prefixes = std::vector<std::string>{
                "/_matrix/federation/v1/state/",
                "/_matrix/federation/v1/state_ids/",
                "/_matrix/federation/v1/event_auth/",
                "/_matrix/federation/v1/backfill/",
                "/_matrix/federation/v1/make_join/",
                "/_matrix/federation/v1/send_join/",
                "/_matrix/federation/v1/make_leave/",
                "/_matrix/federation/v1/send_leave/",
                "/_matrix/federation/v1/make_knock/",
                "/_matrix/federation/v1/send_knock/",
                "/_matrix/federation/v1/get_missing_events/",
            };

            THEN("every prefix decodes the percent-encoded room ID to the plain-text form")
            {
                for (auto const& prefix : prefixes)
                {
                    INFO("prefix: " << prefix);
                    auto const request = make_request(prefix + encoded_room_id);
                    REQUIRE(federation_worker_room_id_from_request(request) == decoded_room_id);
                }
            }
        }

        WHEN("the target is a two-segment v1 endpoint (room ID then event ID)")
        {
            auto const prefixes = std::vector<std::string>{
                "/_matrix/federation/v1/invite/",
                "/_matrix/federation/v1/invite2/",
            };

            THEN("the room ID segment alone is decoded")
            {
                for (auto const& prefix : prefixes)
                {
                    INFO("prefix: " << prefix);
                    auto const request = make_request(prefix + encoded_room_id + "/$event");
                    REQUIRE(federation_worker_room_id_from_request(request) == decoded_room_id);
                }
            }
        }

        WHEN("the target is a v2 endpoint")
        {
            auto const prefixes = std::vector<std::string>{
                "/_matrix/federation/v2/invite/",     "/_matrix/federation/v2/send_join/",
                "/_matrix/federation/v2/send_leave/", "/_matrix/federation/v2/make_knock/",
                "/_matrix/federation/v2/send_knock/",
            };

            THEN("every v2 prefix decodes the percent-encoded room ID")
            {
                for (auto const& prefix : prefixes)
                {
                    INFO("prefix: " << prefix);
                    auto const request = make_request(prefix + encoded_room_id + "/$eventId");
                    REQUIRE(federation_worker_room_id_from_request(request) == decoded_room_id);
                }
            }
        }

        WHEN("the real request also carries a trailing user ID and query string, as make_join does")
        {
            auto const request =
                make_request("/_matrix/federation/v1/make_join/" + encoded_room_id + "/@user:remote.example?ver=12");
            THEN("the room ID is still decoded correctly, unaffected by what follows it")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == decoded_room_id);
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

SCENARIO("Room ID is extracted from /send body when room_id follows a nested field",
         "[federation][routing][room-id][send]")
{
    GIVEN("a PUT /send/{txnId} body where the first PDU has nested objects before room_id")
    {
        // A real PDU often has "content", "hashes", or "unsigned" before "room_id".
        // The old find('}') would stop at the closing brace of "content" and miss
        // "room_id" entirely; brace-depth tracking must walk past nested objects.
        auto const room_id = std::string{"!nested:example.com"};
        auto const body = std::string{
            R"({"pdus":[{"content":{"msgtype":"m.text","body":"hi"},"hashes":{"sha256":"abc"},"room_id":")" + room_id +
            R"(","event_id":"$y:remote.example"}]})"};
        auto const request = make_request("/_matrix/federation/v1/send/txn-2", body);

        WHEN("the room ID is extracted")
        {
            THEN("it is found correctly even though nested objects precede it")
            {
                REQUIRE(federation_worker_room_id_from_request(request) == room_id);
            }
        }
    }

    GIVEN("a PUT /send/{txnId} body where the PDU has deeply nested content before room_id")
    {
        auto const room_id = std::string{"!deep:example.com"};
        auto const body =
            std::string{R"({"pdus":[{"content":{"body":"hi","relates_to":{"rel_type":"m.thread","event_id":"$x"}})"
                        R"(,"room_id":")" +
                        room_id + R"("}]})"};
        auto const request = make_request("/_matrix/federation/v1/send/txn-3", body);

        WHEN("the room ID is extracted")
        {
            THEN("it is found despite deeply nested content preceding it")
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

        WHEN("the target is /_matrix/federation/v1/query/directory?room_alias=... (the real spec shape)")
        {
            // room_alias is a query parameter here, not a path segment (unlike
            // every other room-scoped endpoint above), so it is deliberately
            // not extracted for shard routing — see docs/architecture.md,
            // "Federation worker room staleness" / known gap. Pinning empty
            // here documents the current (still-broken-for-shards>1) behaviour
            // so a future change to this routing is a visible, deliberate diff.
            auto const request =
                make_request("/_matrix/federation/v1/query/directory?room_alias=%23alias%3Aexample.com");
            THEN("no room ID is extracted; the request always routes to shard 0")
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

SCENARIO("Federation key server endpoint is matched exactly", "[federation][routing][key-server]")
{
    GIVEN("the exact key server path")
    {
        WHEN("the target has no query string")
        {
            THEN("it is recognized as the key server endpoint")
            {
                REQUIRE(is_federation_key_server_endpoint("/_matrix/key/v2/server"));
            }
        }

        WHEN("the target has a query string")
        {
            THEN("it is still recognized as the key server endpoint")
            {
                REQUIRE(is_federation_key_server_endpoint("/_matrix/key/v2/server?key=ed25519:a"));
            }
        }
    }

    GIVEN("targets that contain the key server path as a substring")
    {
        WHEN("the substring appears as a path prefix segment")
        {
            THEN("it is rejected so the request is not handled locally")
            {
                REQUIRE_FALSE(is_federation_key_server_endpoint("/evil/_matrix/key/v2/server"));
                REQUIRE_FALSE(is_federation_key_server_endpoint("/_matrix/key/v2/server/extra"));
            }
        }

        WHEN("the substring appears at the end of a longer last segment")
        {
            THEN("it is rejected")
            {
                REQUIRE_FALSE(is_federation_key_server_endpoint("/_matrix/key/v2/server2"));
            }
        }
    }

    GIVEN("unrelated federation targets")
    {
        WHEN("they are room-scoped or profile endpoints")
        {
            THEN("they are not recognized as the key server endpoint")
            {
                REQUIRE_FALSE(is_federation_key_server_endpoint("/_matrix/federation/v1/state/!room:example.com"));
                REQUIRE_FALSE(is_federation_key_server_endpoint("/_matrix/federation/v1/query/profile"));
            }
        }
    }
}
