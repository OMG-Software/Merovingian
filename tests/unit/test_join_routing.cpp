// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         FEDERATED JOIN ROUTING (via / server_name) TESTS                |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18 — POST /join/{roomIdOrAlias}      |
// |  Spec: Matrix room version 12 (MSC4291) — room IDs as create hashes     |
// |                                                                         |
// |  To join a room over federation the server must know which resident     |
// |  server(s) to contact. For room versions 10 and 11 the server domain    |
// |  is embedded in the room ID (!opaque:server). Room version 12 IDs are   |
// |  bare reference hashes with NO server domain, so the only route is the   |
// |  via / server_name query parameters supplied by the client. These tests |
// |  pin that behaviour across all three stable room versions.              |
// +-------------------------------------------------------------------------+

#include "merovingian/homeserver/room_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using merovingian::homeserver::join_candidate_servers;
using merovingian::homeserver::parse_join_via_servers;
using Servers = std::vector<std::string>;

SCENARIO("parse_join_via_servers extracts server_name and via query parameters", "[join][federation][routing]")
{
    GIVEN("query strings carrying join routing parameters")
    {
        WHEN("a single legacy server_name parameter is parsed")
        {
            THEN("the server is returned")
            {
                REQUIRE(parse_join_via_servers("server_name=matrix.example") == Servers{"matrix.example"});
            }
        }

        WHEN("multiple via parameters are parsed (MSC4156)")
        {
            THEN("all servers are returned in request order")
            {
                REQUIRE(parse_join_via_servers("via=a.example&via=b.example") == Servers{"a.example", "b.example"});
            }
        }

        WHEN("both server_name and via are present")
        {
            THEN("both spellings are honoured, in order")
            {
                REQUIRE(parse_join_via_servers("server_name=a.example&via=b.example") ==
                        Servers{"a.example", "b.example"});
            }
        }

        WHEN("a value is percent-encoded (e.g. a host:port)")
        {
            THEN("the value is percent-decoded")
            {
                REQUIRE(parse_join_via_servers("via=a.example%3A8448") == Servers{"a.example:8448"});
            }
        }

        WHEN("a server is repeated and unrelated parameters are present")
        {
            THEN("duplicates are removed and unrelated parameters ignored")
            {
                REQUIRE(parse_join_via_servers("filter=x&via=a.example&via=a.example&limit=5") == Servers{"a.example"});
            }
        }

        WHEN("the query string is empty or has no routing parameters")
        {
            THEN("no servers are returned")
            {
                REQUIRE(parse_join_via_servers("").empty());
                REQUIRE(parse_join_via_servers("limit=5&filter=x").empty());
            }
        }
    }
}

SCENARIO("join_candidate_servers routes pre-v12 rooms by domain and v12 rooms by via (MSC4291)",
         "[join][federation][routing][room-version]")
{
    auto constexpr our = std::string_view{"home.example"};

    GIVEN("room versions 10 and 11, whose room IDs embed the resident server")
    {
        WHEN("no via servers are supplied")
        {
            THEN("the room ID's domain is used as the sole candidate")
            {
                // Room v10/v11 IDs are "!opaque:server"; the server is derivable.
                REQUIRE(join_candidate_servers({}, "!abc:remote.example", our) == Servers{"remote.example"});
            }
        }

        WHEN("via servers are also supplied")
        {
            THEN("via servers come first, then the room ID domain")
            {
                REQUIRE(join_candidate_servers({"s1.example"}, "!abc:remote.example", our) ==
                        Servers{"s1.example", "remote.example"});
            }
        }
    }

    GIVEN("a room version 12 room ID, which is a bare hash with no server domain (MSC4291)")
    {
        auto constexpr v12_room = std::string_view{"!2YQSq5ktnAd_dGjYrlQH9xoneatU4LJBwuoadqUhfTA"};

        WHEN("via servers are supplied")
        {
            THEN("the via servers are the candidates — the room is routable")
            {
                REQUIRE(join_candidate_servers({"s1.example", "s2.example"}, v12_room, our) ==
                        Servers{"s1.example", "s2.example"});
            }
        }

        WHEN("no via servers are supplied")
        {
            THEN("there are no candidates — a v12 join cannot be routed without via")
            {
                // This is the gap this feature closes: previously join_room rejected with
                // 403 "unknown room"; now the caller must supply via, and an empty list is
                // surfaced explicitly so the join endpoint can return a clear error.
                REQUIRE(join_candidate_servers({}, v12_room, our).empty());
            }
        }
    }

    GIVEN("candidate lists containing our own server and duplicates")
    {
        WHEN("the candidate list is built")
        {
            THEN("our own server is excluded and duplicates removed")
            {
                REQUIRE(join_candidate_servers({"home.example", "s1.example"}, "!abc:home.example", our) ==
                        Servers{"s1.example"});
                REQUIRE(join_candidate_servers({"s1.example"}, "!abc:s1.example", our) == Servers{"s1.example"});
            }
        }
    }
}
