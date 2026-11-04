// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The directory request parser, its relay frames and the page limits of the listing. What the endpoints
// answer is covered by tests/conformance/test_federation_public_rooms_conformance.cpp.

#include "../support/json_test_support.hpp"
#include "merovingian/federation/public_rooms.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/homeserver/public_rooms.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{

using merovingian::federation::PublicRoomsRequest;
using merovingian::tests::object_member_as_array;
using merovingian::tests::parse_object;
using merovingian::tests::string_member;

[[nodiscard]] auto database_with_published_rooms(std::size_t count) -> merovingian::homeserver::LocalDatabase
{
    auto database = merovingian::homeserver::LocalDatabase{};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        auto room = merovingian::homeserver::LocalRoom{};
        room.room_id = "!room" + std::to_string(index) + ":example.org";
        room.directory_public = true;
        database.rooms.push_back(std::move(room));
    }
    return database;
}

[[nodiscard]] auto rooms_in(std::string const& body) -> std::size_t
{
    auto const answer = parse_object(body);
    auto const* chunk = object_member_as_array(answer, "chunk");
    REQUIRE(chunk != nullptr);
    return chunk->size();
}

} // namespace

SCENARIO("The publicRooms route is matched for GET and POST and relayed to main", "[federation][public_rooms]")
{
    GIVEN("the inbound federation route table")
    {
        WHEN("each method is matched, with and without a query string")
        {
            auto const get =
                merovingian::federation::match_federation_route("GET", "/_matrix/federation/v1/publicRooms?limit=1");
            auto const post =
                merovingian::federation::match_federation_route("POST", "/_matrix/federation/v1/publicRooms");
            auto const put =
                merovingian::federation::match_federation_route("PUT", "/_matrix/federation/v1/publicRooms");

            THEN("GET and POST reach the endpoint, X-Matrix signed, on a worker's relay pool")
            {
                REQUIRE(get.matched);
                REQUIRE(post.matched);
                REQUIRE(get.route.endpoint == merovingian::federation::FederationEndpoint::public_rooms);
                REQUIRE(post.route.endpoint == merovingian::federation::FederationEndpoint::public_rooms);
                REQUIRE(get.route.requires_request_signature);
                REQUIRE(post.route.requires_request_signature);
                REQUIRE(merovingian::federation::federation_endpoint_requires_main_relay(
                    merovingian::federation::FederationEndpoint::public_rooms));
            }

            THEN("no other method does")
            {
                REQUIRE_FALSE(put.matched);
            }
        }
    }
}

SCENARIO("A worker relays a directory request as a frame main reads back with the same checks",
         "[federation][public_rooms][ipc]")
{
    GIVEN("a request using every field")
    {
        auto request = PublicRoomsRequest{};
        request.filter.generic_search_term = "chëese \"quoted\"";
        request.filter.room_types = std::vector<std::optional<std::string>>{std::nullopt, "m.space"};
        request.limit = 7U;
        request.since_offset = 42U;
        request.third_party_instance_id = "irc:freenode:0";

        WHEN("it crosses the relay frame")
        {
            auto const read = merovingian::ipc::deserialize_public_rooms_ingest(
                merovingian::ipc::serialize_public_rooms_ingest(request));

            THEN("main reads an equal request")
            {
                REQUIRE(read.has_value());
                REQUIRE(read->filter.generic_search_term == request.filter.generic_search_term);
                REQUIRE(read->filter.room_types == request.filter.room_types);
                REQUIRE(read->limit == request.limit);
                REQUIRE(read->since_offset == request.since_offset);
                REQUIRE(read->third_party_instance_id == request.third_party_instance_id);
                REQUIRE_FALSE(read->include_all_networks);
            }
        }
    }

    GIVEN("an empty request, with a filter of no types")
    {
        auto request = PublicRoomsRequest{};
        request.filter.room_types = std::vector<std::optional<std::string>>{};

        WHEN("it crosses the relay frame")
        {
            auto const read = merovingian::ipc::deserialize_public_rooms_ingest(
                merovingian::ipc::serialize_public_rooms_ingest(request));

            THEN("the empty list stays a list, which lists nothing, and does not become no filter")
            {
                REQUIRE(read.has_value());
                REQUIRE(read->filter.room_types.has_value());
                REQUIRE(read->filter.room_types->empty());
            }
        }
    }

    GIVEN("frames a compromised worker could send")
    {
        auto const frames = std::vector<std::string>{
            "not json",
            R"({"type":"public_rooms_ingest"})",
            R"({"type":"public_rooms_ingest","request":"not json"})",
            R"({"type":"public_rooms_ingest","request":"{\"since\":\"not-a-token\"}"})",
            R"({"type":"public_rooms_ingest","request":"{\"limit\":-1}"})",
            R"({"type":"public_rooms_ingest","request":"{\"include_all_networks\":true,\"third_party_instance_id\":\"x\"}"})",
        };

        WHEN("main reads each")
        {
            THEN("none becomes a request")
            {
                for (auto const& frame : frames)
                {
                    INFO("frame: " << frame);
                    REQUIRE_FALSE(merovingian::ipc::deserialize_public_rooms_ingest(frame).has_value());
                }
            }
        }
    }

    GIVEN("main's answers")
    {
        WHEN("a listing crosses the result frame")
        {
            auto const body = std::string{R"({"chunk":[{"name":"quoted \"name\""}]})"};
            auto const read = merovingian::ipc::deserialize_public_rooms_ingest_result(
                merovingian::ipc::serialize_public_rooms_ingest_result(body));
            THEN("the worker gets the same bytes")
            {
                REQUIRE(read == body);
            }
        }

        WHEN("main refused the frame, or answered with its overload frame")
        {
            auto const refused = merovingian::ipc::deserialize_public_rooms_ingest_result(
                merovingian::ipc::serialize_public_rooms_ingest_result(std::nullopt));
            auto const overloaded = merovingian::ipc::deserialize_public_rooms_ingest_result(
                R"({"type":"error","status":503,"reason":"main at per-channel in-flight cap"})");
            THEN("the worker has no listing, never an empty one")
            {
                REQUIRE_FALSE(refused.has_value());
                REQUIRE_FALSE(overloaded.has_value());
            }
        }
    }
}

// A remote server chooses `limit` and `since`, and a room's name and topic can reach 64 KiB each.
SCENARIO("A directory page is bounded in rooms and in bytes, and paging always advances",
         "[federation][public_rooms][paging]")
{
    GIVEN("five published rooms and one unpublished")
    {
        auto database = database_with_published_rooms(5U);
        auto hidden = merovingian::homeserver::LocalRoom{};
        hidden.room_id = "!hidden:example.org";
        database.rooms.push_back(std::move(hidden));

        WHEN("a page's byte ceiling is smaller than one room")
        {
            auto const first = merovingian::homeserver::public_rooms_response_json(database, {}, 100U, 0U, {}, 1U);
            THEN("the page still holds one room, with next_batch reaching the next")
            {
                REQUIRE(rooms_in(first) == 1U);
                auto const answer = parse_object(first);
                REQUIRE(*string_member(answer, "next_batch") == "1");
            }
        }

        WHEN("a byte ceiling is walked to the end")
        {
            auto seen = std::size_t{0U};
            auto since = std::size_t{0U};
            auto pages = std::size_t{0U};
            auto more = true;
            while (more && pages < 10U)
            {
                auto const body =
                    merovingian::homeserver::public_rooms_response_json(database, {}, 100U, since, {}, 1U);
                seen += rooms_in(body);
                ++pages;
                auto const answer = parse_object(body);
                auto const* next = string_member(answer, "next_batch");
                more = next != nullptr;
                if (more)
                {
                    since = std::stoul(*next);
                }
            }
            THEN("every published room arrives once and paging stops")
            {
                REQUIRE(seen == 5U);
                REQUIRE(pages == 5U);
                REQUIRE_FALSE(more);
            }
        }

        WHEN("the limit is 0, which no caller should pass")
        {
            auto const body = merovingian::homeserver::public_rooms_response_json(database, {}, 0U, 0U);
            THEN("the page holds one room rather than none, so paging cannot stand still")
            {
                REQUIRE(rooms_in(body) == 1U);
            }
        }

        WHEN("since is the largest number the parser accepts")
        {
            auto const body =
                merovingian::homeserver::public_rooms_response_json(database, {}, 2U, static_cast<std::size_t>(-1));
            THEN("the page is empty, ends paging, and prev_batch leads back into the directory")
            {
                REQUIRE(rooms_in(body) == 0U);
                auto const answer = parse_object(body);
                REQUIRE(string_member(answer, "next_batch") == nullptr);
                REQUIRE(*string_member(answer, "prev_batch") == "3");
            }
        }
    }
}
