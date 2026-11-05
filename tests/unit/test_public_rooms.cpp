// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The directory request parser, its relay frames, the page limits of the listing, and the project's rules for
// the handler that the spec does not state. What the spec requires of the endpoints is covered by
// tests/conformance/test_federation_public_rooms_conformance.cpp.

#include "../federation_signing_test_support.hpp"
#include "../support/json_test_support.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/public_rooms.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/homeserver/public_rooms.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <variant>
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

auto const remote_origin = std::string{"remote.example.org"};
auto const remote_key_id = std::string{"ed25519:public-rooms-unit"};
auto const remote_key_seed = std::string{"public-rooms-unit-seed"};
auto const public_rooms_path = std::string{"/_matrix/federation/v1/publicRooms"};

// The handler alone, with one remote server it trusts and no directory provider.
[[nodiscard]] auto inbound_state() -> merovingian::federation::FederationRuntimeState
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 65536U;
    config.remote_timeout_seconds = 30U;
    config.server_name = "example.org";
    auto state = merovingian::federation::make_federation_runtime_state(config);

    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = remote_origin;
    remote.signing_key = {remote_origin, remote_key_id, 2000U,
                          merovingian::federation::test::keypair_from_seed(remote_key_seed).public_key};
    remote.discovery.server_name = remote_origin;
    remote.discovery.well_known_host = remote_origin;
    remote.discovery.resolved_host = remote_origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    merovingian::federation::upsert_remote(state, remote);
    return state;
}

[[nodiscard]] auto signed_request(std::string method, std::string body)
    -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = std::move(method);
    request.target = public_rooms_path;
    request.origin = remote_origin;
    request.destination = "example.org";
    request.key_id = remote_key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = std::move(body);
    request.signature = merovingian::federation::make_federation_signature(
        remote_origin, request.destination, request.method, request.target, request.body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return request;
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
                // A null entry and a named type both survive: `null` is the spec's way to ask for rooms without a type.
                REQUIRE(read->filter.room_types == request.filter.room_types);
                REQUIRE(read->limit == request.limit);
                REQUIRE(read->since_offset == request.since_offset);
                REQUIRE(read->third_party_instance_id == request.third_party_instance_id);
                // Left unset, so it can sit beside third_party_instance_id, which requires it to be false.
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
                // The frame must keep this apart from "no filter", which lists every room rather than none.
                REQUIRE(read->filter.room_types->empty());
            }
        }
    }

    // A GET's `limit` and `since` can be any size_t, but a JSON integer stops at 2^53 - 1. Refusing the frame
    // would turn a request main answers into a 503 on a server with workers.
    GIVEN("a GET whose limit and since are the largest values the parser accepts")
    {
        auto const parsed =
            merovingian::federation::parse_public_rooms_query("18446744073709551615", "18446744073709551615", {}, {});
        REQUIRE(std::holds_alternative<PublicRoomsRequest>(parsed));
        auto const& request = std::get<PublicRoomsRequest>(parsed);

        WHEN("it crosses the relay frame")
        {
            auto const read = merovingian::ipc::deserialize_public_rooms_ingest(
                merovingian::ipc::serialize_public_rooms_ingest(request));

            THEN("main reads a request, with since unchanged and the limit still above any page size")
            {
                REQUIRE(read.has_value());
                REQUIRE(read->since_offset == request.since_offset);
                REQUIRE(read->limit.has_value());
                REQUIRE(*read->limit == std::size_t{9007199254740991U});
            }
        }
    }

    // Main treats a worker's frame as untrusted input (ADR-0071), so each of these must end in no request at all.
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
                // The listing is a JSON text, so quotes in a room name must survive the frame's own escaping.
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

// ADR-0461: a worker whose relay to main brings back no listing has no answer to give. An empty `chunk` is a valid
// answer that says this server publishes nothing, so that case must not look like one.
SCENARIO("The publicRooms handler answers with an error when no listing can be had",
         "[federation][public_rooms][unavailable]")
{
    GIVEN("a directory provider that gives no listing, as a worker's does when main refuses the relay")
    {
        auto state = inbound_state();
        state.public_rooms_provider = [](PublicRoomsRequest const&) -> std::optional<std::string> {
            return std::nullopt;
        };

        WHEN("a GET and a POST are handled")
        {
            auto const get =
                merovingian::federation::handle_inbound_federation_request(state, signed_request("GET", ""));
            auto const post =
                merovingian::federation::handle_inbound_federation_request(state, signed_request("POST", "{}"));

            THEN("both are 503 M_UNAVAILABLE, never an empty directory")
            {
                for (auto const& response : {get, post})
                {
                    REQUIRE(response.status == 503U);
                    REQUIRE(response.body.find("M_UNAVAILABLE") != std::string::npos);
                    REQUIRE(response.body.find("chunk") == std::string::npos);
                }
            }
        }
    }

    GIVEN("no directory provider at all")
    {
        auto state = inbound_state();

        WHEN("a GET is handled")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(state, signed_request("GET", ""));

            THEN("it is 501, with no directory in the answer")
            {
                REQUIRE(response.status == 501U);
                REQUIRE(response.body.find("chunk") == std::string::npos);
            }
        }
    }
}

// Project rule (src/federation/AGENTS.md): every non-/send endpoint counts against the per-origin request cap, keyed
// by the origin X-Matrix proved. The spec marks this endpoint "Rate-limited: No", which tells a requester not to
// expect 429; it does not require a server to accept a flood.
SCENARIO("GET and POST /publicRooms count against the per-origin request cap", "[federation][public_rooms][rate_limit]")
{
    GIVEN("a per-origin cap of two requests a minute and a provider that counts its calls")
    {
        auto state = inbound_state();
        state.config.per_origin_request_rate = {2U, 60U};
        auto listings = std::size_t{0U};
        state.public_rooms_provider = [&listings](PublicRoomsRequest const&) -> std::optional<std::string> {
            ++listings;
            return std::string{R"({"chunk":[]})"};
        };

        WHEN("three requests arrive from one origin")
        {
            auto const first =
                merovingian::federation::handle_inbound_federation_request(state, signed_request("GET", ""));
            auto const second =
                merovingian::federation::handle_inbound_federation_request(state, signed_request("POST", "{}"));
            auto const third =
                merovingian::federation::handle_inbound_federation_request(state, signed_request("GET", ""));

            THEN("the first two are answered and the third is refused before anything is listed")
            {
                REQUIRE(first.status == 200U);
                REQUIRE(second.status == 200U);
                REQUIRE(third.status == 429U);
                REQUIRE(third.body.find("M_LIMIT_EXCEEDED") != std::string::npos);
                REQUIRE(listings == 2U);
            }
        }
    }
}
