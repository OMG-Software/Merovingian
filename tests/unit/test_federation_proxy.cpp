// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::homeserver::federation_worker_shard_for;

} // namespace

SCENARIO("Federation worker shard routing is deterministic and bounded", "[federation][worker-pool][sharding]")
{
    GIVEN("two distinct room IDs and two shards")
    {
        auto const room_a = std::string_view{"!room1:example.com"};
        auto const room_b = std::string_view{"!room2:example.com"};
        auto const shards = std::uint32_t{2U};

        WHEN("each room ID is hashed with FNV-1a modulo shards")
        {
            auto const shard_a = federation_worker_shard_for(room_a, shards);
            auto const shard_b = federation_worker_shard_for(room_b, shards);

            THEN("both map to valid shard indices and are distributed across shards")
            {
                REQUIRE(shard_a < shards);
                REQUIRE(shard_b < shards);
                REQUIRE(shard_a != shard_b);
            }
        }
    }
}

SCENARIO("Single-sharded pool routes every room ID to shard 0", "[federation][worker-pool][sharding]")
{
    GIVEN("a single shard and a variety of room IDs")
    {
        auto const shards = std::uint32_t{1U};

        WHEN("any room ID is hashed")
        {
            THEN("it always lands on shard 0")
            {
                REQUIRE(federation_worker_shard_for("!room1:example.com", shards) == 0U);
                REQUIRE(federation_worker_shard_for("!room2:matrix.org", shards) == 0U);
                REQUIRE(federation_worker_shard_for("!a:b", shards) == 0U);
            }
        }
    }
}

SCENARIO("Non-room federation requests route to shard 0", "[federation][worker-pool][sharding]")
{
    GIVEN("a multi-shard configuration and an empty room ID")
    {
        auto const shards = std::uint32_t{4U};

        WHEN("a request without a room ID is routed")
        {
            auto const shard = federation_worker_shard_for({}, shards);

            THEN("it is sent to shard 0 so key/profile endpoints have a stable home")
            {
                REQUIRE(shard == 0U);
            }
        }
    }
}

SCENARIO("Shard routing is stable for the same room ID", "[federation][worker-pool][sharding]")
{
    GIVEN("a room ID and a shard count")
    {
        auto const room_id = std::string_view{"!stable:example.com"};
        auto const shards = std::uint32_t{3U};

        WHEN("the shard is computed repeatedly")
        {
            auto const first = federation_worker_shard_for(room_id, shards);
            auto const second = federation_worker_shard_for(room_id, shards);

            THEN("the same room ID always maps to the same shard")
            {
                REQUIRE(first == second);
                REQUIRE(first < shards);
            }
        }
    }
}

SCENARIO("Shard routing gracefully handles a zero-shard count", "[federation][worker-pool][sharding]")
{
    GIVEN("a configuration bug that sets shards to 0")
    {
        auto const shards = std::uint32_t{0U};

        WHEN("a room ID is routed anyway")
        {
            auto const shard = federation_worker_shard_for("!room:example.com", shards);

            THEN("it falls back to shard 0 rather than dividing by zero")
            {
                REQUIRE(shard == 0U);
            }
        }
    }
}

SCENARIO("Every routed room ID lands within the configured shard range", "[federation][worker-pool][sharding]")
{
    GIVEN("a set of representative room IDs and an eight-shard pool")
    {
        auto const shards = std::uint32_t{8U};
        auto const rooms = std::vector<std::string_view>{
            "!room1:example.com", "!room2:matrix.org", "!a:b", "!conference:example.org", "!space:matrix.org",
        };

        WHEN("each room ID is hashed")
        {
            THEN("the resulting shard is always less than the shard count")
            {
                for (auto const room_id : rooms)
                {
                    auto const shard = federation_worker_shard_for(room_id, shards);
                    REQUIRE(shard < shards);
                }
            }
        }
    }
}

SCENARIO("Room-scoped federation requests map to the same shard as the extracted room ID",
         "[federation][proxy][routing]")
{
    GIVEN("a four-shard configuration and a room-scoped request")
    {
        auto const shards = std::uint32_t{4U};
        auto const request_target = std::string{"/_matrix/federation/v1/state/!room:example.com"};
        auto const room_id = std::string{"!room:example.com"};

        WHEN("the shard is computed from the extracted room ID")
        {
            auto const shard = federation_worker_shard_for(room_id, shards);

            THEN("it matches the shard computed directly from the room ID")
            {
                REQUIRE(shard == federation_worker_shard_for(room_id, shards));
                REQUIRE(shard < shards);
            }
        }
    }
}

SCENARIO("FNV-1a sharding distributes room IDs and remains stable across shard counts",
         "[federation][worker-pool][sharding]")
{
    GIVEN("a fixed room ID and varying shard counts")
    {
        auto const room_id = std::string_view{"!distribution:example.com"};

        WHEN("the shard is computed for different counts")
        {
            THEN("the hash is bounded and stable for each count")
            {
                for (auto shards = std::uint32_t{1U}; shards <= 16U; ++shards)
                {
                    auto const shard = federation_worker_shard_for(room_id, shards);
                    REQUIRE(shard < shards);
                    REQUIRE(shard == federation_worker_shard_for(room_id, shards));
                }
            }
        }
    }
}

// F-43 (ADR-0349): a worker's reply to an outbound request is input, not a fact. The size cap and
// the status range are the request's own contract: nothing a worker relays may exceed what main
// asked for, or be an HTTP status no server can send.
SCENARIO("A federation worker's outbound reply is checked against the request before main uses it",
         "[federation][worker-pool][outbound][f-43]")
{
    GIVEN("a request that allows a 1 KiB response")
    {
        auto request = merovingian::http::OutboundRequest{};
        request.max_response_body_bytes = 1024U;

        auto reply = merovingian::http::OutboundResult{};
        reply.ok = true;
        reply.response.status = 200U;
        reply.response.body = "{}";

        WHEN("the worker's reply is a success within the cap")
        {
            auto const checked = merovingian::homeserver::validate_worker_outbound_reply(request, reply);

            THEN("it is passed on unchanged")
            {
                REQUIRE(checked.ok);
                REQUIRE(checked.response.status == 200U);
                REQUIRE(checked.response.body == "{}");
            }
        }

        WHEN("the worker's reply body is larger than the request allowed")
        {
            reply.response.body = std::string(1025U, 'x');
            auto const checked = merovingian::homeserver::validate_worker_outbound_reply(request, reply);

            THEN("it is a failure that carries no body")
            {
                REQUIRE_FALSE(checked.ok);
                REQUIRE(checked.response.body.empty());
            }
        }

        WHEN("the worker's reply body is exactly the cap")
        {
            reply.response.body = std::string(1024U, 'x');
            auto const checked = merovingian::homeserver::validate_worker_outbound_reply(request, reply);

            THEN("it is accepted")
            {
                REQUIRE(checked.ok);
                REQUIRE(checked.response.body.size() == 1024U);
            }
        }

        WHEN("the worker's success reply has a status outside 100 to 599")
        {
            auto const statuses = std::vector<std::uint16_t>{0U, 99U, 600U, 1000U};
            auto accepted = std::vector<std::uint16_t>{};
            for (auto const status : statuses)
            {
                reply.response.status = status;
                if (merovingian::homeserver::validate_worker_outbound_reply(request, reply).ok)
                {
                    accepted.push_back(status);
                }
            }

            THEN("none of them is accepted")
            {
                REQUIRE(accepted.empty());
            }
        }

        WHEN("the worker's success reply has the lowest and the highest valid status")
        {
            reply.response.status = 100U;
            auto const low = merovingian::homeserver::validate_worker_outbound_reply(request, reply);
            reply.response.status = 599U;
            auto const high = merovingian::homeserver::validate_worker_outbound_reply(request, reply);

            THEN("both are accepted")
            {
                REQUIRE(low.ok);
                REQUIRE(high.ok);
            }
        }

        WHEN("the worker reports a failure but attaches a status and a body as if the remote had answered")
        {
            reply.ok = false;
            reply.response.status = 200U;
            reply.response.body = R"({"device_keys":{}})";
            auto const checked = merovingian::homeserver::validate_worker_outbound_reply(request, reply);

            THEN("the failure carries neither")
            {
                REQUIRE_FALSE(checked.ok);
                REQUIRE(checked.response.status == 0U);
                REQUIRE(checked.response.body.empty());
            }
        }

        WHEN("the worker's error detail is long and holds control characters")
        {
            reply.ok = false;
            reply.error_detail = std::string(1000U, 'a') + "\r\nX-Injected: 1";
            auto const checked = merovingian::homeserver::validate_worker_outbound_reply(request, reply);

            THEN("it is cut to the cap")
            {
                REQUIRE(checked.error_detail.size() == merovingian::homeserver::max_worker_outbound_error_detail_bytes);
            }
        }

        WHEN("the worker's short error detail holds control and non-ASCII bytes")
        {
            reply.ok = false;
            reply.error_detail = "bad\r\n\x01\xff end";
            auto const checked = merovingian::homeserver::validate_worker_outbound_reply(request, reply);

            THEN("each such byte is replaced and the printable text is kept")
            {
                REQUIRE(checked.error_detail == "bad???? end");
            }
        }
    }
}
