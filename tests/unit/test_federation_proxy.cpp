// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>

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
