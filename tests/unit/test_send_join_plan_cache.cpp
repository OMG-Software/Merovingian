// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// ADR-0624: the bounds and the synchronisation of the send_join plan cache. What it holds is tested in
// tests/integration/test_send_join_answer_flow.cpp.

#include "merovingian/homeserver/SendJoinPlanBase.hpp"
#include "merovingian/homeserver/SendJoinPlanCache.hpp"
#include "merovingian/homeserver/SendJoinPlanStamp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace
{

using merovingian::homeserver::SendJoinPlanBase;
using merovingian::homeserver::SendJoinPlanCache;
using merovingian::homeserver::SendJoinPlanStamp;

[[nodiscard]] auto always_valid(SendJoinPlanBase const&) -> bool
{
    return true;
}

// Asks for `room` and answers the state size of the base it was given.
auto ask(SendJoinPlanCache& cache, std::string const& room, SendJoinPlanStamp const& stamp, std::size_t ids = 1U)
    -> std::size_t
{
    auto seen = std::size_t{0U};
    cache.with_base(
        room, false, stamp, always_valid,
        [ids] {
            auto base = SendJoinPlanBase{};
            base.state_event_ids.assign(ids, "$id");
            return base;
        },
        [&seen](SendJoinPlanBase const& base) {
            seen = base.state_event_ids.size();
        });
    return seen;
}

} // namespace

SCENARIO("The send_join plan cache keeps a base only while its stamp holds",
         "[homeserver][send-join-plan-cache][boundary]")
{
    GIVEN("a cache holding one room's base")
    {
        auto cache = SendJoinPlanCache{};
        auto const stamp = SendJoinPlanStamp{1U, 4U, 2U, 100U, 200U};
        std::ignore = ask(cache, "!a", stamp);

        WHEN("it is asked again with the same stamp")
        {
            std::ignore = ask(cache, "!a", stamp);

            THEN("nothing is built")
            {
                REQUIRE(cache.builds() == 1U);
            }
        }

        WHEN("any field of the stamp differs")
        {
            auto later = stamp;
            later.state_rows = 5U;
            std::ignore = ask(cache, "!a", later);

            THEN("it is built again, and replaces the old one")
            {
                REQUIRE(cache.builds() == 2U);
                REQUIRE(cache.entries() == 1U);
            }
        }

        WHEN("the validity check refuses it")
        {
            cache.with_base(
                "!a", false, stamp,
                [](SendJoinPlanBase const&) {
                    return false;
                },
                [] {
                    return SendJoinPlanBase{};
                },
                [](SendJoinPlanBase const&) {
                });

            THEN("it is built again")
            {
                REQUIRE(cache.builds() == 2U);
            }
        }

        WHEN("it is asked for the same room without omit_members' answer")
        {
            cache.with_base(
                "!a", true, stamp, always_valid,
                [] {
                    return SendJoinPlanBase{};
                },
                [](SendJoinPlanBase const&) {
                });

            THEN("the two are separate entries")
            {
                REQUIRE(cache.builds() == 2U);
                REQUIRE(cache.entries() == 2U);
            }
        }
    }
}

SCENARIO("The send_join plan cache is bounded", "[homeserver][send-join-plan-cache][boundary][security]")
{
    auto const stamp = SendJoinPlanStamp{1U, 4U, 2U, 100U, 200U};

    GIVEN("a cache of two entries")
    {
        auto cache = SendJoinPlanCache{2U, 1'000'000U, 8U};
        std::ignore = ask(cache, "!a", stamp);
        std::ignore = ask(cache, "!b", stamp);

        WHEN("a third room is asked for after the first was used again")
        {
            std::ignore = ask(cache, "!a", stamp);
            std::ignore = ask(cache, "!c", stamp);

            THEN("the least recently used is the one that went")
            {
                REQUIRE(cache.entries() == 2U);
                REQUIRE(cache.builds() == 3U);
                std::ignore = ask(cache, "!a", stamp);
                REQUIRE(cache.builds() == 3U);
                std::ignore = ask(cache, "!b", stamp);
                REQUIRE(cache.builds() == 4U);
            }
        }
    }

    GIVEN("a byte budget exactly the size of one base")
    {
        auto sample = SendJoinPlanBase{};
        sample.state_event_ids.assign(4U, "$id");
        auto cache = SendJoinPlanCache{8U, sample.estimated_bytes(), 8U};

        WHEN("a base of that size is asked for twice")
        {
            auto const seen = ask(cache, "!a", stamp, 4U);
            std::ignore = ask(cache, "!a", stamp, 4U);

            THEN("it is kept, and used")
            {
                REQUIRE(seen == 4U);
                REQUIRE(cache.builds() == 1U);
                REQUIRE(cache.bytes() == sample.estimated_bytes());
            }
        }

        WHEN("a base one ID larger is asked for")
        {
            auto const seen = ask(cache, "!a", stamp, 5U);

            THEN("it is used but not kept")
            {
                REQUIRE(seen == 5U);
                REQUIRE(cache.entries() == 0U);
                REQUIRE(cache.bytes() == 0U);
            }
        }

        WHEN("a second base is asked for")
        {
            std::ignore = ask(cache, "!a", stamp, 4U);
            std::ignore = ask(cache, "!b", stamp, 4U);

            THEN("the first makes way, and the bytes held stay within the budget")
            {
                REQUIRE(cache.entries() == 1U);
                REQUIRE(cache.bytes() == sample.estimated_bytes());
            }
        }
    }

    GIVEN("a memo of the state before a join, of two entries")
    {
        auto cache = SendJoinPlanCache{2U, 1'000'000U, 2U};
        cache.remember_membership_before("!a", "$one", "$before-one");
        cache.remember_membership_before("!a", "$two", {});

        WHEN("it is read within the bound")
        {
            THEN("each answer is exact, an empty one included, and another room's is not confused with it")
            {
                REQUIRE(cache.membership_before("!a", "$one") == "$before-one");
                REQUIRE(cache.membership_before("!a", "$two") == std::string{});
                REQUIRE_FALSE(cache.membership_before("!b", "$one").has_value());
            }
        }

        WHEN("a third is remembered")
        {
            cache.remember_membership_before("!a", "$three", "$before-three");

            THEN("the oldest has gone")
            {
                REQUIRE_FALSE(cache.membership_before("!a", "$one").has_value());
                REQUIRE(cache.membership_before("!a", "$two").has_value());
                REQUIRE(cache.membership_before("!a", "$three") == "$before-three");
            }
        }
    }
}

SCENARIO("The send_join plan cache can be used from many threads at once", "[homeserver][send-join-plan-cache]")
{
    GIVEN("one cache smaller than the rooms asked for, and threads released together")
    {
        auto cache = SendJoinPlanCache{4U, 1'000'000U, 16U};
        auto const stamp = SendJoinPlanStamp{1U, 4U, 2U, 100U, 200U};
        auto go = std::atomic<bool>{false};
        constexpr auto thread_count = std::size_t{8U};
        auto wrong = std::vector<std::size_t>(thread_count, 0U);

        WHEN("each asks for rooms in turn")
        {
            auto threads = std::vector<std::thread>{};
            for (auto index = std::size_t{0U}; index < thread_count; ++index)
            {
                threads.emplace_back([&cache, &stamp, &go, &wrong, index] {
                    while (!go.load())
                    {
                        std::this_thread::yield();
                    }
                    for (auto round = std::size_t{0U}; round < 200U; ++round)
                    {
                        auto const room = (round + index) % 8U;
                        if (ask(cache, "!" + std::to_string(room), stamp, room + 1U) != room + 1U)
                        {
                            ++wrong[index];
                        }
                        auto const id = "$" + std::to_string(round);
                        cache.remember_membership_before("!a", id, id);
                        std::ignore = cache.membership_before("!a", id);
                    }
                });
            }
            go.store(true);
            for (auto& thread : threads)
            {
                thread.join();
            }

            THEN("every thread read the base of the room it asked for, and the bounds held")
            {
                for (auto const count : wrong)
                {
                    REQUIRE(count == 0U);
                }
                REQUIRE(cache.entries() <= 4U);
            }
        }
    }
}
