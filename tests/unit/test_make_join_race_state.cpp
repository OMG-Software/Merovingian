// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// C33 (ADR-0725): the shared state of a make_join race. At most `parallelism` workers exist for one join; once the race
// is decided or over no candidate is handed out; and the request's client-outbound slot is held until the last worker
// ends, not until the caller returns. Driven on one thread, so the order is exact.
// Tags: [join][c33].

#include "merovingian/homeserver/MakeJoinRaceState.hpp"
#include "merovingian/http/InFlightBudget.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <latch>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace
{

using merovingian::homeserver::MakeJoinRaceState;

[[nodiscard]] auto names(std::size_t count) -> std::vector<std::string>
{
    auto result = std::vector<std::string>{};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        result.push_back("s" + std::to_string(index) + ".example");
    }
    return result;
}

} // namespace

SCENARIO("A make_join race uses at most the allowed number of workers", "[join][c33][security]")
{
    GIVEN("the worker count for a race")
    {
        THEN("it is the smaller of the parallelism and the number of candidates, and zero for none")
        {
            REQUIRE(MakeJoinRaceState::worker_count(8U, 20U) == 8U);
            REQUIRE(MakeJoinRaceState::worker_count(8U, 3U) == 3U);
            REQUIRE(MakeJoinRaceState::worker_count(1U, 20U) == 1U);
            REQUIRE(MakeJoinRaceState::worker_count(8U, 0U) == 0U);
        }
    }

    GIVEN("one worker over four candidates")
    {
        auto race = MakeJoinRaceState{names(4U), 1U};

        WHEN("the worker takes candidates one after another")
        {
            auto taken = std::vector<std::string>{};
            while (auto candidate = race.next_candidate())
            {
                taken.push_back(*candidate);
                race.record_answer(*candidate, false, "no", false);
            }

            THEN("each candidate is taken once, in order, by that one worker")
            {
                REQUIRE(taken == names(4U));
                REQUIRE(race.remaining == 0);
            }
        }
    }
}

SCENARIO("Candidates of a make_join race are not handed out once it is decided or over", "[join][c33][security]")
{
    GIVEN("a race among three candidates and two workers")
    {
        auto race = MakeJoinRaceState{names(3U), 2U};

        WHEN("the first candidate wins")
        {
            auto const first = race.next_candidate();
            REQUIRE(first.has_value());
            race.record_answer(*first, true, "template", false);

            THEN("no further candidate is handed out, and the rest are counted out")
            {
                REQUIRE(race.winner.has_value());
                REQUIRE(race.winner->first == "s0.example");
                REQUIRE_FALSE(race.next_candidate().has_value());
                REQUIRE_FALSE(race.next_candidate().has_value());
                REQUIRE(race.remaining == 0);
            }

            AND_WHEN("a slower candidate answers later")
            {
                race.record_answer("s9.example", true, "other", false);

                THEN("the first winner stands")
                {
                    REQUIRE(race.winner->first == "s0.example");
                }
            }
        }

        WHEN("every candidate fails before the caller gives up")
        {
            auto const first = race.next_candidate();
            race.record_answer(*first, false, "boom", false);
            auto const second = race.next_candidate();
            race.record_answer(*second, false, "refused", true);

            THEN("the last error and the refusal are kept, and the third is still handed out")
            {
                REQUIRE_FALSE(race.winner.has_value());
                REQUIRE(race.last_error == "refused");
                REQUIRE(race.refused);
                REQUIRE(race.next_candidate() == std::optional<std::string>{"s2.example"});
            }
        }

        WHEN("the caller stops waiting with one candidate in flight and two not started")
        {
            auto const first = race.next_candidate();
            REQUIRE(first.has_value());
            race.cancel();

            THEN("none of the two is ever started")
            {
                REQUIRE_FALSE(race.next_candidate().has_value());
                REQUIRE(race.remaining == 1);
                race.record_answer(*first, false, "late", false);
                REQUIRE(race.remaining == 0);
            }
        }
    }
}

SCENARIO("A make_join race keeps the request's client-outbound slot until its last worker ends",
         "[join][c33][security]")
{
    GIVEN("a client with one slot in a budget of one, adopted by a race with two workers")
    {
        auto budget = merovingian::http::InFlightBudget{};
        auto slot = budget.try_acquire("client", 1U, 1U);
        REQUIRE(slot.has_value());
        auto race = MakeJoinRaceState{names(2U), 2U};
        race.adopt_slot(std::move(slot));

        WHEN("the caller has stopped waiting and returned, and one worker has ended")
        {
            race.cancel();
            race.worker_finished();

            THEN("the client's budget still reads held, so it cannot start another join")
            {
                REQUIRE(budget.active("client") == 1U);
                REQUIRE_FALSE(budget.try_acquire("client", 1U, 1U).has_value());
            }

            AND_WHEN("the last worker ends")
            {
                race.worker_finished();

                THEN("the slot is released")
                {
                    REQUIRE(budget.active("client") == 0U);
                    REQUIRE(budget.try_acquire("client", 1U, 1U).has_value());
                }
            }
        }
    }

    GIVEN("a race whose workers have all ended before the slot is adopted")
    {
        auto budget = merovingian::http::InFlightBudget{};
        auto slot = budget.try_acquire("client", 1U, 1U);
        REQUIRE(slot.has_value());
        auto race = MakeJoinRaceState{names(1U), 1U};
        race.worker_finished();

        WHEN("the slot is adopted")
        {
            race.adopt_slot(std::move(slot));

            THEN("it is released at once, as there is nothing left to hold it for")
            {
                REQUIRE(budget.active("client") == 0U);
            }
        }
    }
}

SCENARIO("Workers sharing a make_join race take each candidate exactly once", "[join][c33][security]")
{
    GIVEN("four workers over 200 candidates, released together")
    {
        auto race = MakeJoinRaceState{names(200U), 4U};
        auto go = std::latch{1};
        auto taken = std::vector<std::vector<std::string>>(4U);
        auto threads = std::vector<std::thread>{};
        for (auto worker = std::size_t{0U}; worker < 4U; ++worker)
        {
            threads.emplace_back([&race, &go, &mine = taken[worker]] {
                go.wait();
                while (auto candidate = race.next_candidate())
                {
                    mine.push_back(*candidate);
                    race.record_answer(*candidate, false, "no", false);
                }
                race.worker_finished();
            });
        }

        WHEN("they run to the end")
        {
            go.count_down();
            for (auto& thread : threads)
            {
                thread.join();
            }
            auto all = std::vector<std::string>{};
            for (auto const& mine : taken)
            {
                all.insert(all.end(), mine.begin(), mine.end());
            }
            std::ranges::sort(all);
            auto expected = names(200U);
            std::ranges::sort(expected);

            THEN("every candidate was taken once and none twice, and the race is over")
            {
                REQUIRE(all == expected);
                REQUIRE(race.remaining == 0);
                REQUIRE(race.live_workers == 0U);
            }
        }
    }
}
