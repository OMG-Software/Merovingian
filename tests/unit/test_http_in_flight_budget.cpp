// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// HTTP-2 / ADR-0079: an admission guard for operations that block a request
// thread on a peer this server does not control. Tags: [http-2][http].

#include "../support/joining_threads.hpp"
#include "merovingian/http/in_flight_budget.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <latch>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using merovingian::http::InFlightBudget;

SCENARIO("The in-flight budget refuses work over its global cap without waiting", "[http-2][http]")
{
    GIVEN("a global cap of four and a per-key cap large enough not to matter")
    {
        auto budget = InFlightBudget{};
        auto held = std::vector<InFlightBudget::Slot>{};
        for (auto index = 0; index < 4; ++index)
        {
            auto slot = budget.try_acquire("client-" + std::to_string(index), 4U, 8U);
            REQUIRE(slot.has_value());
            held.push_back(std::move(*slot));
        }

        WHEN("a fifth client asks for a slot")
        {
            auto const fifth = budget.try_acquire("client-4", 4U, 8U);

            THEN("it is refused at once and the count is unchanged")
            {
                REQUIRE_FALSE(fifth.has_value());
                REQUIRE(budget.active() == 4U);
            }
        }

        WHEN("one held slot is released")
        {
            held.pop_back();
            auto const next = budget.try_acquire("client-4", 4U, 8U);

            THEN("a new client is admitted")
            {
                REQUIRE(next.has_value());
                REQUIRE(budget.active() == 4U);
            }
        }
    }
}

SCENARIO("The in-flight budget caps each client separately from the global cap", "[http-2][http]")
{
    GIVEN("a per-client cap of one and a global cap of four")
    {
        auto budget = InFlightBudget{};
        auto const first = budget.try_acquire("192.0.2.1", 4U, 1U);
        REQUIRE(first.has_value());

        WHEN("the same client asks for a second concurrent slot")
        {
            auto const second = budget.try_acquire("192.0.2.1", 4U, 1U);

            THEN("it is refused, without consuming a global slot")
            {
                REQUIRE_FALSE(second.has_value());
                REQUIRE(budget.active() == 1U);
                REQUIRE(budget.active("192.0.2.1") == 1U);
            }
        }

        WHEN("a different client asks for a slot")
        {
            auto const other = budget.try_acquire("192.0.2.2", 4U, 1U);

            THEN("it is admitted")
            {
                REQUIRE(other.has_value());
                REQUIRE(budget.active() == 2U);
            }
        }
    }
}

SCENARIO("A slot is returned on every path that ends its scope", "[http-2][http]")
{
    GIVEN("a budget with one slot in use")
    {
        auto budget = InFlightBudget{};

        WHEN("the slot goes out of scope")
        {
            {
                auto const slot = budget.try_acquire("192.0.2.1", 1U, 1U);
                REQUIRE(slot.has_value());
                REQUIRE(budget.active() == 1U);
            }

            THEN("the client and the budget are free again and no key is left tracked")
            {
                REQUIRE(budget.active() == 0U);
                REQUIRE(budget.active("192.0.2.1") == 0U);
                REQUIRE(budget.tracked_keys() == 0U);
                REQUIRE(budget.try_acquire("192.0.2.1", 1U, 1U).has_value());
            }
        }

        WHEN("the scope is left by an exception")
        {
            try
            {
                auto const slot = budget.try_acquire("192.0.2.1", 1U, 1U);
                REQUIRE(slot.has_value());
                throw std::runtime_error{"boom"};
            }
            catch (std::runtime_error const&)
            {
            }

            THEN("the slot was still returned")
            {
                REQUIRE(budget.active() == 0U);
            }
        }

        WHEN("the slot is moved to a new owner")
        {
            auto slot = budget.try_acquire("192.0.2.1", 1U, 1U);
            REQUIRE(slot.has_value());
            {
                auto const moved = std::move(*slot);
                slot.reset();

                THEN("the slot is counted once, not twice, and returned when the new owner ends")
                {
                    REQUIRE(budget.active() == 1U);
                }
            }
            REQUIRE(budget.active() == 0U);
        }
    }
}

SCENARIO("A cap of zero admits nothing", "[http-2][http]")
{
    GIVEN("a budget")
    {
        auto budget = InFlightBudget{};

        THEN("a zero global cap or a zero per-client cap refuses every request and leaves no state")
        {
            REQUIRE_FALSE(budget.try_acquire("192.0.2.1", 0U, 1U).has_value());
            REQUIRE_FALSE(budget.try_acquire("192.0.2.1", 4U, 0U).has_value());
            REQUIRE(budget.active() == 0U);
            REQUIRE(budget.tracked_keys() == 0U);
        }
    }
}

SCENARIO("The in-flight budget never admits more than the global cap under concurrent use",
         "[http-2][http][concurrency]")
{
    GIVEN("a global cap of four and thirty-two threads, each with its own client key, all released at once")
    {
        auto budget = InFlightBudget{};
        constexpr auto cap = std::uint32_t{4U};
        constexpr auto thread_count = std::size_t{32U};
        auto start = std::latch{static_cast<std::ptrdiff_t>(thread_count)};
        auto admitted = std::vector<int>(thread_count, 0);

        WHEN("every thread asks for a slot and holds it until all have asked")
        {
            {
                auto asked = std::latch{static_cast<std::ptrdiff_t>(thread_count)};
                auto threads = merovingian::tests::JoiningThreads{};
                for (auto index = std::size_t{0U}; index < thread_count; ++index)
                {
                    threads.emplace_back([&, index]() {
                        start.arrive_and_wait();
                        auto const slot = budget.try_acquire("client-" + std::to_string(index), cap, 1U);
                        admitted[index] = slot.has_value() ? 1 : 0;
                        asked.arrive_and_wait();
                    });
                }
            }

            THEN("exactly the cap was admitted and every slot was returned")
            {
                auto total = 0;
                for (auto const value : admitted)
                {
                    total += value;
                }
                REQUIRE(total == static_cast<int>(cap));
                REQUIRE(budget.active() == 0U);
                REQUIRE(budget.tracked_keys() == 0U);
            }
        }
    }
}
