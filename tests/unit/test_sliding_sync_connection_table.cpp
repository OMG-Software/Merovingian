// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run 3, finding C06 follow-up: sweeping idle sliding sync connections costs the connections it removes,
// not every connection of every user (ADR-0663).

#include "merovingian/sync/SlidingSyncConnectionTable.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <string>
#include <tuple>

namespace
{

using merovingian::sync::SlidingSyncConnectionTable;
using Clock = std::chrono::steady_clock;

constexpr auto ttl = std::chrono::hours{1};

[[nodiscard]] auto key_of(std::size_t number) -> std::string
{
    return "user" + std::to_string(number) + "/device/conn";
}

} // namespace

SCENARIO("Sweeping idle sliding sync connections visits only the idle ones", "[sync][sliding-sync][c06][unit]")
{
    GIVEN("500 connections of other users, all touched a minute ago")
    {
        auto const start = Clock::now();
        auto table = SlidingSyncConnectionTable{};
        for (auto number = std::size_t{0U}; number < 500U; ++number)
        {
            std::ignore = table.touch(key_of(number), start);
        }
        auto const now = start + std::chrono::minutes{1};

        WHEN("the sweep runs with none of them idle")
        {
            auto const before = table.idle_entries_visited();
            table.erase_idle(now, ttl);

            THEN("it looked at no more than one entry and removed none")
            {
                REQUIRE(table.idle_entries_visited() - before <= 1U);
                REQUIRE(table.size() == 500U);
                REQUIRE(table.index_size() == 500U);
            }
        }
        WHEN("three of them are idle for over an hour and the sweep runs")
        {
            for (auto number = std::size_t{0U}; number < 3U; ++number)
            {
                std::ignore = table.touch(key_of(number), start - std::chrono::hours{2});
            }
            auto const before = table.idle_entries_visited();
            table.erase_idle(now, ttl);

            THEN("it looked at the three and the one that stopped it, and removed exactly those")
            {
                REQUIRE(table.idle_entries_visited() - before == 4U);
                REQUIRE(table.size() == 497U);
                REQUIRE(table.index_size() == 497U);
                REQUIRE_FALSE(table.contains(key_of(0U)));
                REQUIRE(table.contains(key_of(3U)));
            }
        }
        WHEN("an old connection is touched again before the sweep")
        {
            std::ignore = table.touch(key_of(7U), start - std::chrono::hours{2});
            std::ignore = table.touch(key_of(7U), now);
            table.erase_idle(now + std::chrono::minutes{30}, ttl);

            THEN("it is kept, and the index holds one entry per connection")
            {
                REQUIRE(table.contains(key_of(7U)));
                REQUIRE(table.index_size() == table.size());
            }
        }
        WHEN("connections are erased by key")
        {
            table.erase(key_of(1U));
            table.erase(key_of(1U));
            table.erase("not-held");

            THEN("map and index agree and the erased key is not swept later")
            {
                REQUIRE(table.size() == 499U);
                REQUIRE(table.index_size() == 499U);
                table.erase_idle(now + std::chrono::hours{3}, ttl);
                REQUIRE(table.empty());
                REQUIRE(table.index_size() == 0U);
            }
        }
    }
}
