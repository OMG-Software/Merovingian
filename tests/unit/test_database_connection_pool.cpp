// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// DB-7, ADR-0154: persisted writes lease one of at most `limit` pooled
// connections. A lease is only ever waited for, never timed out, so a slot
// that is not given back is lost for the life of the process.

#include "merovingian/database/connection_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <tuple>

namespace
{

struct FakeConnection final
{
    int id{0};
};

using Pool = merovingian::database::ConnectionPool<FakeConnection>;

auto const always_reusable = [](FakeConnection const&) {
    return true;
};

} // namespace

SCENARIO("A failed or throwing connection open gives its pool slot back", "[database][db7][pool]")
{
    GIVEN("a pool of one connection")
    {
        auto pool = Pool{1U};

        WHEN("opening a connection fails")
        {
            auto const lease = pool.acquire(
                [] {
                    return std::optional<FakeConnection>{};
                },
                always_reusable);

            THEN("no lease is handed out and the slot is free again")
            {
                CHECK_FALSE(lease.has_value());
                CHECK(pool.in_use() == 0U);
            }
        }

        WHEN("opening a connection throws")
        {
            auto threw = false;
            try
            {
                std::ignore = pool.acquire(
                    []() -> std::optional<FakeConnection> {
                        throw std::runtime_error{"connect failed"};
                    },
                    always_reusable);
            }
            catch (std::runtime_error const&)
            {
                threw = true;
            }

            THEN("the exception reaches the caller and the slot is free again")
            {
                CHECK(threw);
                CHECK(pool.in_use() == 0U);
                auto const next = pool.acquire(
                    [] {
                        return std::optional<FakeConnection>{FakeConnection{2}};
                    },
                    always_reusable);
                CHECK(next.has_value());
            }
        }
    }

    GIVEN("a pool of one connection holding an idle connection")
    {
        auto pool = Pool{1U};
        {
            auto const first = pool.acquire(
                [] {
                    return std::optional<FakeConnection>{FakeConnection{1}};
                },
                always_reusable);
            REQUIRE(first.has_value());
        }
        REQUIRE(pool.in_use() == 0U);

        WHEN("checking whether the idle connection is reusable throws")
        {
            auto threw = false;
            try
            {
                std::ignore = pool.acquire(
                    [] {
                        return std::optional<FakeConnection>{FakeConnection{2}};
                    },
                    [](FakeConnection const&) -> bool {
                        throw std::runtime_error{"probe failed"};
                    });
            }
            catch (std::runtime_error const&)
            {
                threw = true;
            }

            THEN("the slot is free again")
            {
                CHECK(threw);
                CHECK(pool.in_use() == 0U);
            }
        }
    }
}

SCENARIO("A pooled connection is reused rather than reopened", "[database][db7][pool]")
{
    GIVEN("a pool that has handed out and taken back one connection")
    {
        auto pool = Pool{2U};
        auto opens = 0;
        auto const open = [&opens] {
            ++opens;
            return std::optional<FakeConnection>{FakeConnection{opens}};
        };
        {
            auto const first = pool.acquire(open, always_reusable);
            REQUIRE(first.has_value());
        }

        WHEN("another connection is leased")
        {
            auto lease = pool.acquire(open, always_reusable);

            THEN("it is the same connection, and one slot is in use while it is held")
            {
                REQUIRE(lease.has_value());
                CHECK(lease->get().id == 1);
                CHECK(opens == 1);
                CHECK(pool.opened_total() == 1U);
                CHECK(pool.in_use() == 1U);
            }
        }
    }
}
