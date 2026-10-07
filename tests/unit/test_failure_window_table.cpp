// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// AUTH-10 (security-audit-report-2026-09-29.md): the failed-login map must be
// bounded, keyed by a fixed-size identity, and expired from a time-ordered queue
// rather than scanned in full on every failure.

#include "merovingian/auth/failure_window_table.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include <sodium.h>

namespace
{

using merovingian::auth::FailureKey;
using merovingian::auth::FailureWindowTable;
using Clock = FailureWindowTable::Clock;

constexpr auto window = std::chrono::minutes{15};
constexpr auto threshold = std::uint32_t{5U};

[[nodiscard]] auto key_for(std::string const& account, std::string const& source = "198.51.100.1") -> FailureKey
{
    auto const key = merovingian::auth::make_failure_key("source", account, source);
    REQUIRE(key.has_value());
    return *key;
}

[[nodiscard]] auto start_of_time() -> Clock::time_point
{
    return Clock::time_point{} + std::chrono::hours{1};
}

} // namespace

SCENARIO("A hundred thousand failed logins for distinct accounts never grow the table past its cap",
         "[auth][login-throttle][auth-10]")
{
    GIVEN("a table with the default capacity")
    {
        REQUIRE(sodium_init() >= 0);
        auto table = FailureWindowTable{};
        auto const now = start_of_time();

        WHEN("one failure is recorded for each of 100000 distinct user IDs, plus ten more")
        {
            auto largest = std::size_t{0U};
            for (auto i = 0U; i < merovingian::auth::max_failure_window_entries + 10U; ++i)
            {
                table.record_failure(key_for("@user" + std::to_string(i) + ":example.org"),
                                     now + std::chrono::milliseconds{i}, window, threshold);
                largest = std::max(largest, table.size());
            }

            THEN("the table never held more entries than its cap")
            {
                REQUIRE(table.capacity() == merovingian::auth::max_failure_window_entries);
                REQUIRE(largest == merovingian::auth::max_failure_window_entries);
                REQUIRE(table.size() == merovingian::auth::max_failure_window_entries);
            }

            THEN("the oldest entries were evicted and the newest are still counted")
            {
                auto const after = now + std::chrono::minutes{1};
                REQUIRE(table.failures(key_for("@user0:example.org"), after, window) == 0U);
                REQUIRE(table.failures(key_for("@user9:example.org"), after, window) == 0U);
                REQUIRE(table.failures(key_for("@user10:example.org"), after, window) == 1U);
                REQUIRE(table.failures(key_for("@user100009:example.org"), after, window) == 1U);
            }
        }
    }

    GIVEN("a table with a capacity of three")
    {
        REQUIRE(sodium_init() >= 0);
        auto table = FailureWindowTable{3U};
        auto const now = start_of_time();

        WHEN("a fourth distinct key fails")
        {
            table.record_failure(key_for("a"), now, window, threshold);
            table.record_failure(key_for("b"), now + std::chrono::seconds{1}, window, threshold);
            table.record_failure(key_for("c"), now + std::chrono::seconds{2}, window, threshold);
            table.record_failure(key_for("d"), now + std::chrono::seconds{3}, window, threshold);

            THEN("the oldest entry is evicted and the other three remain")
            {
                auto const later = now + std::chrono::seconds{10};
                REQUIRE(table.size() == 3U);
                REQUIRE(table.failures(key_for("a"), later, window) == 0U);
                REQUIRE(table.failures(key_for("b"), later, window) == 1U);
                REQUIRE(table.failures(key_for("c"), later, window) == 1U);
                REQUIRE(table.failures(key_for("d"), later, window) == 1U);
            }
        }
    }
}

SCENARIO("A failure whose window has elapsed no longer counts and is dropped without a scan",
         "[auth][login-throttle][auth-10]")
{
    GIVEN("a table holding a refused key and an unrelated key")
    {
        REQUIRE(sodium_init() >= 0);
        auto table = FailureWindowTable{};
        auto const now = start_of_time();
        auto const victim = key_for("@alice:example.org");
        for (auto i = 0U; i < threshold; ++i)
        {
            table.record_failure(victim, now, window, threshold);
        }
        table.record_failure(key_for("@bob:example.org"), now + std::chrono::minutes{1}, window, threshold);
        REQUIRE(table.lockout_remaining(victim, now + std::chrono::minutes{1}, window, threshold) >
                Clock::duration::zero());

        WHEN("the window passes")
        {
            auto const later = now + window + std::chrono::seconds{1};

            THEN("the key is no longer refused and no longer counts")
            {
                REQUIRE(table.lockout_remaining(victim, later, window, threshold) == Clock::duration::zero());
                REQUIRE(table.failures(victim, later, window) == 0U);
            }

            THEN("a new failure after the window starts a fresh count")
            {
                table.record_failure(victim, later, window, threshold);
                REQUIRE(table.failures(victim, later, window) == 1U);
                REQUIRE(table.lockout_remaining(victim, later, window, threshold) == Clock::duration::zero());
            }

            THEN("expired entries leave the table when any key is next touched")
            {
                table.record_failure(key_for("@carol:example.org"), later + window, window, threshold);
                REQUIRE(table.size() == 1U);
            }
        }
    }
}

SCENARIO("A key is refused from the failure that reaches the threshold for one full window",
         "[auth][login-throttle][auth-2]")
{
    GIVEN("a key with one failure short of the threshold")
    {
        REQUIRE(sodium_init() >= 0);
        auto table = FailureWindowTable{};
        auto const now = start_of_time();
        auto const key = key_for("@alice:example.org");
        for (auto i = 0U; i + 1U < threshold; ++i)
        {
            table.record_failure(key, now + std::chrono::seconds{i}, window, threshold);
        }

        THEN("it is not refused")
        {
            REQUIRE(table.lockout_remaining(key, now + std::chrono::seconds{10}, window, threshold) ==
                    Clock::duration::zero());
        }

        WHEN("the threshold failure arrives ten minutes after the first")
        {
            auto const tripped_at = now + std::chrono::minutes{10};
            table.record_failure(key, tripped_at, window, threshold);

            THEN("it is refused for a full window from that failure, not from the first")
            {
                REQUIRE(table.lockout_remaining(key, tripped_at, window, threshold) == window);
                REQUIRE(table.lockout_remaining(key, tripped_at + std::chrono::minutes{14}, window, threshold) ==
                        std::chrono::minutes{1});
                REQUIRE(table.lockout_remaining(key, tripped_at + window, window, threshold) ==
                        Clock::duration::zero());
            }
        }

        WHEN("a failure for a different key arrives, and then the key is cleared")
        {
            table.record_failure(key_for("@bob:example.org"), now, window, threshold);
            table.clear(key);

            THEN("only the cleared key is forgotten")
            {
                REQUIRE(table.failures(key, now, window) == 0U);
                REQUIRE(table.failures(key_for("@bob:example.org"), now, window) == 1U);
            }
        }
    }
}

SCENARIO("Failure keys are fixed size and cannot be made to collide by choosing the name",
         "[auth][login-throttle][auth-10]")
{
    GIVEN("keys built from very different account lengths")
    {
        REQUIRE(sodium_init() >= 0);
        auto const short_key = merovingian::auth::make_failure_key("source", "a", "198.51.100.1");
        auto const long_key =
            merovingian::auth::make_failure_key("source", std::string(60U * 1024U, 'u'), "198.51.100.1");

        THEN("both keys have the same fixed size")
        {
            REQUIRE(short_key.has_value());
            REQUIRE(long_key.has_value());
            REQUIRE(sizeof(short_key->digest) == sizeof(long_key->digest));
            REQUIRE(*short_key != *long_key);
        }
    }

    GIVEN("two (account, qualifier) pairs that concatenate to the same text")
    {
        REQUIRE(sodium_init() >= 0);
        auto const first = merovingian::auth::make_failure_key("source", "ab", "c");
        auto const second = merovingian::auth::make_failure_key("source", "a", "bc");
        auto const embedded_nul = merovingian::auth::make_failure_key("source", std::string{"a\0b", 3U}, "c");
        auto const split_at_nul = merovingian::auth::make_failure_key("source", "a", std::string{"b\0c", 3U});

        THEN("their keys differ")
        {
            REQUIRE(*first != *second);
            REQUIRE(*embedded_nul != *split_at_nul);
        }
    }

    GIVEN("the same account counted under two different kinds")
    {
        REQUIRE(sodium_init() >= 0);
        auto const login = merovingian::auth::make_failure_key("source", "@alice:example.org", "device");
        auto const uia = merovingian::auth::make_failure_key("uia", "@alice:example.org", "device");

        THEN("their keys differ, so one kind never feeds another's counter")
        {
            REQUIRE(*login != *uia);
        }
    }
}
