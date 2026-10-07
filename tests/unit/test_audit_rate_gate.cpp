// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// AUTH-1 (security-audit-report-2026-09-29.md): unauthenticated per-request
// rejections must not write one durable audit row per request. The gate admits
// a fixed number of rows per audit event kind per window and counts the rest,
// so the next admitted row can report how many were dropped.

#include "merovingian/observability/audit_rate_gate.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <tuple>

namespace
{

using merovingian::observability::AuditRateGate;
using Clock = AuditRateGate::Clock;

[[nodiscard]] auto count_admitted(AuditRateGate& gate, std::string const& kind, Clock::time_point now, int attempts)
    -> int
{
    auto admitted = 0;
    for (auto i = 0; i < attempts; ++i)
    {
        if (gate.admit(kind, now).write)
        {
            ++admitted;
        }
    }
    return admitted;
}

} // namespace

SCENARIO("The audit rate gate admits at most ten rows per kind per window", "[observability][audit][rate-gate]")
{
    GIVEN("a fresh gate")
    {
        auto gate = AuditRateGate{};
        auto const start = Clock::time_point{} + std::chrono::hours{1};

        WHEN("a thousand access-token rejections arrive inside one window")
        {
            auto const admitted = count_admitted(gate, "access_token.rejected", start, 1000);

            THEN("exactly the per-window allowance is admitted")
            {
                REQUIRE(admitted == static_cast<int>(merovingian::observability::audit_rate_gate_max_rows));
                REQUIRE(admitted == 10);
            }
        }

        WHEN("two different rate-capped kinds arrive in the same window")
        {
            auto const tokens = count_admitted(gate, "access_token.rejected", start, 100);
            auto const limits = count_admitted(gate, "rate_limit.exceeded", start, 100);

            THEN("each kind has its own allowance")
            {
                REQUIRE(tokens == 10);
                REQUIRE(limits == 10);
            }
        }
    }
}

SCENARIO("The audit rate gate reports how many rows a window suppressed on the next admitted row",
         "[observability][audit][rate-gate]")
{
    GIVEN("a gate whose first window suppressed 90 events")
    {
        auto gate = AuditRateGate{};
        auto const start = Clock::time_point{} + std::chrono::hours{1};
        REQUIRE(count_admitted(gate, "rate_limit.exceeded", start, 100) == 10);

        WHEN("the window has not yet elapsed")
        {
            auto const inside = gate.admit("rate_limit.exceeded", start + std::chrono::seconds{59});

            THEN("the event is still suppressed")
            {
                REQUIRE_FALSE(inside.write);
            }
        }

        WHEN("the next event arrives after the window")
        {
            auto const after = gate.admit("rate_limit.exceeded", start + std::chrono::seconds{60});
            auto const following = gate.admit("rate_limit.exceeded", start + std::chrono::seconds{61});

            THEN("that row is admitted and carries the suppressed count, and the count is reported once")
            {
                REQUIRE(after.write);
                REQUIRE(after.suppressed == 90U);
                REQUIRE(following.write);
                REQUIRE(following.suppressed == 0U);
            }
        }
    }
}

SCENARIO("The audit rate gate never limits audit events that are not per-request rejections",
         "[observability][audit][rate-gate]")
{
    GIVEN("a gate and event kinds outside the capped set")
    {
        auto gate = AuditRateGate{};
        auto const start = Clock::time_point{} + std::chrono::hours{1};

        WHEN("a thousand login successes and admin actions arrive")
        {
            auto const logins = count_admitted(gate, "auth.login", start, 1000);
            auto const admin = count_admitted(gate, "admin.action", start, 1000);

            THEN("every one is admitted with nothing suppressed")
            {
                REQUIRE(logins == 1000);
                REQUIRE(admin == 1000);
                REQUIRE(gate.admit("auth.login", start).suppressed == 0U);
            }
        }
    }

    GIVEN("the capped-kind predicate")
    {
        THEN("it names exactly the unauthenticated per-request rejections")
        {
            REQUIRE(merovingian::observability::audit_event_is_rate_capped("access_token.rejected"));
            REQUIRE(merovingian::observability::audit_event_is_rate_capped("rate_limit.exceeded"));
            REQUIRE(merovingian::observability::audit_event_is_rate_capped("request.rejected"));
            REQUIRE(merovingian::observability::audit_event_is_rate_capped("login.rejected"));
            REQUIRE(merovingian::observability::audit_event_is_rate_capped("login.throttled"));
            REQUIRE_FALSE(merovingian::observability::audit_event_is_rate_capped("auth.login"));
            REQUIRE_FALSE(merovingian::observability::audit_event_is_rate_capped("auth.logout"));
            REQUIRE_FALSE(merovingian::observability::audit_event_is_rate_capped(""));
        }
    }
}

SCENARIO("The audit rate gate tracks state only for the fixed set of capped kinds",
         "[observability][audit][rate-gate][bounded]")
{
    GIVEN("a gate offered many distinct, attacker-chosen kind strings")
    {
        auto gate = AuditRateGate{};
        auto const start = Clock::time_point{} + std::chrono::hours{1};

        WHEN("ten thousand unknown kinds are offered")
        {
            for (auto i = 0; i < 10000; ++i)
            {
                REQUIRE(gate.admit("attacker.kind." + std::to_string(i), start).write);
            }

            THEN("no per-kind state accumulates")
            {
                REQUIRE(gate.tracked_kinds() == 0U);
            }
        }
    }
}

SCENARIO("The audit rate gate follows an injected clock", "[observability][audit][rate-gate]")
{
    GIVEN("a gate using a controllable clock")
    {
        auto now = Clock::time_point{} + std::chrono::hours{1};
        auto gate = AuditRateGate{};
        gate.set_clock([&now]() {
            return now;
        });

        WHEN("the allowance is spent and the clock then advances past the window")
        {
            for (auto i = 0; i < 25; ++i)
            {
                std::ignore = gate.admit("request.rejected");
            }
            now += merovingian::observability::audit_rate_gate_window;
            auto const decision = gate.admit("request.rejected");

            THEN("the first row of the new window carries the 15 suppressed events")
            {
                REQUIRE(decision.write);
                REQUIRE(decision.suppressed == 15U);
            }
        }
    }
}
