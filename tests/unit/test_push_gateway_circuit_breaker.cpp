// SPDX-License-Identifier: GPL-3.0-or-later

// OUT-3 (29 Sep 2026 audit): a push gateway host that keeps failing is skipped
// for a cooldown, so its stalled requests stop occupying delivery capacity.

#include "merovingian/push/gateway_circuit_breaker.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

namespace
{

using merovingian::push::GatewayCircuitBreaker;
using merovingian::push::GatewayCircuitBreakerPolicy;
using namespace std::chrono_literals;

constexpr auto policy = GatewayCircuitBreakerPolicy{3U, 300s, 4U};

auto fail(GatewayCircuitBreaker& breaker, std::string const& host, std::chrono::steady_clock::time_point now, int times)
    -> void
{
    for (auto i = 0; i < times; ++i)
    {
        breaker.record(host, false, now, policy);
    }
}

} // namespace

SCENARIO("a gateway host opens after consecutive failures and reopens for one probe after the cooldown", "[push][out3]")
{
    GIVEN("a breaker with a threshold of 3 and a 300 s cooldown")
    {
        auto breaker = GatewayCircuitBreaker{};
        auto const start = std::chrono::steady_clock::time_point{} + 1000s;

        WHEN("a host fails twice")
        {
            fail(breaker, "gw.example", start, 2);

            THEN("it is still allowed")
            {
                CHECK(breaker.allow("gw.example", start, policy));
            }
        }

        WHEN("a host fails three times in a row")
        {
            fail(breaker, "gw.example", start, 3);

            THEN("it is skipped until the cooldown ends, then one probe is allowed")
            {
                CHECK_FALSE(breaker.allow("gw.example", start, policy));
                CHECK_FALSE(breaker.allow("gw.example", start + 299s, policy));
                CHECK(breaker.allow("gw.example", start + 300s, policy));
                CHECK_FALSE(breaker.allow("gw.example", start + 300s, policy));
            }

            THEN("other hosts are unaffected")
            {
                CHECK(breaker.allow("other.example", start, policy));
            }
        }

        WHEN("the probe after the cooldown fails")
        {
            fail(breaker, "gw.example", start, 3);
            REQUIRE(breaker.allow("gw.example", start + 300s, policy));
            breaker.record("gw.example", false, start + 300s, policy);

            THEN("the host is skipped for another full cooldown")
            {
                CHECK_FALSE(breaker.allow("gw.example", start + 599s, policy));
                CHECK(breaker.allow("gw.example", start + 600s, policy));
            }
        }

        WHEN("the probe after the cooldown succeeds")
        {
            fail(breaker, "gw.example", start, 3);
            REQUIRE(breaker.allow("gw.example", start + 300s, policy));
            breaker.record("gw.example", true, start + 300s, policy);
            fail(breaker, "gw.example", start + 301s, 2);

            THEN("the circuit is closed and the failure count started again")
            {
                CHECK(breaker.allow("gw.example", start + 301s, policy));
                CHECK(breaker.allow("gw.example", start + 301s, policy));
            }
        }

        WHEN("a success comes between failures")
        {
            fail(breaker, "gw.example", start, 2);
            breaker.record("gw.example", true, start, policy);
            fail(breaker, "gw.example", start, 2);

            THEN("the failures are not consecutive and the host stays allowed")
            {
                CHECK(breaker.allow("gw.example", start, policy));
            }
        }

        WHEN("more hosts fail than the breaker tracks")
        {
            for (auto i = 0; i < 10; ++i)
            {
                fail(breaker, "host-" + std::to_string(i) + ".example", start + std::chrono::seconds{i}, 1);
            }

            THEN("it tracks no more than its bound")
            {
                CHECK(breaker.tracked_hosts() <= 4U);
            }
        }
    }
}
