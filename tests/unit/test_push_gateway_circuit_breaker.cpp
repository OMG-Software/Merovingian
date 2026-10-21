// SPDX-License-Identifier: GPL-3.0-or-later

// OUT-3 (29 Sep 2026 audit): a push gateway host that keeps failing is skipped
// for a cooldown, so its stalled requests stop occupying delivery capacity.

#include "merovingian/push/gateway_circuit_breaker.hpp"
#include "merovingian/push/push_gateway_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <string_view>

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

SCENARIO("only a gateway that could not be reached counts toward opening its circuit", "[push][out3]")
{
    // PR #509 review: a 5xx (or 429) is the gateway answering about one
    // notification. Counting it let one user's bad pusher open the circuit of a
    // shared gateway for every user of that host.
    using merovingian::http::OutboundError;
    using merovingian::push::GatewayCircuitOutcome;
    using merovingian::push::PushGatewayResult;

    GIVEN("delivery results")
    {
        auto const answered = [](std::uint16_t status) {
            auto result = PushGatewayResult{};
            result.ok = true;
            result.status = status;
            result.error = OutboundError::none;
            return merovingian::push::gateway_circuit_outcome(result);
        };
        auto const failed = [](OutboundError error) {
            auto result = PushGatewayResult{};
            result.error = error;
            return merovingian::push::gateway_circuit_outcome(result);
        };

        WHEN("they are classified")
        {
            THEN("any HTTP answer is reachable, a transport failure is a failure, and a refusal is neither")
            {
                for (auto const status : {200U, 400U, 404U, 429U, 500U, 502U, 503U})
                {
                    INFO(status);
                    CHECK(answered(static_cast<std::uint16_t>(status)) == GatewayCircuitOutcome::reachable);
                }
                for (auto const error :
                     {OutboundError::unresolved_host, OutboundError::connection_failed,
                      OutboundError::tls_verification_failed, OutboundError::timeout, OutboundError::network_error})
                {
                    CHECK(failed(error) == GatewayCircuitOutcome::transport_failure);
                }
                for (auto const error :
                     {OutboundError::invalid_url, OutboundError::https_required, OutboundError::redirect_rejected,
                      OutboundError::response_too_large, OutboundError::invalid_header})
                {
                    CHECK(failed(error) == GatewayCircuitOutcome::not_attempted);
                }
                auto disabled = PushGatewayResult{};
                disabled.disabled = true;
                disabled.error = OutboundError::none;
                CHECK(merovingian::push::gateway_circuit_outcome(disabled) == GatewayCircuitOutcome::not_attempted);
            }
        }
    }
}

SCENARIO("a gateway's circuit is keyed by its case-folded host and port", "[push][out3]")
{
    // PR #509 review: case and trailing-dot variants of one host had separate
    // circuits (a way round the breaker), and different ports shared one.
    GIVEN("gateway URLs naming one host in different spellings, and another port")
    {
        auto const host = [](std::string_view url) {
            return merovingian::push::push_gateway_host(url).value_or("<none>");
        };

        WHEN("their circuit keys are computed")
        {
            THEN("spellings of one host and port share a key, and ports do not")
            {
                CHECK(host("https://push.example.org/_matrix/push/v1/notify") == "push.example.org:443");
                CHECK(host("https://PUSH.Example.ORG/_matrix/push/v1/notify") == "push.example.org:443");
                CHECK(host("https://push.example.org./_matrix/push/v1/notify") == "push.example.org:443");
                CHECK(host("https://push.example.org:443/_matrix/push/v1/notify") == "push.example.org:443");
                CHECK(host("https://push.example.org:8443/_matrix/push/v1/notify") == "push.example.org:8443");
                CHECK(host("not a url") == "<none>");
            }
        }
    }
}

SCENARIO("only a pusher whose own pushkey the gateway rejects is rejected", "[push][out3]")
{
    GIVEN("a gateway answer that rejects one pushkey")
    {
        auto result = merovingian::push::PushGatewayResult{};
        result.ok = true;
        result.status = 200U;
        result.rejected_pushkeys = {"rejected-key"};

        WHEN("pushers are checked against it")
        {
            THEN("the listed pushkey is rejected and any other is not")
            {
                CHECK(merovingian::push::pushkey_was_rejected(result, "rejected-key"));
                CHECK_FALSE(merovingian::push::pushkey_was_rejected(result, "other-key"));
                auto failed = result;
                failed.ok = false;
                CHECK_FALSE(merovingian::push::pushkey_was_rejected(failed, "rejected-key"));
            }
        }
    }
}
