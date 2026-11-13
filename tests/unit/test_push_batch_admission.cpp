// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/GatewayCircuitBreaker.hpp"
#include "merovingian/push/GatewayCircuitBreakerPolicy.hpp"
#include "merovingian/push/GatewayInFlightLimiter.hpp"
#include "merovingian/push/PushBatchAdmission.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{

using merovingian::push::GatewayCircuitBreaker;
using merovingian::push::GatewayCircuitBreakerPolicy;
using merovingian::push::GatewayInFlightLimiter;
using merovingian::push::PushBatchAdmission;
using merovingian::push::PushBatchRefusal;

// Starts batches the way dispatch_push_deliveries does: counts those admitted and holds their slots.
struct Dispatcher final
{
    PushBatchAdmission admission{};
    std::size_t max_in_flight{256U};
    std::size_t in_flight{0U};
    std::vector<std::optional<GatewayInFlightLimiter::Slot>> running{};

    auto start(std::vector<std::string> const& hosts, bool reachable) -> PushBatchRefusal
    {
        auto outcome = admission.admit(in_flight, max_in_flight, hosts, reachable);
        if (outcome.slot.has_value())
        {
            ++in_flight;
            running.push_back(std::move(outcome.slot));
        }
        return outcome.refusal;
    }
};

} // namespace

SCENARIO("Gateways the sender chose cannot hold every slot of the push delivery budget",
         "[push][push-slots][gate-l]")
{
    GIVEN("a budget of 256 and an attacker who mints a gateway host name for every wave")
    {
        auto dispatcher = Dispatcher{};

        WHEN("33 accounts start batches on 8 fresh host names, each name carrying every batch it can")
        {
            auto admitted = std::size_t{0U};
            for (auto host = 0; host < 8; ++host)
            {
                for (auto account = 0; account < 33; ++account)
                {
                    admitted +=
                        dispatcher.start({"attacker" + std::to_string(host) + ".example"}, false) ==
                                PushBatchRefusal::none
                            ? 1U
                            : 0U;
                }
            }

            THEN("a host carries an eighth of the budget and the unproven batches stop at the unreserved share")
            {
                CHECK(admitted == 6U * 32U);
                CHECK(dispatcher.in_flight == 192U);
            }
        }

        WHEN("33 accounts start batches on 7 fresh host names, then a reachable and a fresh gateway ask")
        {
            for (auto host = 0; host < 7; ++host)
            {
                for (auto account = 0; account < 33; ++account)
                {
                    std::ignore = dispatcher.start({"attacker" + std::to_string(host) + ".example"}, false);
                }
            }

            THEN("the unproven batches are held to three quarters, and only the reachable gateway gets a slot")
            {
                CHECK(dispatcher.in_flight == 192U);
                CHECK(dispatcher.start({"sygnal.example"}, true) == PushBatchRefusal::none);
                CHECK(dispatcher.start({"fresh.example"}, false) == PushBatchRefusal::unproven_share);
            }
        }

        WHEN("the whole budget is in flight")
        {
            for (auto index = 0; index < 256; ++index)
            {
                REQUIRE(dispatcher.start({"gateway" + std::to_string(index) + ".example"}, true) ==
                        PushBatchRefusal::none);
            }

            THEN("even a reachable gateway is refused")
            {
                CHECK(dispatcher.start({"sygnal.example"}, true) == PushBatchRefusal::global_cap);
            }
        }

        WHEN("one host carries 32 batches")
        {
            for (auto index = 0; index < 32; ++index)
            {
                REQUIRE(dispatcher.start({"sygnal.example"}, true) == PushBatchRefusal::none);
            }

            THEN("its 33rd is refused for the host, another host is not, and a finished batch frees a place")
            {
                CHECK(dispatcher.start({"sygnal.example"}, true) == PushBatchRefusal::gateway_host);
                CHECK(dispatcher.start({"other.example"}, true) == PushBatchRefusal::none);
                CHECK(dispatcher.admission.host_in_flight("sygnal.example") == 32U);
                dispatcher.running.erase(dispatcher.running.begin());
                --dispatcher.in_flight;
                CHECK(dispatcher.admission.host_in_flight("sygnal.example") == 31U);
                CHECK(dispatcher.start({"sygnal.example"}, true) == PushBatchRefusal::none);
            }
        }
    }
}

SCENARIO("The budget's caps follow its size", "[push][push-slots][gate-l]")
{
    GIVEN("budgets of 1, 3, 4, 8 and 256")
    {
        THEN("a quarter is kept for reachable gateways from 4 up, and a host always may carry one batch")
        {
            CHECK(PushBatchAdmission::global_cap(1U, false) == 1U);
            CHECK(PushBatchAdmission::global_cap(3U, false) == 3U);
            CHECK(PushBatchAdmission::global_cap(4U, false) == 3U);
            CHECK(PushBatchAdmission::global_cap(8U, false) == 6U);
            CHECK(PushBatchAdmission::global_cap(256U, false) == 192U);
            CHECK(PushBatchAdmission::global_cap(256U, true) == 256U);
            CHECK(PushBatchAdmission::host_cap(1U) == 1U);
            CHECK(PushBatchAdmission::host_cap(7U) == 2U);
            CHECK(PushBatchAdmission::host_cap(256U) == 32U);
        }
    }
}

SCENARIO("A gateway host is reachable only after a prompt answer and until it fails or answers slowly",
         "[push][push-slots][gate-l]")
{
    GIVEN("a circuit breaker that has recorded one prompt answer")
    {
        auto breaker = GatewayCircuitBreaker{};
        auto const policy = GatewayCircuitBreakerPolicy{};
        auto const now = std::chrono::steady_clock::now();
        REQUIRE_FALSE(breaker.reachable_recently("sygnal.example", now, policy));
        breaker.record("sygnal.example", true, now, policy);

        WHEN("it is asked within the lifetime of that answer")
        {
            THEN("the host is reachable, and an unseen one is not")
            {
                CHECK(breaker.reachable_recently("sygnal.example", now + std::chrono::minutes{59}, policy));
                CHECK_FALSE(breaker.reachable_recently("sygnal.example", now + std::chrono::minutes{61}, policy));
                CHECK_FALSE(breaker.reachable_recently("never.example", now, policy));
            }
        }

        WHEN("the host then fails or answers slowly")
        {
            breaker.record("sygnal.example", false, now + std::chrono::seconds{1}, policy);

            THEN("it is no longer reachable")
            {
                CHECK_FALSE(breaker.reachable_recently("sygnal.example", now + std::chrono::seconds{2}, policy));
            }
        }
    }

    GIVEN("a breaker that remembers at most 4 reachable hosts")
    {
        auto breaker = GatewayCircuitBreaker{};
        auto policy = GatewayCircuitBreakerPolicy{};
        policy.max_hosts = 4U;
        auto const now = std::chrono::steady_clock::now();

        WHEN("ten hosts answer in turn")
        {
            for (auto index = 0; index < 10; ++index)
            {
                breaker.record("host" + std::to_string(index) + ".example", true, now + std::chrono::seconds{index},
                               policy);
            }

            THEN("the newest are remembered and the oldest forgotten")
            {
                CHECK(breaker.reachable_recently("host9.example", now + std::chrono::seconds{10}, policy));
                CHECK_FALSE(breaker.reachable_recently("host0.example", now + std::chrono::seconds{10}, policy));
            }
        }
    }
}

// C48 (ADR-0721): hosts that answer just inside the old "prompt" threshold must not hold the reserve for hosts that
// answer promptly.
SCENARIO("A gateway host that answers slowly does not keep the delivery reserve", "[push][push-slots][c48]")
{
    GIVEN("a budget of 256 with the unreserved three quarters in flight")
    {
        auto dispatcher = Dispatcher{};
        for (auto host = 0; host < 6; ++host)
        {
            for (auto batch = 0; batch < 32; ++batch)
            {
                REQUIRE(dispatcher.start({"busy" + std::to_string(host) + ".example"}, true) == PushBatchRefusal::none);
            }
        }
        REQUIRE(dispatcher.in_flight == 192U);

        WHEN("one host that was reachable asks for the reserve 33 times")
        {
            auto admitted = std::size_t{0U};
            auto last = PushBatchRefusal::none;
            for (auto batch = 0; batch < 33; ++batch)
            {
                last = dispatcher.start({"burst.example"}, true);
                admitted += last == PushBatchRefusal::none ? 1U : 0U;
            }

            THEN("it gets a quarter of its usual share, and a different reachable host is still admitted")
            {
                CHECK(PushBatchAdmission::reserve_host_cap(256U) == 8U);
                CHECK(admitted == 8U);
                CHECK(last == PushBatchRefusal::gateway_host);
                CHECK(dispatcher.start({"other.example"}, true) == PushBatchRefusal::none);
            }
        }

        WHEN("a small budget is used")
        {
            THEN("the reserve cap is never below one")
            {
                CHECK(PushBatchAdmission::reserve_host_cap(4U) == 1U);
                CHECK(PushBatchAdmission::reserve_host_cap(256U) == 8U);
            }
        }
    }
}
