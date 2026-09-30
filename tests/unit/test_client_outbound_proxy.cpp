// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// HTTP-2 / OUT-7 / ADR-0079: the policy, deadline and admission helpers that
// bound client-triggered outbound proxying. Tags: [http-2][out-7][homeserver].

#include "../support/master_key.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_outbound_proxy.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace merovingian::homeserver;

SCENARIO("The client outbound proxy caps are derived from the main request pool size", "[http-2][out-7][homeserver]")
{
    GIVEN("the shipped pool size")
    {
        auto const policy = default_client_outbound_proxy_policy();

        THEN("the global cap is half the default pool of sixteen and each client may hold one call")
        {
            // HTTP-1 made the pool configurable (server.http.request_threads,
            // default 16); the default policy follows the default pool.
            REQUIRE(default_main_request_pool_threads == 16U);
            REQUIRE(policy.global_cap == default_main_request_pool_threads / 2U);
            REQUIRE(policy.global_cap == 8U);
            REQUIRE(policy.per_client_cap == 1U);
        }

        THEN("directory lookups get at most ten seconds and remote media at most thirty")
        {
            REQUIRE(policy.directory_deadline_seconds <= 10U);
            REQUIRE(policy.media_deadline_seconds <= 30U);
        }

        THEN("a refused caller is told to retry in one second")
        {
            REQUIRE(policy.retry_after_ms == 1000U);
        }
    }

    GIVEN("a different pool size")
    {
        THEN("the global cap follows it and is never zero")
        {
            REQUIRE(client_outbound_proxy_policy_for_pool(32U).global_cap == 16U);
            REQUIRE(client_outbound_proxy_policy_for_pool(1U).global_cap == 1U);
            REQUIRE(client_outbound_proxy_policy_for_pool(0U).global_cap == 1U);
        }
    }
}

SCENARIO("A runtime starts with the default client outbound proxy policy and an empty budget",
         "[http-2][out-7][homeserver]")
{
    GIVEN("a fresh runtime")
    {
        auto runtime = HomeserverRuntime{};

        THEN("the policy is the default and nothing is in flight")
        {
            REQUIRE(runtime.client_outbound_proxy_policy.global_cap ==
                    default_client_outbound_proxy_policy().global_cap);
            REQUIRE(runtime.client_outbound_budget != nullptr);
            REQUIRE(runtime.client_outbound_budget->active() == 0U);
        }
    }
}

SCENARIO("Admission to client outbound proxying honours the runtime policy", "[http-2][out-7][homeserver]")
{
    GIVEN("a runtime with the default policy")
    {
        auto runtime = HomeserverRuntime{};

        WHEN("one client holds a slot")
        {
            auto const held = admit_client_outbound_proxy(runtime, "192.0.2.1");
            REQUIRE(held.has_value());

            THEN("the same client is refused and another is admitted")
            {
                REQUIRE_FALSE(admit_client_outbound_proxy(runtime, "192.0.2.1").has_value());
                REQUIRE(admit_client_outbound_proxy(runtime, "192.0.2.2").has_value());
            }
        }

        WHEN("as many different clients as the global cap hold slots")
        {
            auto held = std::vector<std::optional<merovingian::http::InFlightBudget::Slot>>{};
            auto all_admitted = true;
            for (auto index = 0U; index < runtime.client_outbound_proxy_policy.global_cap; ++index)
            {
                held.push_back(admit_client_outbound_proxy(runtime, "192.0.2." + std::to_string(index + 1U)));
                all_admitted = all_admitted && held.back().has_value();
            }
            REQUIRE(all_admitted);

            THEN("one more client is refused")
            {
                REQUIRE_FALSE(admit_client_outbound_proxy(runtime, "198.51.100.1").has_value());
            }
        }
    }

    GIVEN("a runtime whose policy is lowered after start")
    {
        auto runtime = HomeserverRuntime{};
        runtime.client_outbound_proxy_policy.global_cap = 1U;

        THEN("the lowered cap applies to the next admission")
        {
            auto const first = admit_client_outbound_proxy(runtime, "192.0.2.1");
            REQUIRE(first.has_value());
            REQUIRE_FALSE(admit_client_outbound_proxy(runtime, "192.0.2.2").has_value());
        }
    }
}

SCENARIO("A client outbound deadline only ever shortens the configured remote timeout", "[http-2][out-7][homeserver]")
{
    GIVEN("a runtime")
    {
        auto runtime = HomeserverRuntime{};

        WHEN("the operator's remote timeout is the shipped 60 seconds")
        {
            runtime.federation.config.remote_timeout_seconds = 60U;

            THEN("the short deadline wins")
            {
                REQUIRE(effective_client_outbound_deadline(runtime, 10U) == 10U);
                REQUIRE(effective_client_outbound_deadline(runtime, 30U) == 30U);
            }
        }

        WHEN("the operator configured a remote timeout shorter than the policy deadline")
        {
            runtime.federation.config.remote_timeout_seconds = 5U;

            THEN("the operator's value wins")
            {
                REQUIRE(effective_client_outbound_deadline(runtime, 10U) == 5U);
            }
        }

        WHEN("no remote timeout is configured")
        {
            runtime.federation.config.remote_timeout_seconds = 0U;

            THEN("the policy deadline is used unchanged")
            {
                REQUIRE(effective_client_outbound_deadline(runtime, 10U) == 10U);
            }
        }
    }
}

SCENARIO("An outbound deadline reports the time left and when it has passed", "[http-2][out-7][homeserver]")
{
    GIVEN("a ten second deadline")
    {
        auto const deadline = OutboundDeadline{10U};

        THEN("it has not expired and at most ten seconds remain, rounded up")
        {
            REQUIRE_FALSE(deadline.expired());
            REQUIRE(deadline.remaining_seconds() >= 9U);
            REQUIRE(deadline.remaining_seconds() <= 10U);
        }
    }

    GIVEN("a deadline of zero seconds")
    {
        auto const deadline = OutboundDeadline{0U};

        THEN("it is already expired with nothing left")
        {
            REQUIRE(deadline.expired());
            REQUIRE(deadline.remaining_seconds() == 0U);
        }
    }

    GIVEN("a one second deadline that has been partly used")
    {
        auto const deadline = OutboundDeadline{1U};
        std::this_thread::sleep_for(std::chrono::milliseconds{50});

        THEN("the sub-second remainder still rounds up to one second")
        {
            REQUIRE(deadline.remaining_seconds() == 1U);
        }
    }
}

SCENARIO("A runtime started from configuration derives its outbound caps from the configured pool size",
         "[http-1][http-2][homeserver]")
{
    GIVEN("a configuration with a main request pool of thirty-two threads")
    {
        auto config = merovingian::config::Config{};
        config.server().http.request_threads = 32U;
        config.security().secrets.master_key_file = merovingian::tests::shared_master_key_file();

        WHEN("the runtime starts")
        {
            auto const started = start_runtime(config);

            THEN("the global outbound cap is half the configured pool")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.client_outbound_proxy_policy.global_cap == 16U);
            }
        }
    }
}
