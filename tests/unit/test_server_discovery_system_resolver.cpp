// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/joining_threads.hpp"
#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <barrier>
#include <string>
#include <tuple>

// ADR-0355. Delivery threads discover different destinations at the same time. NetBSD's res_query
// shares one state between threads, and there two overlapping lookups could leave one thread blocked
// reading a socket another is closing, with neither returning. A hang here is a meson timeout. The
// answers are not asserted: `.invalid` never resolves (RFC 6761), and the machine may have no DNS.
SCENARIO("SRV lookups made at the same time on the system resolver all return",
         "[federation][server_discovery][system_resolver][concurrency]")
{
    GIVEN("sixteen threads released together on one system discovery network")
    {
        auto const network = merovingian::federation::make_system_server_discovery_network();
        auto start = std::barrier{16};
        auto finished = std::atomic<unsigned>{0U};
        auto callers = merovingian::tests::JoiningThreads{};

        WHEN("each looks up its own names")
        {
            for (auto caller = 0U; caller < 16U; ++caller)
            {
                callers.emplace_back([&, caller] {
                    start.arrive_and_wait();
                    for (auto lookup = 0U; lookup < 8U; ++lookup)
                    {
                        std::ignore = network->lookup_srv("_matrix-fed._tcp.caller" + std::to_string(caller) + "-" +
                                                          std::to_string(lookup) + ".invalid");
                    }
                    finished.fetch_add(1U);
                });
            }
            callers.join();

            THEN("every thread comes back")
            {
                REQUIRE(finished.load() == 16U);
            }
        }
    }
}
