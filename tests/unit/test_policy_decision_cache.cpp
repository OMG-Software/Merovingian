// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/trust_safety/PolicyAction.hpp"
#include "merovingian/trust_safety/PolicyDecisionCache.hpp"
#include "merovingian/trust_safety/PolicyServerHook.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using merovingian::trust_safety::PolicyAction;
using merovingian::trust_safety::PolicyDecisionCache;
using merovingian::trust_safety::PolicyServerHook;

[[nodiscard]] auto denied() -> PolicyServerHook
{
    auto hook = PolicyServerHook{};
    hook.enabled = true;
    hook.decision_received = true;
    hook.action = PolicyAction::deny;
    hook.rule_id = "rule-1";
    return hook;
}

} // namespace

SCENARIO("A policy decision is kept for its fresh period and a failure to get one is not kept",
         "[trust-safety][policy-decision-cache][gate-l]")
{
    GIVEN("a cache with a 30 second fresh period")
    {
        auto cache = PolicyDecisionCache{};
        auto const settings = PolicyDecisionCache::Settings{};
        auto const start = std::chrono::steady_clock::now();

        WHEN("the first request for an origin asks and stores a decision")
        {
            auto first = cache.acquire("bad.example", start, settings, std::chrono::milliseconds{0});
            REQUIRE(first.leader.has_value());
            first.leader->publish(denied(), start);

            THEN("a request within the fresh period gets that decision and does not ask")
            {
                auto const again = cache.acquire("bad.example", start + std::chrono::seconds{29}, settings,
                                                 std::chrono::milliseconds{0});
                REQUIRE(again.decision.has_value());
                CHECK(again.decision->action == PolicyAction::deny);
                CHECK(again.decision->rule_id == "rule-1");
                CHECK_FALSE(again.leader.has_value());
            }

            THEN("a request after the fresh period asks again, and the old decision is still usable when no place is left")
            {
                auto const later = cache.acquire("bad.example", start + std::chrono::seconds{31}, settings,
                                                 std::chrono::milliseconds{0});
                CHECK_FALSE(later.decision.has_value());
                CHECK(later.leader.has_value());
                auto const remembered = cache.stale("bad.example", start + std::chrono::seconds{31}, settings);
                REQUIRE(remembered.has_value());
                CHECK(remembered->action == PolicyAction::deny);
                CHECK_FALSE(cache.stale("bad.example", start + std::chrono::minutes{11}, settings).has_value());
                CHECK_FALSE(cache.stale("other.example", start, settings).has_value());
            }
        }

        WHEN("the request that asked gets no decision")
        {
            {
                auto failed = cache.acquire("flaky.example", start, settings, std::chrono::milliseconds{0});
                REQUIRE(failed.leader.has_value());
            }

            THEN("nothing is kept and the next request asks")
            {
                CHECK(cache.size() == 0U);
                auto const next = cache.acquire("flaky.example", start, settings, std::chrono::milliseconds{0});
                CHECK_FALSE(next.decision.has_value());
                CHECK(next.leader.has_value());
            }
        }
    }
}

SCENARIO("Requests for one origin that arrive together cost one ask", "[trust-safety][policy-decision-cache][gate-l]")
{
    GIVEN("one request asking about an origin and four more arriving while it asks")
    {
        auto cache = PolicyDecisionCache{};
        auto const settings = PolicyDecisionCache::Settings{};
        auto const start = std::chrono::steady_clock::now();
        auto leader_claim = cache.acquire("busy.example", start, settings, std::chrono::milliseconds{0});
        REQUIRE(leader_claim.leader.has_value());

        auto arrived = std::atomic<int>{0};
        auto answers = std::vector<std::optional<PolicyServerHook>>(4U);
        auto asked = std::vector<int>(4U, 1);
        auto threads = std::vector<std::thread>{};
        for (auto index = std::size_t{0U}; index < 4U; ++index)
        {
            threads.emplace_back([&, index] {
                arrived.fetch_add(1);
                auto claim = cache.acquire("busy.example", start, settings, std::chrono::seconds{5});
                answers[index] = claim.decision;
                asked[index] = claim.leader.has_value() ? 1 : 0;
            });
        }
        while (arrived.load() < 4)
        {
            std::this_thread::yield();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{50});

        WHEN("the first request stores its decision")
        {
            leader_claim.leader->publish(denied(), start);
            for (auto& thread : threads)
            {
                thread.join();
            }

            THEN("every waiting request gets that decision and none of them asks")
            {
                for (auto index = std::size_t{0U}; index < 4U; ++index)
                {
                    CAPTURE(index);
                    REQUIRE(answers[index].has_value());
                    CHECK(answers[index]->action == PolicyAction::deny);
                    CHECK(asked[index] == 0);
                }
            }
        }

        WHEN("the first request ends without a decision")
        {
            leader_claim.leader.reset();
            for (auto& thread : threads)
            {
                thread.join();
            }

            THEN("the waiting requests have no decision and still do not ask")
            {
                for (auto index = std::size_t{0U}; index < 4U; ++index)
                {
                    CAPTURE(index);
                    CHECK_FALSE(answers[index].has_value());
                    CHECK(asked[index] == 0);
                }
                CHECK(cache.size() == 0U);
            }
        }
    }
}

SCENARIO("The cache holds a bounded number of origins and never forgets one being asked about",
         "[trust-safety][policy-decision-cache][gate-l]")
{
    GIVEN("a cache limited to 4 origins with one origin being asked about")
    {
        auto cache = PolicyDecisionCache{};
        auto settings = PolicyDecisionCache::Settings{};
        settings.max_entries = 4U;
        auto const start = std::chrono::steady_clock::now();
        auto pending = cache.acquire("pending.example", start, settings, std::chrono::milliseconds{0});
        REQUIRE(pending.leader.has_value());

        WHEN("ten other origins are decided in turn")
        {
            for (auto index = 0; index < 10; ++index)
            {
                auto claim = cache.acquire("origin" + std::to_string(index) + ".example",
                                           start + std::chrono::seconds{index}, settings, std::chrono::milliseconds{0});
                REQUIRE(claim.leader.has_value());
                claim.leader->publish(denied(), start + std::chrono::seconds{index});
            }

            THEN("at most 4 are held, the newest among them, and the pending one is still being asked about")
            {
                CHECK(cache.size() <= 4U);
                CHECK(cache.stale("origin9.example", start + std::chrono::seconds{10}, settings).has_value());
                CHECK_FALSE(cache.stale("origin0.example", start + std::chrono::seconds{10}, settings).has_value());
                auto const concurrent =
                    cache.acquire("pending.example", start, settings, std::chrono::milliseconds{0});
                CHECK_FALSE(concurrent.leader.has_value());
            }
        }
    }
}
