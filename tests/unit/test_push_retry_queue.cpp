// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// push::PushRetryQueue and the retry policy (R14, ADR-0206).
// Spec: ../../docs/matrix-v1.19-spec/push-gateway-api.md — "If the endpoint returns an HTTP error
// code, the homeserver SHOULD retry for a reasonable amount of time using exponential backoff."

#include "../support/joining_threads.hpp"
#include "merovingian/push/push_retry_queue.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using merovingian::push::PushRetry;
using merovingian::push::PushRetryAdmission;
using merovingian::push::PushRetryQueue;
using std::chrono::milliseconds;
using std::chrono::seconds;

auto const t0 = std::chrono::steady_clock::time_point{} + std::chrono::hours{1};

[[nodiscard]] auto retry_for(std::string user, std::string pushkey, std::uint32_t failed_attempts = 1U) -> PushRetry
{
    auto retry = PushRetry{};
    retry.user_id = std::move(user);
    retry.app_id = "org.example.app";
    retry.pushkey = std::move(pushkey);
    retry.gateway_url = "https://push.example.org/_matrix/push/v1/notify";
    retry.notification.event_id = "$event";
    retry.failed_attempts = failed_attempts;
    return retry;
}

} // namespace

SCENARIO("Push retries back off exponentially to a ceiling", "[push][push_retry][r14]")
{
    GIVEN("the retry policy")
    {
        WHEN("the backoff after successive failures is computed")
        {
            THEN("it starts at five seconds, doubles, and stops at ten minutes")
            {
                REQUIRE(merovingian::push::push_retry_backoff(1U) == seconds{5});
                REQUIRE(merovingian::push::push_retry_backoff(2U) == seconds{10});
                REQUIRE(merovingian::push::push_retry_backoff(4U) == seconds{40});
                REQUIRE(merovingian::push::push_retry_backoff(8U) == std::chrono::minutes{10});
                REQUIRE(merovingian::push::push_retry_backoff(40U) == std::chrono::minutes{10});
            }
        }
    }
}

SCENARIO("Only an HTTP error or an unreachable gateway is retried", "[push][push_retry][r14]")
{
    GIVEN("delivery outcomes")
    {
        auto accepted = merovingian::push::PushGatewayResult{};
        accepted.ok = true;
        accepted.status = 200U;
        auto server_error = accepted;
        server_error.status = 503U;
        auto throttled = accepted;
        throttled.status = 429U;
        auto unreachable = merovingian::push::PushGatewayResult{};
        unreachable.error = merovingian::http::OutboundError::connection_failed;
        auto refused_url = merovingian::push::PushGatewayResult{};
        refused_url.error = merovingian::http::OutboundError::invalid_url;
        auto disabled = merovingian::push::PushGatewayResult{};
        disabled.disabled = true;

        WHEN("each is classified")
        {
            THEN("HTTP error statuses and transport failures retry; acceptance, refusal and disabled do not")
            {
                // Spec SHOULD: "If the endpoint returns an HTTP error code, the homeserver SHOULD retry".
                REQUIRE(merovingian::push::push_delivery_should_retry(server_error));
                REQUIRE(merovingian::push::push_delivery_should_retry(throttled));
                REQUIRE(merovingian::push::push_delivery_should_retry(unreachable));
                REQUIRE_FALSE(merovingian::push::push_delivery_should_retry(accepted));
                REQUIRE_FALSE(merovingian::push::push_delivery_should_retry(refused_url));
                REQUIRE_FALSE(merovingian::push::push_delivery_should_retry(disabled));
            }
        }
    }
}

SCENARIO("A scheduled retry becomes due after its backoff", "[push][push_retry][r14]")
{
    GIVEN("one retry after a first failure and one after a third")
    {
        auto queue = PushRetryQueue{};
        REQUIRE(queue.schedule(retry_for("@a:example.org", "late", 3U), t0) == PushRetryAdmission::queued);
        REQUIRE(queue.schedule(retry_for("@a:example.org", "early", 1U), t0) == PushRetryAdmission::queued);

        WHEN("the queue is asked before, at and after the first is due")
        {
            auto const before = queue.take_due(t0 + seconds{4}, 10U);
            auto const at_first = queue.take_due(t0 + seconds{5}, 10U);
            auto const next = queue.next_due();
            auto const at_second = queue.take_due(t0 + seconds{20}, 10U);

            THEN("each is handed out once, when due, earliest first")
            {
                REQUIRE(before.empty());
                REQUIRE(at_first.size() == 1U);
                REQUIRE(at_first.front().pushkey == "early");
                REQUIRE(next.has_value());
                REQUIRE(*next == t0 + seconds{20});
                REQUIRE(at_second.size() == 1U);
                REQUIRE(at_second.front().pushkey == "late");
                REQUIRE(queue.size() == 0U);
            }
        }
    }
}

SCENARIO("A notification is given up after the last retry", "[push][push_retry][r14]")
{
    GIVEN("an empty queue")
    {
        auto queue = PushRetryQueue{};

        WHEN("retries after the eighth and ninth failed attempts are scheduled")
        {
            auto const eighth = queue.schedule(retry_for("@a:example.org", "k", 8U), t0);
            auto const ninth = queue.schedule(retry_for("@a:example.org", "k", 9U), t0);

            THEN("the eighth retry is still made and the ninth is not")
            {
                REQUIRE(eighth == PushRetryAdmission::queued);
                REQUIRE(ninth == PushRetryAdmission::gave_up);
                REQUIRE(queue.size() == 1U);
            }
        }
    }
}

SCENARIO("The retry queue is bounded per recipient and in all", "[push][push_retry][r14][security]")
{
    GIVEN("one recipient at their share of the queue")
    {
        auto queue = PushRetryQueue{};
        for (auto i = std::size_t{0U}; i < merovingian::push::push_retry_per_user_capacity; ++i)
        {
            REQUIRE(queue.schedule(retry_for("@a:example.org", "k" + std::to_string(i)), t0) ==
                    PushRetryAdmission::queued);
        }

        WHEN("that recipient and another each fail once more")
        {
            auto const same = queue.schedule(retry_for("@a:example.org", "extra"), t0);
            auto const other = queue.schedule(retry_for("@b:example.org", "k"), t0);

            THEN("the first is dropped and the second queued")
            {
                REQUIRE(same == PushRetryAdmission::queue_full);
                REQUIRE(other == PushRetryAdmission::queued);
            }
        }

        WHEN("many recipients fill the whole queue")
        {
            auto user = std::size_t{0U};
            while (queue.size() < merovingian::push::push_retry_queue_capacity)
            {
                REQUIRE(queue.schedule(retry_for("@u" + std::to_string(user++) + ":example.org", "k"), t0) ==
                        PushRetryAdmission::queued);
            }

            THEN("one more is refused")
            {
                REQUIRE(queue.schedule(retry_for("@late:example.org", "k"), t0) == PushRetryAdmission::queue_full);
            }
        }
    }
}

SCENARIO("A rejected pushkey's queued retries are dropped", "[push][push_retry][r14]")
{
    GIVEN("retries to two pushkeys")
    {
        auto queue = PushRetryQueue{};
        REQUIRE(queue.schedule(retry_for("@a:example.org", "dead"), t0) == PushRetryAdmission::queued);
        REQUIRE(queue.schedule(retry_for("@a:example.org", "dead", 2U), t0) == PushRetryAdmission::queued);
        REQUIRE(queue.schedule(retry_for("@a:example.org", "alive"), t0) == PushRetryAdmission::queued);

        WHEN("the gateway rejects one of them")
        {
            auto const dropped = queue.drop_pushkey("org.example.app", "dead");

            THEN("\"Homeservers must cease sending notification requests for these pushkeys\"")
            {
                REQUIRE(dropped == 2U);
                auto const remaining = queue.take_due(t0 + std::chrono::hours{1}, 10U);
                REQUIRE(remaining.size() == 1U);
                REQUIRE(remaining.front().pushkey == "alive");
            }
        }
    }
}

SCENARIO("Scheduling a retry wakes the retry job", "[push][push_retry][r14]")
{
    GIVEN("a queue with a wake hook")
    {
        auto queue = PushRetryQueue{};
        auto wakes = 0;
        queue.set_wake([&wakes]() {
            ++wakes;
        });

        WHEN("a retry is queued, one is refused, and the hook is cleared before another")
        {
            REQUIRE(queue.schedule(retry_for("@a:example.org", "k"), t0) == PushRetryAdmission::queued);
            REQUIRE(queue.schedule(retry_for("@a:example.org", "k", 99U), t0) == PushRetryAdmission::gave_up);
            queue.set_wake({});
            REQUIRE(queue.schedule(retry_for("@a:example.org", "k2"), t0) == PushRetryAdmission::queued);

            THEN("only the first queued retry woke the job")
            {
                REQUIRE(wakes == 1);
            }
        }
    }
}

SCENARIO("Delivery threads and the retry job share the queue safely", "[push][push_retry][r14][concurrency]")
{
    GIVEN("eight threads scheduling retries for their own recipients while one thread takes due retries")
    {
        auto queue = PushRetryQueue{};
        auto taken = std::atomic<std::size_t>{0U};
        auto start = std::atomic<bool>{false};
        auto producers_done = std::atomic<std::size_t>{0U};
        constexpr auto producers = std::size_t{8U};
        constexpr auto per_producer = std::size_t{20U};

        WHEN("they run at once")
        {
            {
                auto threads = merovingian::tests::JoiningThreads{};
                for (auto p = std::size_t{0U}; p < producers; ++p)
                {
                    threads.emplace_back([&queue, &start, &producers_done, p]() {
                        while (!start.load())
                        {
                            std::this_thread::yield();
                        }
                        for (auto i = std::size_t{0U}; i < per_producer; ++i)
                        {
                            std::ignore = queue.schedule(
                                retry_for("@p" + std::to_string(p) + ":example.org", "k" + std::to_string(i)), t0);
                        }
                        ++producers_done;
                    });
                }
                threads.emplace_back([&queue, &start, &taken, &producers_done]() {
                    while (!start.load())
                    {
                        std::this_thread::yield();
                    }
                    while (producers_done.load() < producers || queue.size() > 0U)
                    {
                        taken += queue.take_due(t0 + std::chrono::hours{1}, 7U).size();
                    }
                });
                start = true;
            }

            THEN("every scheduled retry was taken exactly once")
            {
                REQUIRE(taken.load() == producers * per_producer);
                REQUIRE(queue.size() == 0U);
            }
        }
    }
}
