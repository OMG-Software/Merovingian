// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// push::EmailDigestQueue (ADR-0219): when notification emails for kind "email" pushers are due.
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md, POST /_matrix/client/v3/pushers/set —
// kind "email" "makes a pusher that emails the user with unread notifications". How often is the
// server's choice; this server sends a delayed, throttled digest.

#include "../support/joining_threads.hpp"
#include "merovingian/push/email_digest_queue.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace
{

using merovingian::push::EmailDigestAdmission;
using merovingian::push::EmailDigestKey;
using merovingian::push::EmailDigestOutcome;
using merovingian::push::EmailDigestPolicy;
using merovingian::push::EmailDigestQueue;
using std::chrono::minutes;
using std::chrono::seconds;

auto const t0 = std::chrono::steady_clock::time_point{} + std::chrono::hours{1};
auto const policy = EmailDigestPolicy{seconds{600}, seconds{3600}};

[[nodiscard]] auto alice() -> EmailDigestKey
{
    return EmailDigestKey{"@alice:example.org", "alice@example.net"};
}

[[nodiscard]] auto bob() -> EmailDigestKey
{
    return EmailDigestKey{"@bob:example.org", "bob@example.net"};
}

} // namespace

SCENARIO("A notification email waits for the delay before it is due", "[push][email-digest]")
{
    GIVEN("an empty queue")
    {
        auto queue = EmailDigestQueue{};

        WHEN("a notification is noted")
        {
            auto const admission = queue.note_notification(alice(), t0, policy);

            THEN("an email is scheduled for the end of the delay, not before")
            {
                REQUIRE(admission == EmailDigestAdmission::scheduled);
                REQUIRE(queue.next_due() == t0 + seconds{600});
                REQUIRE(queue.take_due(t0 + seconds{599}, 16U).empty());
                auto const due = queue.take_due(t0 + seconds{600}, 16U);
                REQUIRE(due.size() == 1U);
                REQUIRE(due.front() == alice());
            }
        }

        WHEN("more notifications arrive before the email is due")
        {
            std::ignore = queue.note_notification(alice(), t0, policy);
            auto const second = queue.note_notification(alice(), t0 + seconds{300}, policy);

            THEN("they fold into the same email, which stays due when the first said")
            {
                REQUIRE(second == EmailDigestAdmission::folded);
                REQUIRE(queue.next_due() == t0 + seconds{600});
                REQUIRE(queue.take_due(t0 + minutes{20}, 16U).size() == 1U);
                REQUIRE(queue.take_due(t0 + minutes{20}, 16U).empty());
            }
        }

        WHEN("the delay is zero")
        {
            std::ignore = queue.note_notification(alice(), t0, EmailDigestPolicy{seconds{0}, seconds{3600}});

            THEN("the email is due at once")
            {
                REQUIRE(queue.take_due(t0, 16U).size() == 1U);
            }
        }
    }
}

SCENARIO("Emails to one pusher are at least the throttle apart", "[push][email-digest]")
{
    GIVEN("an email that was sent")
    {
        auto queue = EmailDigestQueue{};
        std::ignore = queue.note_notification(alice(), t0, policy);
        std::ignore = queue.take_due(t0 + seconds{600}, 16U);
        auto const sent_at = t0 + seconds{601};
        std::ignore = queue.complete(alice(), EmailDigestOutcome::sent, sent_at, policy);

        WHEN("a notification arrives soon after")
        {
            auto const admission = queue.note_notification(alice(), sent_at + seconds{60}, policy);

            THEN("the next email is due a throttle after the last one, not a delay after the notification")
            {
                REQUIRE(admission == EmailDigestAdmission::scheduled);
                REQUIRE(queue.next_due() == sent_at + seconds{3600});
            }
        }

        WHEN("a notification arrives after the throttle has passed")
        {
            auto const later = sent_at + seconds{7200};
            std::ignore = queue.note_notification(alice(), later, policy);

            THEN("the next email waits only for the delay")
            {
                REQUIRE(queue.next_due() == later + seconds{600});
            }
        }

        WHEN("nothing else arrives")
        {
            THEN("no further email is ever due")
            {
                REQUIRE_FALSE(queue.next_due().has_value());
                REQUIRE(queue.take_due(sent_at + std::chrono::hours{24}, 16U).empty());
            }
        }
    }

    GIVEN("two different pushers")
    {
        auto queue = EmailDigestQueue{};
        std::ignore = queue.note_notification(alice(), t0, policy);
        std::ignore = queue.take_due(t0 + seconds{600}, 16U);
        std::ignore = queue.complete(alice(), EmailDigestOutcome::sent, t0 + seconds{600}, policy);

        WHEN("the other pusher is notified")
        {
            std::ignore = queue.note_notification(bob(), t0 + seconds{700}, policy);

            THEN("its email is not held back by the first pusher's throttle")
            {
                REQUIRE(queue.next_due() == t0 + seconds{1300});
            }
        }
    }
}

SCENARIO("An email that finds nothing unread is not sent and does not start a throttle", "[push][email-digest]")
{
    GIVEN("an email taken for sending")
    {
        auto queue = EmailDigestQueue{};
        std::ignore = queue.note_notification(alice(), t0, policy);
        std::ignore = queue.take_due(t0 + seconds{600}, 16U);

        WHEN("it completes with nothing unread and a new notification arrives")
        {
            std::ignore = queue.complete(alice(), EmailDigestOutcome::nothing_unread, t0 + seconds{600}, policy);
            std::ignore = queue.note_notification(alice(), t0 + seconds{700}, policy);

            THEN("the next email waits only for the delay")
            {
                REQUIRE(queue.next_due() == t0 + seconds{1300});
            }
        }

        WHEN("it completes with nothing unread and nothing else arrives")
        {
            std::ignore = queue.complete(alice(), EmailDigestOutcome::nothing_unread, t0 + seconds{600}, policy);

            THEN("the queue forgets the pusher")
            {
                REQUIRE(queue.size() == 0U);
                REQUIRE_FALSE(queue.next_due().has_value());
            }
        }
    }
}

SCENARIO("A notification noted while an email is being sent gets the next email", "[push][email-digest]")
{
    GIVEN("an email taken for sending")
    {
        auto queue = EmailDigestQueue{};
        std::ignore = queue.note_notification(alice(), t0, policy);
        std::ignore = queue.take_due(t0 + seconds{600}, 16U);

        WHEN("a notification arrives before the send completes")
        {
            auto const admission = queue.note_notification(alice(), t0 + seconds{601}, policy);

            THEN("it is folded and is not due while the send is in progress")
            {
                REQUIRE(admission == EmailDigestAdmission::folded);
                REQUIRE_FALSE(queue.next_due().has_value());
                REQUIRE(queue.take_due(t0 + std::chrono::hours{5}, 16U).empty());
            }

            AND_WHEN("the send completes")
            {
                std::ignore = queue.complete(alice(), EmailDigestOutcome::sent, t0 + seconds{602}, policy);

                THEN("the next email is scheduled a throttle after it")
                {
                    REQUIRE(queue.next_due() == t0 + seconds{602} + seconds{3600});
                }
            }
        }
    }
}

SCENARIO("A failed email is retried with backoff and then given up", "[push][email-digest]")
{
    GIVEN("the retry policy")
    {
        WHEN("the backoff after successive failures is computed")
        {
            THEN("it starts at one minute, doubles, and stops at thirty minutes")
            {
                REQUIRE(merovingian::push::email_digest_backoff(1U) == minutes{1});
                REQUIRE(merovingian::push::email_digest_backoff(2U) == minutes{2});
                REQUIRE(merovingian::push::email_digest_backoff(5U) == minutes{16});
                REQUIRE(merovingian::push::email_digest_backoff(6U) == minutes{30});
                REQUIRE(merovingian::push::email_digest_backoff(60U) == minutes{30});
                REQUIRE(merovingian::push::email_digest_backoff(0U) == minutes{1});
            }
        }
    }

    GIVEN("an email taken for sending")
    {
        auto queue = EmailDigestQueue{};
        std::ignore = queue.note_notification(alice(), t0, policy);
        auto now = t0 + seconds{600};
        std::ignore = queue.take_due(now, 16U);

        WHEN("it fails once")
        {
            auto const retried = queue.complete(alice(), EmailDigestOutcome::failed, now, policy);

            THEN("it is due again a minute later")
            {
                REQUIRE(retried);
                REQUIRE(queue.next_due() == now + minutes{1});
            }
        }

        WHEN("it fails every attempt")
        {
            auto attempts = std::uint32_t{0U};
            auto retried = true;
            while (retried && attempts < 100U)
            {
                retried = queue.complete(alice(), EmailDigestOutcome::failed, now, policy);
                ++attempts;
                if (retried)
                {
                    now = *queue.next_due();
                    REQUIRE(queue.take_due(now, 16U).size() == 1U);
                }
            }

            THEN("it is given up after the last allowed attempt and nothing more is due")
            {
                REQUIRE(attempts == merovingian::push::email_digest_max_attempts);
                REQUIRE_FALSE(queue.next_due().has_value());
            }
        }

        WHEN("it fails and a later attempt succeeds")
        {
            std::ignore = queue.complete(alice(), EmailDigestOutcome::failed, now, policy);
            std::ignore = queue.take_due(now + minutes{1}, 16U);
            std::ignore = queue.complete(alice(), EmailDigestOutcome::sent, now + minutes{1}, policy);
            std::ignore = queue.note_notification(alice(), now + std::chrono::hours{3}, policy);
            std::ignore = queue.take_due(now + std::chrono::hours{4}, 16U);
            auto const retried =
                queue.complete(alice(), EmailDigestOutcome::failed, now + std::chrono::hours{4}, policy);

            THEN("the failure count starts again from the success")
            {
                REQUIRE(retried);
                REQUIRE(queue.next_due() == now + std::chrono::hours{4} + minutes{1});
            }
        }
    }
}

SCENARIO("An email to a pusher that has gone is never sent", "[push][email-digest]")
{
    GIVEN("a scheduled email")
    {
        auto queue = EmailDigestQueue{};
        std::ignore = queue.note_notification(alice(), t0, policy);

        WHEN("the pusher is forgotten before it is due")
        {
            queue.forget(alice());

            THEN("nothing is due")
            {
                REQUIRE_FALSE(queue.next_due().has_value());
                REQUIRE(queue.take_due(t0 + std::chrono::hours{1}, 16U).empty());
                REQUIRE(queue.size() == 0U);
            }
        }

        WHEN("the attempt is abandoned")
        {
            std::ignore = queue.take_due(t0 + seconds{600}, 16U);
            auto const retried = queue.complete(alice(), EmailDigestOutcome::abandoned, t0 + seconds{600}, policy);

            THEN("it is not retried and the pusher is forgotten")
            {
                REQUIRE_FALSE(retried);
                REQUIRE(queue.size() == 0U);
            }
        }
    }
}

SCENARIO("The email queue is bounded", "[push][email-digest][security]")
{
    GIVEN("a queue holding its capacity of due emails")
    {
        auto queue = EmailDigestQueue{};
        for (auto index = std::size_t{0U}; index < merovingian::push::email_digest_queue_capacity; ++index)
        {
            REQUIRE(
                queue.note_notification(EmailDigestKey{"@u" + std::to_string(index) + ":example.org", "a@b.example"},
                                        t0, policy) == EmailDigestAdmission::scheduled);
        }

        WHEN("another pusher is notified")
        {
            auto const admission = queue.note_notification(alice(), t0, policy);

            THEN("it is refused and the queue does not grow")
            {
                REQUIRE(admission == EmailDigestAdmission::queue_full);
                REQUIRE(queue.size() == merovingian::push::email_digest_queue_capacity);
            }
        }

        WHEN("a pusher already queued is notified again")
        {
            auto const admission =
                queue.note_notification(EmailDigestKey{"@u0:example.org", "a@b.example"}, t0, policy);

            THEN("it folds as usual")
            {
                REQUIRE(admission == EmailDigestAdmission::folded);
            }
        }
    }

    GIVEN("a full queue of pushers remembered only for a throttle that has passed")
    {
        auto queue = EmailDigestQueue{};
        for (auto index = std::size_t{0U}; index < merovingian::push::email_digest_queue_capacity; ++index)
        {
            auto const key = EmailDigestKey{"@u" + std::to_string(index) + ":example.org", "a@b.example"};
            std::ignore = queue.note_notification(key, t0, policy);
        }
        auto const taken = queue.take_due(t0 + seconds{600}, merovingian::push::email_digest_queue_capacity);
        for (auto const& key : taken)
        {
            std::ignore = queue.complete(key, EmailDigestOutcome::sent, t0 + seconds{600}, policy);
        }

        WHEN("a new pusher is notified after the throttle has passed")
        {
            auto const admission = queue.note_notification(alice(), t0 + std::chrono::hours{3}, policy);

            THEN("the idle pushers are released and it is scheduled")
            {
                REQUIRE(admission == EmailDigestAdmission::scheduled);
                REQUIRE(queue.size() == 1U);
            }
        }
    }
}

SCENARIO("The email queue may be used from several threads at once", "[push][email-digest][concurrency]")
{
    GIVEN("a queue shared by noting threads and a taking thread")
    {
        auto queue = EmailDigestQueue{};
        auto wakes = std::atomic<std::size_t>{0U};
        queue.set_wake([&wakes]() {
            ++wakes;
        });
        constexpr auto thread_count = std::size_t{4U};
        constexpr auto per_thread = std::size_t{200U};
        auto release = std::atomic<bool>{false};
        auto admitted = std::atomic<std::size_t>{0U};
        auto taken = std::atomic<std::size_t>{0U};

        WHEN("they run together")
        {
            {
                auto threads = merovingian::tests::JoiningThreads{};
                for (auto thread = std::size_t{0U}; thread < thread_count; ++thread)
                {
                    threads.emplace_back([&, thread]() {
                        while (!release.load())
                        {
                            std::this_thread::yield();
                        }
                        for (auto index = std::size_t{0U}; index < per_thread; ++index)
                        {
                            auto const key = EmailDigestKey{"@t" + std::to_string(thread) + "u" +
                                                                std::to_string(index) + ":example.org",
                                                            "a@b.example"};
                            if (queue.note_notification(key, t0, EmailDigestPolicy{seconds{0}, seconds{0}}) ==
                                EmailDigestAdmission::scheduled)
                            {
                                ++admitted;
                            }
                        }
                    });
                }
                threads.emplace_back([&]() {
                    while (!release.load())
                    {
                        std::this_thread::yield();
                    }
                    for (auto round = 0; round < 400; ++round)
                    {
                        auto const due = queue.take_due(t0, 8U);
                        taken += due.size();
                        for (auto const& key : due)
                        {
                            std::ignore = queue.complete(key, EmailDigestOutcome::sent, t0,
                                                         EmailDigestPolicy{seconds{0}, seconds{0}});
                        }
                    }
                });
                release.store(true);
            }
            auto const remaining = queue.take_due(t0, thread_count * per_thread).size();

            THEN("every distinct pusher was scheduled exactly once and taken exactly once")
            {
                REQUIRE(admitted.load() == thread_count * per_thread);
                REQUIRE(taken.load() + remaining == thread_count * per_thread);
                REQUIRE(wakes.load() == thread_count * per_thread);
            }
        }
    }
}
