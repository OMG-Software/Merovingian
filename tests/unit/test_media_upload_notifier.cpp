// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/joining_threads.hpp"
#include "merovingian/homeserver/media_upload_notifier.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <thread>

SCENARIO("The media upload notifier wakes every waiter when an upload completes",
         "[homeserver][media][async-upload][concurrency]")
{
    GIVEN("several threads waiting on the notifier's current generation")
    {
        auto notifier = merovingian::homeserver::MediaUploadNotifier{};
        auto const seen = notifier.generation();
        constexpr auto waiter_count = std::size_t{8U};
        auto woke = std::array<bool, waiter_count>{};
        auto threads = merovingian::tests::JoiningThreads{};
        for (auto index = std::size_t{0U}; index < waiter_count; ++index)
        {
            threads.emplace_back([&notifier, &woke, seen, index] {
                woke[index] =
                    notifier.wait_for_upload(seen, std::chrono::steady_clock::now() + std::chrono::seconds{10});
            });
        }
        auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (notifier.waiting() < waiter_count && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }

        WHEN("an upload completes")
        {
            notifier.notify_uploaded();
            threads.join();

            THEN("every waiter returns true and none is left waiting")
            {
                for (auto const value : woke)
                {
                    REQUIRE(value);
                }
                REQUIRE(notifier.waiting() == 0U);
                REQUIRE(notifier.generation() != seen);
            }
        }
    }
}

SCENARIO("A wait on the media upload notifier ends at its deadline", "[homeserver][media][async-upload]")
{
    GIVEN("a notifier nobody notifies")
    {
        auto notifier = merovingian::homeserver::MediaUploadNotifier{};

        WHEN("a thread waits with a short deadline")
        {
            auto const started = std::chrono::steady_clock::now();
            auto const moved = notifier.wait_for_upload(notifier.generation(), started + std::chrono::milliseconds{30});
            auto const waited = std::chrono::steady_clock::now() - started;

            THEN("it returns false once the deadline passes")
            {
                REQUIRE_FALSE(moved);
                REQUIRE(waited >= std::chrono::milliseconds{25});
            }
        }

        WHEN("a thread waits on a generation that has already moved on")
        {
            auto const seen = notifier.generation();
            notifier.notify_uploaded();
            auto const moved =
                notifier.wait_for_upload(seen, std::chrono::steady_clock::now() + std::chrono::seconds{10});

            THEN("it returns at once: an upload between the read and the wait is not lost")
            {
                REQUIRE(moved);
            }
        }
    }
}
