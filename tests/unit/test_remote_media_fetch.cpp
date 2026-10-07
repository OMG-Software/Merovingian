// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/joining_threads.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/remote_media_fetch_coalescer.hpp"
#include "merovingian/homeserver/remote_media_fetch_scope.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <thread>

// ADR-0121: one fetch per remote file at a time. A second request for a file
// that is already being fetched waits for that fetch and is then served from
// the cache, instead of fetching it again and displacing the first copy.
SCENARIO("The remote media fetch coalescer lets one request lead each file's fetch",
         "[homeserver][media][media-fetch-pool]")
{
    GIVEN("a coalescer with no fetch in flight")
    {
        auto coalescer = merovingian::homeserver::RemoteMediaFetchCoalescer{};

        WHEN("a request leads the fetch of one file")
        {
            auto lead = coalescer.try_lead("peer.example.org/abc");
            auto second = coalescer.try_lead("peer.example.org/abc");
            auto other = coalescer.try_lead("peer.example.org/def");

            THEN("no other request may lead the same file, while a different file is independent")
            {
                REQUIRE(lead.has_value());
                REQUIRE_FALSE(second.has_value());
                REQUIRE(other.has_value());
                REQUIRE(coalescer.in_flight() == 2U);
            }
        }

        WHEN("the leading fetch ends")
        {
            {
                auto lead = coalescer.try_lead("peer.example.org/abc");
                REQUIRE(lead.has_value());
            }
            auto again = coalescer.try_lead("peer.example.org/abc");

            THEN("the file can be led again and nothing is left in flight")
            {
                REQUIRE(again.has_value());
                REQUIRE(coalescer.in_flight() == 1U);
            }
        }

        WHEN("a lead is moved into another owner and that owner ends")
        {
            auto lead = coalescer.try_lead("peer.example.org/abc");
            REQUIRE(lead.has_value());
            {
                auto const moved = std::move(*lead);
                lead.reset();
            }

            THEN("the file is released exactly once")
            {
                REQUIRE(coalescer.in_flight() == 0U);
                REQUIRE(coalescer.try_lead("peer.example.org/abc").has_value());
            }
        }
    }
}

SCENARIO("A request waiting on another's fetch of the same file resumes when it ends, and not before",
         "[homeserver][media][media-fetch-pool][concurrency]")
{
    GIVEN("a fetch of one file in flight and a second request waiting for it on another thread")
    {
        auto coalescer = merovingian::homeserver::RemoteMediaFetchCoalescer{};
        auto lead = coalescer.try_lead("peer.example.org/abc");
        REQUIRE(lead.has_value());
        auto waiter_idle = std::atomic<int>{-1};
        auto threads = merovingian::tests::JoiningThreads{};
        threads.emplace_back([&coalescer, &waiter_idle] {
            auto const idle = coalescer.wait_until_idle("peer.example.org/abc",
                                                        std::chrono::steady_clock::now() + std::chrono::seconds{10});
            waiter_idle.store(idle ? 1 : 0);
        });
        auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (coalescer.waiting() == 0U && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        REQUIRE(coalescer.waiting() == 1U);

        WHEN("the leading fetch is still running")
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
            auto const before_release = waiter_idle.load();
            lead.reset();
            threads.join();

            THEN("the waiter was still waiting, and resumed once the fetch ended")
            {
                REQUIRE(before_release == -1);
                REQUIRE(waiter_idle.load() == 1);
                REQUIRE(coalescer.waiting() == 0U);
            }
        }
    }

    GIVEN("a fetch of one file that never ends within the waiter's deadline")
    {
        auto coalescer = merovingian::homeserver::RemoteMediaFetchCoalescer{};
        auto const lead = coalescer.try_lead("peer.example.org/abc");
        REQUIRE(lead.has_value());

        WHEN("another request waits for it with a short deadline")
        {
            auto const began = std::chrono::steady_clock::now();
            auto const idle = coalescer.wait_until_idle("peer.example.org/abc", began + std::chrono::milliseconds{100});
            auto const waited = std::chrono::steady_clock::now() - began;

            THEN("the wait ends at the deadline and reports that the fetch is still in flight")
            {
                REQUIRE_FALSE(idle);
                REQUIRE(waited >= std::chrono::milliseconds{100});
                REQUIRE(waited < std::chrono::seconds{5});
                REQUIRE(coalescer.waiting() == 0U);
            }
        }

        WHEN("another request waits for a different file")
        {
            auto const idle = coalescer.wait_until_idle("peer.example.org/def",
                                                        std::chrono::steady_clock::now() + std::chrono::seconds{5});

            THEN("it does not wait at all")
            {
                REQUIRE(idle);
            }
        }
    }
}

// ADR-0121: the mode a remote media fetch runs in is published for the
// request's thread, like the request lock, so the fetch deep in the media
// service knows whether to fetch, defer to the media pool, or skip the
// main-pool budget because the media pool already admitted it.
SCENARIO("A remote media fetch scope publishes how this thread may fetch remote media",
         "[homeserver][media][media-fetch-pool]")
{
    using merovingian::homeserver::RemoteMediaFetchMode;
    using merovingian::homeserver::RemoteMediaFetchScope;

    GIVEN("a thread with no scope published")
    {
        THEN("remote media is fetched inline, as it always was, and a deferral is not recorded")
        {
            REQUIRE(RemoteMediaFetchScope::current_mode() == RemoteMediaFetchMode::inline_fetch);
            REQUIRE_FALSE(RemoteMediaFetchScope::record_deferral());
        }
    }

    GIVEN("a request that may defer its remote fetch to the media pool")
    {
        auto const scope = RemoteMediaFetchScope{RemoteMediaFetchMode::defer};

        WHEN("the fetch path records a deferral")
        {
            auto const recorded = RemoteMediaFetchScope::record_deferral();

            THEN("the scope reports the deferral")
            {
                REQUIRE(recorded);
                REQUIRE(RemoteMediaFetchScope::current_mode() == RemoteMediaFetchMode::defer);
                REQUIRE(scope.deferred());
            }
        }

        WHEN("nothing is deferred")
        {
            THEN("the scope reports no deferral")
            {
                REQUIRE_FALSE(scope.deferred());
            }
        }

        WHEN("an inner scope is published and then ends")
        {
            {
                auto const inner = RemoteMediaFetchScope{RemoteMediaFetchMode::admitted};
                REQUIRE(RemoteMediaFetchScope::current_mode() == RemoteMediaFetchMode::admitted);
                REQUIRE_FALSE(RemoteMediaFetchScope::record_deferral());
            }

            THEN("the outer scope is current again and the inner one recorded nothing on it")
            {
                REQUIRE(RemoteMediaFetchScope::current_mode() == RemoteMediaFetchMode::defer);
                REQUIRE_FALSE(scope.deferred());
            }
        }
    }

    GIVEN("a scope published on another thread")
    {
        auto const scope = RemoteMediaFetchScope{RemoteMediaFetchMode::defer};
        auto other_mode = std::optional<RemoteMediaFetchMode>{};
        auto threads = merovingian::tests::JoiningThreads{};
        threads.emplace_back([&other_mode] {
            other_mode = RemoteMediaFetchScope::current_mode();
        });
        threads.join();

        THEN("this thread does not see it")
        {
            REQUIRE(other_mode == RemoteMediaFetchMode::inline_fetch);
        }
    }
}

SCENARIO("Media fetch admission caps follow the configured pool settings",
         "[homeserver][media][media-fetch-pool][config]")
{
    GIVEN("the default HTTP transport settings")
    {
        auto const settings = merovingian::config::HttpTransportConfig{};

        WHEN("the admission caps are resolved")
        {
            auto const caps = merovingian::homeserver::media_fetch_admission_caps(settings);

            THEN("queued and running fetches are capped together, and one client may hold several")
            {
                REQUIRE(caps.global == 64U);
                REQUIRE(caps.per_client == 8U);
            }
        }
    }

    GIVEN("a per-client cap configured above the global cap")
    {
        auto settings = merovingian::config::HttpTransportConfig{};
        settings.media_fetch_max_in_flight = 4U;
        settings.media_fetch_max_per_client = 16U;

        WHEN("the admission caps are resolved")
        {
            auto const caps = merovingian::homeserver::media_fetch_admission_caps(settings);

            THEN("one client can never be promised more than the whole budget")
            {
                REQUIRE(caps.global == 4U);
                REQUIRE(caps.per_client == 4U);
            }
        }
    }
}
