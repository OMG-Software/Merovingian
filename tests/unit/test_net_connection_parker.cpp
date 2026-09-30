// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// HTTP-1 / ADR-0077: the connection parker holds connections that are waiting
// for input on one thread, and hands them out only when readable, under a
// global and a per-client cap. Tags: [net][http-1].

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/net/connection_parker.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{

using merovingian::core::FileDescriptor;
using merovingian::net::ConnectionParker;
using namespace std::chrono_literals;

// One end of a socketpair, parked as a connection. The test keeps the other end
// to make it readable or to observe that the parker closed it.
class PairConnection final : public ConnectionParker::Connection
{
public:
    PairConnection(FileDescriptor end, bool buffered,
                   std::shared_ptr<std::atomic<int>> expired) // SHARED_PTR: reviewed — test observer
        : m_end{std::move(end)}
        , m_buffered{buffered}
        , m_expired{std::move(expired)}
    {
    }

    [[nodiscard]] auto fd() const noexcept -> int override
    {
        return m_end.get();
    }

    [[nodiscard]] auto has_buffered_input() const noexcept -> bool override
    {
        return m_buffered;
    }

    auto on_park_expired() noexcept -> void override
    {
        if (m_expired)
        {
            m_expired->fetch_add(1);
        }
    }

private:
    FileDescriptor m_end;
    bool m_buffered;
    std::shared_ptr<std::atomic<int>> m_expired; // SHARED_PTR: reviewed — test observer
};

struct Pair final
{
    FileDescriptor parked{};
    FileDescriptor peer{};
};

[[nodiscard]] auto make_pair() -> Pair
{
    auto fds = std::array<int, 2U>{-1, -1};
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()) == 0);
    return {FileDescriptor{fds[0]}, FileDescriptor{fds[1]}};
}

auto make_readable(FileDescriptor const& peer) -> void
{
    auto const byte = char{'x'};
    REQUIRE(::send(peer.get(), &byte, 1U, MSG_NOSIGNAL) == 1);
}

// True once the parked end has been closed: the peer reads EOF. Bounded.
[[nodiscard]] auto peer_sees_close(FileDescriptor const& peer, std::chrono::milliseconds within) -> bool
{
    auto entry = pollfd{};
    entry.fd = peer.get();
    entry.events = POLLIN;
    if (::poll(&entry, 1U, static_cast<int>(within.count())) <= 0)
    {
        return false;
    }
    auto byte = char{};
    return ::recv(peer.get(), &byte, 1U, MSG_DONTWAIT) == 0;
}

// Collects dispatched connections; the test decides when to release them.
class Collector final
{
public:
    auto add(ConnectionParker::Dispatched dispatched) -> void
    {
        {
            auto const lock = std::lock_guard{m_mutex};
            m_items.push_back(std::move(dispatched));
        }
        m_cv.notify_all();
    }

    [[nodiscard]] auto wait_for_count(std::size_t count, std::chrono::milliseconds within) -> bool
    {
        auto lock = std::unique_lock{m_mutex};
        return m_cv.wait_for(lock, within, [&] {
            return m_items.size() >= count;
        });
    }

    [[nodiscard]] auto count() -> std::size_t
    {
        auto const lock = std::lock_guard{m_mutex};
        return m_items.size();
    }

    [[nodiscard]] auto count_for(std::string const& key) -> std::size_t
    {
        auto const lock = std::lock_guard{m_mutex};
        auto total = std::size_t{0U};
        for (auto const& item : m_items)
        {
            if (item.client_key == key)
            {
                ++total;
            }
        }
        return total;
    }

    // Releases (destroys) the first dispatched item for `key`: closes it and
    // frees its share.
    auto release_first(std::string const& key) -> bool
    {
        auto released = ConnectionParker::Dispatched{};
        {
            auto const lock = std::lock_guard{m_mutex};
            for (auto it = m_items.begin(); it != m_items.end(); ++it)
            {
                if (it->client_key == key && it->share.held())
                {
                    released = std::move(*it);
                    m_items.erase(it);
                    break;
                }
            }
        }
        if (!released.share.held())
        {
            return false;
        }
        released.share.release();
        return true;
    }

    auto clear() -> void
    {
        auto items = std::vector<ConnectionParker::Dispatched>{};
        {
            auto const lock = std::lock_guard{m_mutex};
            items.swap(m_items);
        }
    }

private:
    std::mutex m_mutex{};
    std::condition_variable m_cv{};
    std::vector<ConnectionParker::Dispatched> m_items{};
};

[[nodiscard]] auto far_deadline() -> std::chrono::steady_clock::time_point
{
    return std::chrono::steady_clock::now() + 60s;
}

auto park_pair(ConnectionParker& parker, Pair& pair, std::string key, bool buffered = false,
               std::shared_ptr<std::atomic<int>> expired = {}, // SHARED_PTR: reviewed — test observer
               std::chrono::steady_clock::time_point deadline = far_deadline()) -> bool
{
    return parker.park(std::make_unique<PairConnection>(std::move(pair.parked), buffered, std::move(expired)),
                       std::move(key), deadline);
}

} // namespace

SCENARIO("The connection parker hands a connection out only once it is readable", "[net][http-1]")
{
    GIVEN("a started parker with room for four active connections")
    {
        auto collector = Collector{};
        auto parker = ConnectionParker{
            {4U, 4U},
            [&](ConnectionParker::Dispatched dispatched) {
                collector.add(std::move(dispatched));
             }
        };
        REQUIRE(parker.start());

        WHEN("a quiet connection is parked")
        {
            auto pair = make_pair();
            REQUIRE(park_pair(parker, pair, "client-a"));
            auto const dispatched_while_quiet = collector.wait_for_count(1U, 300ms);
            auto const parked_while_quiet = parker.parked();

            AND_WHEN("its peer sends a byte")
            {
                make_readable(pair.peer);
                auto const dispatched = collector.wait_for_count(1U, 2000ms);

                THEN("it was held without being dispatched, and is dispatched once readable")
                {
                    REQUIRE_FALSE(dispatched_while_quiet);
                    REQUIRE(parked_while_quiet == 1U);
                    REQUIRE(dispatched);
                    REQUIRE(parker.active("client-a") == 1U);
                    REQUIRE(parker.parked() == 0U);
                }
            }
        }

        WHEN("a connection that already has input buffered above the socket is parked")
        {
            auto pair = make_pair();
            REQUIRE(park_pair(parker, pair, "client-a", true));

            THEN("it is dispatched without the socket being readable")
            {
                REQUIRE(collector.wait_for_count(1U, 2000ms));
            }
        }
        collector.clear();
        parker.request_stop();
    }
}

SCENARIO("The connection parker caps the workers one client may hold", "[net][http-1][security]")
{
    GIVEN("a parker with four active slots and at most one per client")
    {
        auto collector = Collector{};
        auto parker = ConnectionParker{
            {4U, 1U},
            [&](ConnectionParker::Dispatched dispatched) {
                collector.add(std::move(dispatched));
             }
        };
        REQUIRE(parker.start());

        WHEN("one client has three readable connections and another client has one")
        {
            auto pairs = std::vector<Pair>{};
            for (auto index = 0; index < 4; ++index)
            {
                pairs.push_back(make_pair());
                make_readable(pairs.back().peer);
            }
            REQUIRE(park_pair(parker, pairs[0], "client-a"));
            REQUIRE(park_pair(parker, pairs[1], "client-a"));
            REQUIRE(park_pair(parker, pairs[2], "client-a"));
            REQUIRE(park_pair(parker, pairs[3], "client-b"));

            REQUIRE(collector.wait_for_count(2U, 2000ms));
            // Give an over-cap dispatch time to happen if the cap were not enforced.
            std::ignore = collector.wait_for_count(3U, 300ms);
            auto const first_a = collector.count_for("client-a");
            auto const first_b = collector.count_for("client-b");
            auto const still_parked = parker.parked();

            AND_WHEN("the client's dispatched connection is released")
            {
                REQUIRE(collector.release_first("client-a"));
                auto const next_dispatched = collector.wait_for_count(2U, 2000ms) && [&] {
                    auto const deadline = std::chrono::steady_clock::now() + 2000ms;
                    while (std::chrono::steady_clock::now() < deadline)
                    {
                        if (collector.count_for("client-a") == 1U && parker.parked() == 1U)
                        {
                            return true;
                        }
                        std::this_thread::sleep_for(10ms);
                    }
                    return false;
                }();

                THEN("each client held one worker, the rest waited, and a release let the next one through")
                {
                    REQUIRE(first_a == 1U);
                    REQUIRE(first_b == 1U);
                    REQUIRE(still_parked == 2U);
                    REQUIRE(next_dispatched);
                    REQUIRE(parker.active("client-a") == 1U);
                }
            }
        }
        collector.clear();
        parker.request_stop();
    }
}

SCENARIO("The connection parker exempts an empty client key from the per-client cap but not the global one",
         "[net][http-1]")
{
    GIVEN("a parker with two active slots and at most one per client")
    {
        auto collector = Collector{};
        auto parker = ConnectionParker{
            {2U, 1U},
            [&](ConnectionParker::Dispatched dispatched) {
                collector.add(std::move(dispatched));
             }
        };
        REQUIRE(parker.start());

        WHEN("three readable connections with no client key are parked")
        {
            auto pairs = std::vector<Pair>{};
            for (auto index = 0; index < 3; ++index)
            {
                pairs.push_back(make_pair());
                make_readable(pairs.back().peer);
                REQUIRE(park_pair(parker, pairs.back(), {}));
            }
            REQUIRE(collector.wait_for_count(2U, 2000ms));
            auto const over_global_cap = collector.wait_for_count(3U, 300ms);
            REQUIRE(collector.release_first({}));
            auto const third = collector.wait_for_count(2U, 2000ms) && [&] {
                auto const deadline = std::chrono::steady_clock::now() + 2000ms;
                while (std::chrono::steady_clock::now() < deadline)
                {
                    if (parker.parked() == 0U)
                    {
                        return true;
                    }
                    std::this_thread::sleep_for(10ms);
                }
                return false;
            }();

            THEN("two are dispatched at once, and the third only after one is released")
            {
                REQUIRE_FALSE(over_global_cap);
                REQUIRE(third);
                REQUIRE(parker.active() == 2U);
            }
        }
        collector.clear();
        parker.request_stop();
    }
}

SCENARIO("The connection parker closes a connection that is not readable by its deadline", "[net][http-1]")
{
    GIVEN("a started parker")
    {
        auto collector = Collector{};
        auto parker = ConnectionParker{
            {4U, 4U},
            [&](ConnectionParker::Dispatched dispatched) {
                collector.add(std::move(dispatched));
             }
        };
        REQUIRE(parker.start());

        WHEN("a quiet connection is parked with a short deadline")
        {
            auto expired = std::make_shared<std::atomic<int>>(0);
            auto pair = make_pair();
            REQUIRE(park_pair(parker, pair, "client-a", false, expired, std::chrono::steady_clock::now() + 200ms));
            auto const closed = peer_sees_close(pair.peer, 3000ms);

            THEN("it is closed, reported as expired, and never dispatched")
            {
                REQUIRE(closed);
                REQUIRE(expired->load() == 1);
                REQUIRE(collector.count() == 0U);
                REQUIRE(parker.parked() == 0U);
            }
        }
        parker.request_stop();
    }
}

SCENARIO("Stopping the connection parker closes every parked connection promptly and refuses new ones", "[net][http-1]")
{
    GIVEN("a started parker holding five quiet connections")
    {
        auto collector = Collector{};
        auto parker = ConnectionParker{
            {4U, 4U},
            [&](ConnectionParker::Dispatched dispatched) {
                collector.add(std::move(dispatched));
             }
        };
        REQUIRE(parker.start());
        auto pairs = std::vector<Pair>{};
        for (auto index = 0; index < 5; ++index)
        {
            pairs.push_back(make_pair());
            REQUIRE(park_pair(parker, pairs.back(), "client-a"));
        }

        WHEN("the parker is stopped")
        {
            auto const started = std::chrono::steady_clock::now();
            parker.request_stop();
            auto const elapsed = std::chrono::steady_clock::now() - started;
            auto all_closed = true;
            for (auto const& pair : pairs)
            {
                all_closed = all_closed && peer_sees_close(pair.peer, 1000ms);
            }
            auto late = make_pair();
            auto const accepted_late = park_pair(parker, late, "client-a");

            THEN("it returns at once, every peer sees the close, and a later connection is refused and closed")
            {
                REQUIRE(elapsed < 1000ms);
                REQUIRE(all_closed);
                REQUIRE_FALSE(accepted_late);
                REQUIRE(peer_sees_close(late.peer, 1000ms));
                REQUIRE_FALSE(parker.running());
            }
        }
    }
}

SCENARIO("The connection parker refuses connections before it is started", "[net][http-1]")
{
    GIVEN("a parker that was never started")
    {
        auto parker = ConnectionParker{
            {1U, 1U},
            [](ConnectionParker::Dispatched) {
             }
        };

        WHEN("a connection is parked")
        {
            auto pair = make_pair();
            auto const accepted = park_pair(parker, pair, "client-a");

            THEN("it is refused and closed (fail closed)")
            {
                REQUIRE_FALSE(accepted);
                REQUIRE(peer_sees_close(pair.peer, 1000ms));
            }
        }
    }
}

SCENARIO("The connection parker accepts connections from many threads at once", "[net][http-1][concurrency]")
{
    GIVEN("a parker whose dispatch callback releases each connection at once")
    {
        auto dispatched_total = std::atomic<std::size_t>{0U};
        auto parker = ConnectionParker{
            {3U, 1U},
            [&](ConnectionParker::Dispatched dispatched) {
                // Dropping it closes the connection and releases the share.
                [[maybe_unused]] auto const released = std::move(dispatched);
                dispatched_total.fetch_add(1U);
             }
        };
        REQUIRE(parker.start());

        WHEN("eight threads each park twenty-five readable connections under four client keys")
        {
            constexpr auto threads = 8U;
            constexpr auto per_thread = 25U;
            auto peers = std::vector<std::vector<FileDescriptor>>(threads);
            auto start_flag = std::atomic<bool>{false};
            auto refused = std::atomic<std::size_t>{0U};
            auto workers = std::vector<std::thread>{};
            for (auto thread = 0U; thread < threads; ++thread)
            {
                workers.emplace_back([&, thread] {
                    while (!start_flag.load())
                    {
                        std::this_thread::yield();
                    }
                    for (auto index = 0U; index < per_thread; ++index)
                    {
                        auto fds = std::array<int, 2U>{-1, -1};
                        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()) != 0)
                        {
                            refused.fetch_add(1U);
                            continue;
                        }
                        auto peer = FileDescriptor{fds[1]};
                        auto const byte = char{'x'};
                        std::ignore = ::send(peer.get(), &byte, 1U, MSG_NOSIGNAL);
                        if (!parker.park(std::make_unique<PairConnection>(FileDescriptor{fds[0]}, false, nullptr),
                                         "client-" + std::to_string((thread + index) % 4U), far_deadline()))
                        {
                            refused.fetch_add(1U);
                        }
                        peers[thread].push_back(std::move(peer));
                    }
                });
            }
            start_flag.store(true);
            for (auto& worker : workers)
            {
                worker.join();
            }
            auto const deadline = std::chrono::steady_clock::now() + 5000ms;
            while ((dispatched_total.load() < threads * per_thread || parker.active() != 0U) &&
                   std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(10ms);
            }

            THEN("every connection is dispatched exactly once and every share is released")
            {
                REQUIRE(refused.load() == 0U);
                REQUIRE(dispatched_total.load() == threads * per_thread);
                REQUIRE(parker.active() == 0U);
                REQUIRE(parker.parked() == 0U);
            }
        }
        parker.request_stop();
    }
}
