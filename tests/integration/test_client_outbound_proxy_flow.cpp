// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// HTTP-2 and OUT-7 (security audit 2026-09-29, ADR-0079).
//
// HTTP-2: publicRooms?server=, remote room-alias lookups and remote media
// fetches are reachable without authentication and each holds a request-pool
// thread for the whole outbound round trip. Against a peer that never answers
// a handful of them pinned the whole pool. They now run under a small in-flight
// budget (4 overall, 1 per client address) and a short total deadline.
//
// OUT-7: security.media.remote_fetch_enabled=false is documented as the opt-in
// for live remote media fetching but was only checked after the bytes had
// already been downloaded. It is now checked before any discovery or outbound
// call, on every download and thumbnail route.
//
// The peer used here is a TCP listener that completes the handshake (the kernel
// does that from the backlog) and never says anything, i.e. the "peer that never
// answers". It counts the connections it is offered, which is how these tests
// observe that no outbound call was made.

#include "../support/joining_threads.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <latch>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <poll.h>
#include <sodium.h>
#include <sys/socket.h>

using namespace merovingian::tests;
using namespace std::chrono_literals;

namespace
{

using merovingian::homeserver::ClientServerRuntime;

// Any name works: the destination is pinned through test_forced_outbound_resolution.
constexpr auto silent_server = std::string_view{"silent.example.org"};

// A peer that is reachable and never answers.
class SilentPeer final
{
public:
    SilentPeer()
    {
        REQUIRE(m_acceptor.bind("127.0.0.1", 0U).ok);
        m_thread = std::thread{[this]() {
            accept_loop();
        }};
    }

    ~SilentPeer()
    {
        m_stop.store(true);
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    SilentPeer(SilentPeer const&) = delete;
    auto operator=(SilentPeer const&) -> SilentPeer& = delete;
    SilentPeer(SilentPeer&&) = delete;
    auto operator=(SilentPeer&&) -> SilentPeer& = delete;

    [[nodiscard]] auto port() const noexcept -> std::uint16_t
    {
        return m_acceptor.bound_port();
    }

    // Connections this peer has been offered so far.
    [[nodiscard]] auto connections() const noexcept -> int
    {
        return m_connections.load();
    }

private:
    auto accept_loop() -> void
    {
        auto held = std::vector<merovingian::core::SocketHandle>{};
        while (!m_stop.load())
        {
            auto entry = ::pollfd{m_acceptor.fd(), POLLIN, 0};
            if (::poll(&entry, 1U, 20) <= 0)
            {
                continue;
            }
            auto const fd = ::accept(m_acceptor.fd(), nullptr, nullptr);
            if (fd < 0)
            {
                continue;
            }
            held.emplace_back(fd);
            m_connections.fetch_add(1);
        }
    }

    merovingian::net::TcpAcceptor m_acceptor{};
    std::atomic<bool> m_stop{false};
    std::atomic<int> m_connections{0};
    std::thread m_thread{};
};

// Counts every question put to discovery and answers none of them.
class CountingDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    explicit CountingDiscoveryNetwork(
        std::shared_ptr<std::atomic<int>> calls // SHARED_PTR: reviewed — test shares counter with caller
        )
        : m_calls{std::move(calls)}
    {
    }

    [[nodiscard]] auto fetch_well_known(std::string_view,
                                        std::uint32_t) -> merovingian::federation::WellKnownServerResult override
    {
        m_calls->fetch_add(1);
        return {};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        m_calls->fetch_add(1);
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view,
                                        std::uint16_t) -> merovingian::federation::ResolvedAddressSet override
    {
        m_calls->fetch_add(1);
        return {false, {}, "not found"};
    }

private:
    std::shared_ptr<std::atomic<int>> m_calls; // SHARED_PTR: reviewed — test fixture member shared with caller
};

[[nodiscard]] auto proxy_test_config(bool remote_fetch_enabled) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.http.request_threads = 8U;

    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.media.remote_fetch_enabled = remote_fetch_enabled;
    return {
        std::move(server),
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

struct Answer final
{
    std::uint16_t status{0U};
    std::string errcode{};
    std::int64_t retry_after_ms{0};
};

[[nodiscard]] auto send(ClientServerRuntime& runtime, std::string method, std::string target,
                        std::string const& client_address, std::string const& token = {},
                        std::string body = {}) -> Answer
{
    auto request = merovingian::homeserver::LocalHttpRequest{};
    request.method = std::move(method);
    request.target = std::move(target);
    request.access_token = token;
    request.body = std::move(body);
    request.remote_addr = client_address;
    auto const result = merovingian::homeserver::handle_client_server_request(runtime, request);
    auto answer = Answer{result.response.status, {}, 0};
    if (result.response.status >= 400U)
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless(result.response.body);
        if (auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
            object != nullptr)
        {
            if (auto const* code = string_member(*object, "errcode"); code != nullptr)
            {
                answer.errcode = *code;
            }
            if (auto const* retry = int_member(*object, "retry_after_ms"); retry != nullptr)
            {
                answer.retry_after_ms = *retry;
            }
        }
    }
    return answer;
}

[[nodiscard]] auto wait_until(std::function<bool()> const& condition, std::chrono::milliseconds timeout) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (condition())
        {
            return true;
        }
        std::this_thread::sleep_for(5ms);
    }
    return condition();
}

auto point_at(ClientServerRuntime& runtime, SilentPeer const& peer) -> void
{
    runtime.homeserver.test_forced_outbound_resolution[std::string{silent_server}] =
        merovingian::homeserver::TestOnlyForcedOutboundResolution{"localhost", peer.port(), {"127.0.0.1"}, {}};
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& runtime) -> std::string
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(registration.response.status == 200U);
    auto const body = parse_object(registration.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

auto const silent_rooms_target = std::string{"/_matrix/client/v3/publicRooms?server="} + std::string{silent_server};
auto const silent_alias_target =
    std::string{"/_matrix/client/v3/directory/room/%23room%3A"} + std::string{silent_server};

} // namespace

// ---------------------------------------------------------------------------
// OUT-7
// ---------------------------------------------------------------------------

SCENARIO("With remote_fetch_enabled=false no remote media request leaves the server", "[out-7][integration][media]")
{
    GIVEN("a homeserver with the default remote_fetch_enabled=false, counting discovery, and a reachable peer")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const discovery_calls = std::make_shared<std::atomic<int>>(0);
        runtime.homeserver.discovery_network = std::make_unique<CountingDiscoveryNetwork>(discovery_calls);
        auto const peer = SilentPeer{};
        point_at(runtime, peer);
        auto const token = register_and_login(runtime);
        auto const media = std::string{silent_server} + "/abc";
        auto const thumbnail_query = std::string{"?width=32&height=32&method=crop"};

        WHEN("an unauthenticated client asks for remote media on the legacy download route")
        {
            auto const answer = send(runtime, "GET", "/_matrix/media/v3/download/" + media, "198.51.100.1");

            THEN("the answer is 404 M_NOT_FOUND and neither discovery nor the peer was contacted")
            {
                REQUIRE(answer.status == 404U);
                REQUIRE(answer.errcode == "M_NOT_FOUND");
                REQUIRE(discovery_calls->load() == 0);
                REQUIRE(peer.connections() == 0);
            }
        }

        WHEN("an unauthenticated client asks for a remote thumbnail on the legacy thumbnail route")
        {
            auto const answer =
                send(runtime, "GET", "/_matrix/media/v3/thumbnail/" + media + thumbnail_query, "198.51.100.1");

            THEN("the answer is 404 M_NOT_FOUND and nothing was contacted")
            {
                REQUIRE(answer.status == 404U);
                REQUIRE(answer.errcode == "M_NOT_FOUND");
                REQUIRE(discovery_calls->load() == 0);
                REQUIRE(peer.connections() == 0);
            }
        }

        WHEN("an authenticated client asks for remote media on the v1 download route")
        {
            auto const answer =
                send(runtime, "GET", "/_matrix/client/v1/media/download/" + media, "198.51.100.1", token);

            THEN("the answer is 404 M_NOT_FOUND and nothing was contacted")
            {
                REQUIRE(answer.status == 404U);
                REQUIRE(answer.errcode == "M_NOT_FOUND");
                REQUIRE(discovery_calls->load() == 0);
                REQUIRE(peer.connections() == 0);
            }
        }

        WHEN("an authenticated client asks for a remote thumbnail on the v1 thumbnail route")
        {
            auto const answer = send(runtime, "GET", "/_matrix/client/v1/media/thumbnail/" + media + thumbnail_query,
                                     "198.51.100.1", token);

            THEN("the answer is 404 M_NOT_FOUND and nothing was contacted")
            {
                REQUIRE(answer.status == 404U);
                REQUIRE(answer.errcode == "M_NOT_FOUND");
                REQUIRE(discovery_calls->load() == 0);
                REQUIRE(peer.connections() == 0);
            }
        }

        WHEN("an unauthenticated client repeats the refused request")
        {
            auto const audit_rows_before = runtime.homeserver.database.audit_events.size();
            for (auto attempt = 0; attempt < 5; ++attempt)
            {
                std::ignore = send(runtime, "GET", "/_matrix/media/v3/download/" + media, "198.51.100.1");
            }

            THEN("each refusal is counted but none writes a durable audit row an attacker could grow")
            {
                REQUIRE(runtime.homeserver.media_repository.metrics.remote_fetch_rejections == 5U);
                REQUIRE(runtime.homeserver.database.audit_events.size() == audit_rows_before);
            }
        }

        WHEN("the request names this server's own media")
        {
            auto const answer =
                send(runtime, "GET",
                     "/_matrix/media/v3/download/" + runtime.homeserver.config.server().server_name + "/does-not-exist",
                     "198.51.100.1");

            THEN("it is answered locally as not found without outbound calls")
            {
                REQUIRE(answer.status == 404U);
                REQUIRE(discovery_calls->load() == 0);
                REQUIRE(peer.connections() == 0);
            }
        }
    }
}

SCENARIO("allow_remote=false stops a remote media fetch even when remote fetching is enabled",
         "[out-7][integration][media]")
{
    GIVEN("a homeserver with remote_fetch_enabled=true, counting discovery, and a reachable peer")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(true));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const discovery_calls = std::make_shared<std::atomic<int>>(0);
        runtime.homeserver.discovery_network = std::make_unique<CountingDiscoveryNetwork>(discovery_calls);
        auto const peer = SilentPeer{};
        point_at(runtime, peer);
        auto const token = register_and_login(runtime);
        auto const media = std::string{silent_server} + "/abc";

        WHEN("a client sets allow_remote=false on the legacy download, the legacy thumbnail and the v1 routes")
        {
            auto const legacy_download =
                send(runtime, "GET", "/_matrix/media/v3/download/" + media + "?allow_remote=false", "198.51.100.1");
            auto const legacy_thumbnail =
                send(runtime, "GET", "/_matrix/media/v3/thumbnail/" + media + "?width=32&height=32&allow_remote=false",
                     "198.51.100.1");
            auto const v1_download =
                send(runtime, "GET", "/_matrix/client/v1/media/download/" + media + "?allow_remote=false",
                     "198.51.100.1", token);
            auto const v1_thumbnail =
                send(runtime, "GET",
                     "/_matrix/client/v1/media/thumbnail/" + media + "?width=32&height=32&allow_remote=false",
                     "198.51.100.1", token);

            THEN("each is 404 M_NOT_FOUND and nothing was contacted")
            {
                for (auto const& answer : {legacy_download, legacy_thumbnail, v1_download, v1_thumbnail})
                {
                    REQUIRE(answer.status == 404U);
                    REQUIRE(answer.errcode == "M_NOT_FOUND");
                }
                REQUIRE(discovery_calls->load() == 0);
                REQUIRE(peer.connections() == 0);
            }
        }
    }
}

SCENARIO("Remote media fetches run under the in-flight budget and the media deadline",
         "[out-7][http-2][integration][media]")
{
    GIVEN("a homeserver with remote fetching enabled, a one second media deadline and a peer that never answers")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(true));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.media_deadline_seconds = 1U;
        auto const peer = SilentPeer{};
        point_at(runtime, peer);
        auto const target = "/_matrix/media/v3/download/" + std::string{silent_server} + "/abc";

        WHEN("one client's fetch is in flight and the same client asks again")
        {
            auto first = Answer{};
            auto in_flight = false;
            auto second = Answer{};
            {
                auto threads = JoiningThreads{};
                threads.emplace_back([&]() {
                    first = send(runtime, "GET", target, "198.51.100.1");
                });
                in_flight = wait_until(
                    [&]() {
                        return runtime.homeserver.client_outbound_budget->active("198.51.100.1") == 1U;
                    },
                    2000ms);
                second = send(runtime, "GET", target, "198.51.100.1");
            }

            THEN("the second is refused with 429 M_LIMIT_EXCEEDED and the first ends in a bad gateway")
            {
                REQUIRE(in_flight);
                REQUIRE(second.status == 429U);
                REQUIRE(second.errcode == "M_LIMIT_EXCEEDED");
                REQUIRE(second.retry_after_ms == 1000);
                REQUIRE(first.status == 502U);
            }

            THEN("the slot is free again once the fetch has ended")
            {
                REQUIRE(runtime.homeserver.client_outbound_budget->active() == 0U);
            }
        }

        WHEN("a fetch is made against the peer that never answers")
        {
            auto const start = std::chrono::steady_clock::now();
            auto const answer = send(runtime, "GET", target, "198.51.100.1");
            auto const elapsed = std::chrono::steady_clock::now() - start;

            THEN("the media deadline ends it well before the general federation timeout")
            {
                REQUIRE(answer.status == 502U);
                REQUIRE(elapsed < 6s);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP-2
// ---------------------------------------------------------------------------

SCENARIO("Twenty concurrent unauthenticated publicRooms?server= requests cannot pin the request pool",
         "[http-2][integration][concurrency]")
{
    GIVEN("a peer that never answers, the default budget (4 overall, 1 per client) and a three second deadline")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.directory_deadline_seconds = 3U;
        auto const peer = SilentPeer{};
        point_at(runtime, peer);

        WHEN("four requests are in flight and sixteen more arrive from other addresses")
        {
            constexpr auto total = std::size_t{20U};
            constexpr auto admitted_up_front = std::size_t{4U};
            auto answers = std::vector<Answer>(total);
            auto late = std::latch{1};
            auto versions_answer = Answer{};
            auto versions_elapsed = std::chrono::steady_clock::duration{};
            auto saturated = false;
            {
                auto threads = JoiningThreads{};
                for (auto index = std::size_t{0U}; index < total; ++index)
                {
                    threads.emplace_back([&, index]() {
                        if (index >= admitted_up_front)
                        {
                            late.wait();
                        }
                        answers[index] =
                            send(runtime, "GET", silent_rooms_target, "198.51.100." + std::to_string(index + 1U));
                    });
                }
                saturated = wait_until(
                    [&]() {
                        return runtime.homeserver.client_outbound_budget->active() == admitted_up_front;
                    },
                    2000ms);
                late.count_down();
                // Let the sixteen latecomers reach the budget, then probe.
                std::this_thread::sleep_for(300ms);
                auto const start = std::chrono::steady_clock::now();
                versions_answer = send(runtime, "GET", "/_matrix/client/versions", "203.0.113.99");
                versions_elapsed = std::chrono::steady_clock::now() - start;
            }

            THEN("/versions still answers promptly while the peer is being held open")
            {
                REQUIRE(saturated);
                REQUIRE(versions_answer.status == 200U);
                REQUIRE(versions_elapsed < 1500ms);
            }

            THEN("exactly the four admitted requests reached the peer and failed; the other sixteen got 429")
            {
                auto too_many = 0U;
                auto bad_gateway = 0U;
                for (auto const& answer : answers)
                {
                    if (answer.status == 429U)
                    {
                        ++too_many;
                        REQUIRE(answer.errcode == "M_LIMIT_EXCEEDED");
                        REQUIRE(answer.retry_after_ms == 1000);
                    }
                    else if (answer.status == 502U)
                    {
                        ++bad_gateway;
                    }
                }
                REQUIRE(too_many == 16U);
                REQUIRE(bad_gateway == 4U);
                REQUIRE(peer.connections() <= 4);
            }

            THEN("every slot has been returned")
            {
                REQUIRE(runtime.homeserver.client_outbound_budget->active() == 0U);
                REQUIRE(runtime.homeserver.client_outbound_budget->tracked_keys() == 0U);
            }
        }
    }
}

SCENARIO("One client address may hold one proxied lookup at a time", "[http-2][integration][concurrency]")
{
    GIVEN("a peer that never answers")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.directory_deadline_seconds = 2U;
        auto const peer = SilentPeer{};
        point_at(runtime, peer);

        WHEN("a lookup is in flight from one address, then the same address asks again and a different one asks")
        {
            auto first = Answer{};
            auto other_client = Answer{};
            auto same_client = Answer{};
            auto in_flight = false;
            auto other_in_flight = false;
            {
                auto threads = JoiningThreads{};
                threads.emplace_back([&]() {
                    first = send(runtime, "GET", silent_rooms_target, "192.0.2.10");
                });
                in_flight = wait_until(
                    [&]() {
                        return runtime.homeserver.client_outbound_budget->active("192.0.2.10") == 1U;
                    },
                    2000ms);
                same_client = send(runtime, "GET", silent_rooms_target, "192.0.2.10");
                threads.emplace_back([&]() {
                    other_client = send(runtime, "GET", silent_rooms_target, "192.0.2.11");
                });
                other_in_flight = wait_until(
                    [&]() {
                        return runtime.homeserver.client_outbound_budget->active("192.0.2.11") == 1U;
                    },
                    2000ms);
            }

            THEN("the same address is refused and the different address is admitted")
            {
                REQUIRE(in_flight);
                REQUIRE(same_client.status == 429U);
                REQUIRE(same_client.errcode == "M_LIMIT_EXCEEDED");
                REQUIRE(other_in_flight);
            }

            THEN("the admitted lookups end in a bad gateway once the peer's silence hits the deadline")
            {
                REQUIRE(first.status == 502U);
                REQUIRE(other_client.status == 502U);
            }
        }
    }
}

SCENARIO("Every unauthenticated proxy route shares one budget, and authenticated callers are counted too",
         "[http-2][integration][concurrency]")
{
    GIVEN("a budget of one call overall and a peer that never answers")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(true));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.directory_deadline_seconds = 2U;
        auto const peer = SilentPeer{};
        point_at(runtime, peer);
        auto const token = register_and_login(runtime);
        runtime.homeserver.client_outbound_proxy_policy.global_cap = 1U;

        WHEN("one lookup holds the only slot and other routes that proxy to a remote server are tried")
        {
            auto holder = Answer{};
            auto get_rooms = Answer{};
            auto post_rooms = Answer{};
            auto alias = Answer{};
            auto authenticated_alias = Answer{};
            auto media = Answer{};
            auto held = false;
            {
                auto threads = JoiningThreads{};
                threads.emplace_back([&]() {
                    holder = send(runtime, "GET", silent_rooms_target, "192.0.2.20");
                });
                held = wait_until(
                    [&]() {
                        return runtime.homeserver.client_outbound_budget->active() == 1U;
                    },
                    2000ms);
                get_rooms = send(runtime, "GET", silent_rooms_target, "192.0.2.21");
                post_rooms = send(runtime, "POST", silent_rooms_target, "192.0.2.22", {}, R"({"limit":5})");
                alias = send(runtime, "GET", silent_alias_target, "192.0.2.23");
                authenticated_alias = send(runtime, "GET", silent_alias_target, "192.0.2.24", token);
                media = send(runtime, "GET", "/_matrix/media/v3/download/" + std::string{silent_server} + "/abc",
                             "192.0.2.25");
            }

            THEN("each is refused with 429 M_LIMIT_EXCEEDED before any outbound call")
            {
                REQUIRE(held);
                for (auto const& answer : {get_rooms, post_rooms, alias, authenticated_alias, media})
                {
                    REQUIRE(answer.status == 429U);
                    REQUIRE(answer.errcode == "M_LIMIT_EXCEEDED");
                    REQUIRE(answer.retry_after_ms == 1000);
                }
                REQUIRE(peer.connections() <= 1);
            }

            THEN("the call that held the slot ends in a bad gateway")
            {
                REQUIRE(holder.status == 502U);
            }
        }
    }
}

SCENARIO("A proxied lookup ends within its deadline and returns its slot", "[http-2][integration]")
{
    GIVEN("a one second directory deadline and a peer that never answers")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.directory_deadline_seconds = 1U;
        auto const peer = SilentPeer{};
        point_at(runtime, peer);

        WHEN("a publicRooms lookup is made")
        {
            auto const start = std::chrono::steady_clock::now();
            auto const first = send(runtime, "GET", silent_rooms_target, "192.0.2.30");
            auto const elapsed = std::chrono::steady_clock::now() - start;

            THEN("it fails as a bad gateway within the deadline plus a small margin")
            {
                REQUIRE(first.status == 502U);
                REQUIRE(elapsed >= 900ms);
                REQUIRE(elapsed < 4s);
            }

            THEN("the slot is free and a later lookup from the same address is admitted, not refused")
            {
                REQUIRE(runtime.homeserver.client_outbound_budget->active() == 0U);
                auto const second = send(runtime, "GET", silent_rooms_target, "192.0.2.30");
                REQUIRE(second.status == 502U);
            }
        }

        WHEN("a remote alias lookup is made")
        {
            auto const start = std::chrono::steady_clock::now();
            auto const answer = send(runtime, "GET", silent_alias_target, "192.0.2.31");
            auto const elapsed = std::chrono::steady_clock::now() - start;

            THEN("it too fails as a bad gateway within the deadline plus a small margin")
            {
                REQUIRE(answer.status == 502U);
                REQUIRE(elapsed < 4s);
                REQUIRE(runtime.homeserver.client_outbound_budget->active() == 0U);
            }
        }
    }
}

SCENARIO("A local publicRooms request never takes a proxy slot", "[http-2][integration]")
{
    GIVEN("a budget of zero calls")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.global_cap = 0U;

        WHEN("the local directory is listed, with and without naming this server")
        {
            auto const own = runtime.homeserver.config.server().server_name;
            auto const plain = send(runtime, "GET", "/_matrix/client/v3/publicRooms", "192.0.2.40");
            auto const named = send(runtime, "GET", "/_matrix/client/v3/publicRooms?server=" + own, "192.0.2.40");
            auto const local_alias =
                send(runtime, "GET", "/_matrix/client/v3/directory/room/%23nobody%3A" + own, "192.0.2.40");

            THEN("they are answered locally")
            {
                REQUIRE(plain.status == 200U);
                REQUIRE(named.status == 200U);
                REQUIRE(local_alias.status == 404U);
            }
        }
    }
}
