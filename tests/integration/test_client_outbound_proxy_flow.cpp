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
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/TestOnlyForcedOutboundResolution.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>
#include <poll.h>
#include <sodium.h>
#include <sys/socket.h>

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

    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t)
        -> merovingian::federation::WellKnownServerResult override
    {
        m_calls->fetch_add(1);
        return {};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        m_calls->fetch_add(1);
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
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
                        std::string const& client_address, std::string const& token = {}, std::string body = {})
    -> Answer
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

struct RawAnswer final
{
    std::uint16_t status{0U};
    std::string body{};
};

// The status and the whole body, for a test that reads what was answered.
[[nodiscard]] auto send_raw(ClientServerRuntime& runtime, std::string method, std::string target,
                            std::string const& client_address, std::string const& token = {}, std::string body = {})
    -> RawAnswer
{
    auto request = merovingian::homeserver::LocalHttpRequest{};
    request.method = std::move(method);
    request.target = std::move(target);
    request.access_token = token;
    request.body = std::move(body);
    request.remote_addr = client_address;
    auto const result = merovingian::homeserver::handle_client_server_request(runtime, request);
    return {result.response.status, result.response.body};
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
        auto const token = register_and_login(runtime);
        // The authenticated route: the deprecated /_matrix/media/v3 routes never
        // fetch remote media during the freeze (ADR-0068).
        auto const target = "/_matrix/client/v1/media/download/" + std::string{silent_server} + "/abc";

        WHEN("one client's fetch is in flight and the same client asks again")
        {
            auto first = Answer{};
            auto in_flight = false;
            auto second = Answer{};
            {
                auto threads = JoiningThreads{};
                threads.emplace_back([&]() {
                    first = send(runtime, "GET", target, "198.51.100.1", token);
                });
                in_flight = wait_until(
                    [&]() {
                        return runtime.homeserver.client_outbound_budget->active("198.51.100.1") == 1U;
                    },
                    2000ms);
                second = send(runtime, "GET", target, "198.51.100.1", token);
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
            auto const answer = send(runtime, "GET", target, "198.51.100.1", token);
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
                // Matrix v1.19 POST /publicRooms requires authentication before proxy admission.
                post_rooms = send(runtime, "POST", silent_rooms_target, "192.0.2.22", token, R"({"limit":5})");
                alias = send(runtime, "GET", silent_alias_target, "192.0.2.23");
                authenticated_alias = send(runtime, "GET", silent_alias_target, "192.0.2.24", token);
                // Authenticated: the deprecated media routes never fetch remote media (ADR-0068).
                media = send(runtime, "GET", "/_matrix/client/v1/media/download/" + std::string{silent_server} + "/abc",
                             "192.0.2.25", token);
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

// ---------------------------------------------------------------------------
// F-17 (ADR-0350): /keys/query, /keys/claim and POST /join/{#remoteAlias} are client-triggered
// outbound calls like the lookups above, and run under the same controls.
// ---------------------------------------------------------------------------

namespace
{

// The `failures` object of a /keys/query or /keys/claim answer.
[[nodiscard]] auto failures_of(std::string const& body) -> merovingian::canonicaljson::Object
{
    auto const root = parse_object(body);
    auto const* failures = object_member_as_object(root, "failures");
    REQUIRE(failures != nullptr);
    return *failures;
}

[[nodiscard]] auto failure_errcode(merovingian::canonicaljson::Object const& failures, std::string const& server)
    -> std::string
{
    auto const* entry = object_member_as_object(failures, server);
    if (entry == nullptr)
    {
        return {};
    }
    auto const* code = string_member(*entry, "errcode");
    return code == nullptr ? std::string{} : *code;
}

[[nodiscard]] auto failure_message(merovingian::canonicaljson::Object const& failures, std::string const& server)
    -> std::string
{
    auto const* entry = object_member_as_object(failures, server);
    if (entry == nullptr)
    {
        return {};
    }
    auto const* message = string_member(*entry, "error");
    return message == nullptr ? std::string{} : *message;
}

[[nodiscard]] auto remote_user(std::string const& server) -> std::string
{
    return "@someone:" + server;
}

// The body of a /keys/query naming each remote user, and the local user alice.
[[nodiscard]] auto key_query_body(std::vector<std::string> const& servers, std::string const& local_server)
    -> std::string
{
    auto body = std::string{R"({"device_keys":{"@alice:)"} + local_server + R"(":[])";
    for (auto const& server : servers)
    {
        body += R"(,")" + remote_user(server) + R"(":[])";
    }
    return body + "}}";
}

} // namespace

SCENARIO("With no proxy slot free a key query reports its remote servers as failures and still answers locally",
         "[f-17][http-2][integration][keys]")
{
    GIVEN("a budget of no calls and a remote server that would be reachable")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const peer = SilentPeer{};
        point_at(runtime, peer);
        auto const token = register_and_login(runtime);
        runtime.homeserver.client_outbound_proxy_policy.global_cap = 0U;
        auto const local_server = runtime.homeserver.config.server().server_name;

        WHEN("a client queries the keys of a local user and of a user on that remote server")
        {
            // client-server-api.md, POST /keys/query: `failures` records "any remote homeservers could not be
            // reached"; the rest of the answer is still returned.
            auto const answer = send_raw(runtime, "POST", "/_matrix/client/v3/keys/query", "192.0.2.50", token,
                                         key_query_body({std::string{silent_server}}, local_server));

            THEN("the request succeeds, the remote server is a failure, and it was never contacted")
            {
                REQUIRE(answer.status == 200U);
                auto const failures = failures_of(answer.body);
                REQUIRE(failure_errcode(failures, std::string{silent_server}) == "M_LIMIT_EXCEEDED");
                auto const root = parse_object(answer.body);
                auto const* device_keys = object_member_as_object(root, "device_keys");
                REQUIRE(device_keys != nullptr);
                REQUIRE(object_member_as_object(*device_keys, "@alice:" + local_server) != nullptr);
                REQUIRE(peer.connections() == 0);
            }
        }
    }
}

SCENARIO("With no proxy slot free a key claim returns the one-time keys it already took here",
         "[f-17][http-2][integration][keys]")
{
    GIVEN("a local one-time key, a budget of no calls and a remote server that would be reachable")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const peer = SilentPeer{};
        point_at(runtime, peer);
        auto const token = register_and_login(runtime);
        auto const local_server = runtime.homeserver.config.server().server_name;
        auto const alice = "@alice:" + local_server;
        REQUIRE(merovingian::database::store_one_time_key(
            runtime.homeserver.database.persistent_store,
            {alice, "ALICEDEV", "signed_curve25519:AAAAAQ", R"({"key":"LOCAL_OTK_VALUE"})"}));
        runtime.homeserver.client_outbound_proxy_policy.global_cap = 0U;

        WHEN("a client claims a key of that local user and of a user on the remote server")
        {
            auto const claim = std::string{R"({"one_time_keys":{")"} + alice +
                               R"(":{"ALICEDEV":"signed_curve25519"},")" + remote_user(std::string{silent_server}) +
                               R"(":{"REMOTEDEV":"signed_curve25519"}}})";
            auto const answer = send_raw(runtime, "POST", "/_matrix/client/v3/keys/claim", "192.0.2.51", token, claim);

            THEN("the local key, which was consumed, is in the answer; the remote server is a failure, uncontacted")
            {
                // client-server-api.md, POST /keys/claim: an unreachable server is recorded in `failures`.
                REQUIRE(answer.status == 200U);
                REQUIRE(answer.body.find("LOCAL_OTK_VALUE") != std::string::npos);
                auto const failures = failures_of(answer.body);
                REQUIRE(failure_errcode(failures, std::string{silent_server}) == "M_LIMIT_EXCEEDED");
                REQUIRE(peer.connections() == 0);
                REQUIRE(runtime.homeserver.client_outbound_budget->active() == 0U);
            }
        }
    }
}

SCENARIO("One key query shares a single deadline across every remote server it names",
         "[f-17][http-2][integration][keys]")
{
    GIVEN("a one second key deadline and three remote servers that accept a connection and never answer")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.remote_keys_deadline_seconds = 1U;
        auto const peer = SilentPeer{};
        auto const servers = std::vector<std::string>{"s1.example.org", "s2.example.org", "s3.example.org"};
        for (auto const& server : servers)
        {
            runtime.homeserver.test_forced_outbound_resolution[server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{"localhost", peer.port(), {"127.0.0.1"}, {}};
        }
        auto const token = register_and_login(runtime);
        auto const local_server = runtime.homeserver.config.server().server_name;

        WHEN("a client queries the keys of a user on each of them")
        {
            auto const answer = send_raw(runtime, "POST", "/_matrix/client/v3/keys/query", "192.0.2.52", token,
                                         key_query_body(servers, local_server));

            THEN("only the first is dialled: it used the whole deadline, so the others fail without a connection")
            {
                REQUIRE(answer.status == 200U);
                auto const failures = failures_of(answer.body);
                for (auto const& server : servers)
                {
                    REQUIRE(failure_errcode(failures, server) == "M_UNKNOWN");
                }
                REQUIRE(peer.connections() == 1);
                REQUIRE(runtime.homeserver.client_outbound_budget->active() == 0U);
            }
        }
    }
}

SCENARIO("One key claim shares a single deadline across every remote server it names",
         "[f-17][http-2][integration][keys]")
{
    GIVEN("a one second key deadline and three remote servers that accept a connection and never answer")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.remote_keys_deadline_seconds = 1U;
        auto const peer = SilentPeer{};
        auto const servers = std::vector<std::string>{"s1.example.org", "s2.example.org", "s3.example.org"};
        auto claim = std::string{R"({"one_time_keys":{)"};
        for (auto const& server : servers)
        {
            runtime.homeserver.test_forced_outbound_resolution[server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{"localhost", peer.port(), {"127.0.0.1"}, {}};
            claim += (claim.back() == '{' ? "" : ",") + std::string{"\""} + remote_user(server) +
                     R"(":{"DEV":"signed_curve25519"})";
        }
        claim += "}}";
        auto const token = register_and_login(runtime);

        WHEN("a client claims a key from a user on each of them")
        {
            auto const answer = send_raw(runtime, "POST", "/_matrix/client/v3/keys/claim", "192.0.2.53", token, claim);

            THEN("only the first is dialled and every server is reported as a failure")
            {
                REQUIRE(answer.status == 200U);
                auto const failures = failures_of(answer.body);
                for (auto const& server : servers)
                {
                    REQUIRE(failure_errcode(failures, server) == "M_UNKNOWN");
                }
                REQUIRE(peer.connections() == 1);
            }
        }
    }
}

SCENARIO("A key query asks at most the configured number of distinct remote servers",
         "[f-17][http-2][integration][keys]")
{
    GIVEN("a cap of two servers, two that fail at once, and two beyond the cap that would accept a connection")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.remote_keys_max_servers = 2U;
        runtime.homeserver.client_outbound_proxy_policy.remote_keys_deadline_seconds = 2U;
        auto const discovery_calls = std::make_shared<std::atomic<int>>(0);
        runtime.homeserver.discovery_network = std::make_unique<CountingDiscoveryNetwork>(discovery_calls);
        auto const peer = SilentPeer{};
        // The map orders servers by name, so a1 and a2 come first and are the two asked.
        auto const asked = std::vector<std::string>{"a1.example.org", "a2.example.org"};
        auto const excess = std::vector<std::string>{"z1.example.org", "z2.example.org"};
        for (auto const& server : excess)
        {
            runtime.homeserver.test_forced_outbound_resolution[server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{"localhost", peer.port(), {"127.0.0.1"}, {}};
        }
        auto const token = register_and_login(runtime);
        auto const local_server = runtime.homeserver.config.server().server_name;
        auto all = asked;
        all.insert(all.end(), excess.begin(), excess.end());

        WHEN("a client queries the keys of a user on each of the four")
        {
            auto const answer = send_raw(runtime, "POST", "/_matrix/client/v3/keys/query", "192.0.2.54", token,
                                         key_query_body(all, local_server));

            THEN("the two beyond the cap are reported as failures and never contacted")
            {
                REQUIRE(answer.status == 200U);
                auto const failures = failures_of(answer.body);
                for (auto const& server : all)
                {
                    REQUIRE_FALSE(failure_errcode(failures, server).empty());
                }
                for (auto const& server : excess)
                {
                    REQUIRE(failure_errcode(failures, server) == "M_LIMIT_EXCEEDED");
                    REQUIRE(failure_message(failures, server).find("too many remote servers") != std::string::npos);
                }
                for (auto const& server : asked)
                {
                    REQUIRE(failure_message(failures, server).find("too many remote servers") == std::string::npos);
                }
                REQUIRE(peer.connections() == 0);
            }
        }
    }
}

SCENARIO("A join through a remote alias takes a proxy slot and ends within the directory deadline",
         "[f-17][http-2][integration]")
{
    GIVEN("a budget of no calls and a remote server that would be reachable")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const peer = SilentPeer{};
        point_at(runtime, peer);
        auto const token = register_and_login(runtime);
        auto const join_target = std::string{"/_matrix/client/v3/join/%23room%3A"} + std::string{silent_server};
        runtime.homeserver.client_outbound_proxy_policy.global_cap = 0U;

        WHEN("a client joins by that server's alias")
        {
            auto const answer = send(runtime, "POST", join_target, "192.0.2.55", token, "{}");

            THEN("it is refused with 429 M_LIMIT_EXCEEDED before any outbound call")
            {
                REQUIRE(answer.status == 429U);
                REQUIRE(answer.errcode == "M_LIMIT_EXCEEDED");
                REQUIRE(answer.retry_after_ms == 1000);
                REQUIRE(peer.connections() == 0);
            }
        }
    }

    GIVEN("a one second directory deadline and a remote server that never answers")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.directory_deadline_seconds = 1U;
        auto const peer = SilentPeer{};
        point_at(runtime, peer);
        auto const token = register_and_login(runtime);
        auto const join_target = std::string{"/_matrix/client/v3/join/%23room%3A"} + std::string{silent_server};

        WHEN("a client joins by that server's alias")
        {
            auto const answer = send(runtime, "POST", join_target, "192.0.2.56", token, "{}");

            THEN("the lookup is a bad gateway once the deadline passes, and the slot is back")
            {
                // The lookup used the directory deadline, not the 60 s remote_timeout: the test would not end
                // otherwise. Only the count of dials and the returned slot are asserted, not the time taken.
                REQUIRE(answer.status == 502U);
                REQUIRE(peer.connections() == 1);
                REQUIRE(runtime.homeserver.client_outbound_budget->active() == 0U);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// F-43 (ADR-0349): a federation worker is the process most exposed to hostile traffic, so what it relays
// is input. An answer main uses without a signature check is fetched over main's own connection. These
// scenarios play a compromised worker: `test_worker_outbound_route` answers any call handed to the
// tunnel with a forgery, and the remote server is a closed port. A forgery that is used shows up in the
// response; a call that reaches the tunnel shows up in the count.
// ---------------------------------------------------------------------------

namespace
{

constexpr auto forged_server = std::string_view{"forged.example.org"};

// A compromised worker: counts the calls it is handed and answers each with `body`, as a success.
struct ForgingWorker final
{
    std::atomic<int> calls{0};
    std::string body{};

    auto install(ClientServerRuntime& runtime) -> void
    {
        runtime.homeserver.test_worker_outbound_route = [this](merovingian::http::OutboundRequest const&) {
            calls.fetch_add(1);
            auto reply = merovingian::http::OutboundResult{};
            reply.ok = true;
            reply.response.status = 200U;
            reply.response.body = body;
            return reply;
        };
    }
};

// The remote server is a loopback port nothing listens on: a call made over main's own client is refused
// at once, so the only way for the forged body to appear is for main to have believed the worker.
auto point_at_closed_port(ClientServerRuntime& runtime) -> void
{
    runtime.homeserver.test_forced_outbound_resolution[std::string{forged_server}] =
        merovingian::homeserver::TestOnlyForcedOutboundResolution{"localhost", 1U, {"127.0.0.1"}, {}};
}

} // namespace

SCENARIO("A worker's forged key query answer is not what a client is told", "[f-43][integration][keys]")
{
    GIVEN("a worker that answers every call it is handed with a forged device for a remote user")
    {
        REQUIRE(sodium_init() >= 0);
        auto worker = ForgingWorker{};
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const victim = remote_user(std::string{forged_server});
        worker.body = R"({"device_keys":{")" + victim + R"(":{"DUMMYDEV":{"user_id":")" + victim +
                      R"(","device_id":"DUMMYDEV","algorithms":[],"keys":{},"signatures":{}}}}})";
        worker.install(runtime);
        point_at_closed_port(runtime);
        auto const token = register_and_login(runtime);
        auto const local_server = runtime.homeserver.config.server().server_name;

        WHEN("a client queries that user's keys")
        {
            auto const answer = send_raw(runtime, "POST", "/_matrix/client/v3/keys/query", "192.0.2.60", token,
                                         key_query_body({std::string{forged_server}}, local_server));

            THEN("the forged device is not returned, the server is a failure and the worker was not asked")
            {
                REQUIRE(answer.status == 200U);
                REQUIRE(answer.body.find("DUMMYDEV") == std::string::npos);
                REQUIRE_FALSE(failure_errcode(failures_of(answer.body), std::string{forged_server}).empty());
                REQUIRE(worker.calls.load() == 0);
            }
        }
    }
}

SCENARIO("A worker's forged key claim answer is not what a client is told", "[f-43][integration][keys]")
{
    GIVEN("a worker that answers every call it is handed with a forged one-time key for a remote user")
    {
        REQUIRE(sodium_init() >= 0);
        auto worker = ForgingWorker{};
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const victim = remote_user(std::string{forged_server});
        worker.body =
            R"({"one_time_keys":{")" + victim + R"(":{"DEV":{"signed_curve25519:AAAAAQ":{"key":"FORGED_OTK"}}}}})";
        worker.install(runtime);
        point_at_closed_port(runtime);
        auto const token = register_and_login(runtime);

        WHEN("a client claims a key from that user")
        {
            auto const claim = R"({"one_time_keys":{")" + victim + R"(":{"DEV":"signed_curve25519"}}})";
            auto const answer = send_raw(runtime, "POST", "/_matrix/client/v3/keys/claim", "192.0.2.61", token, claim);

            THEN("the forged key is not returned and the worker was not asked")
            {
                REQUIRE(answer.status == 200U);
                REQUIRE(answer.body.find("FORGED_OTK") == std::string::npos);
                REQUIRE_FALSE(failure_errcode(failures_of(answer.body), std::string{forged_server}).empty());
                REQUIRE(worker.calls.load() == 0);
            }
        }
    }
}

SCENARIO("A worker's forged alias, public room and profile answers are not what a client is told",
         "[f-43][integration]")
{
    GIVEN("a worker that answers every call it is handed with a forged room, directory entry and profile")
    {
        REQUIRE(sodium_init() >= 0);
        auto worker = ForgingWorker{};
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        worker.body = R"({"room_id":"!FORGED:forged.example.org","servers":["forged.example.org"],)"
                      R"("chunk":[{"room_id":"!FORGED:forged.example.org"}],"displayname":"FORGED"})";
        worker.install(runtime);
        point_at_closed_port(runtime);
        auto const token = register_and_login(runtime);
        auto const server = std::string{forged_server};

        WHEN("a client resolves an alias, lists that server's public rooms, reads a profile, and joins by alias")
        {
            auto const alias =
                send_raw(runtime, "GET", "/_matrix/client/v3/directory/room/%23a%3A" + server, "192.0.2.62", token);
            auto const rooms =
                send_raw(runtime, "GET", "/_matrix/client/v3/publicRooms?server=" + server, "192.0.2.63", token);
            auto const profile =
                send_raw(runtime, "GET", "/_matrix/client/v3/profile/%40u%3A" + server, "192.0.2.64", token);
            auto const join =
                send_raw(runtime, "POST", "/_matrix/client/v3/join/%23a%3A" + server, "192.0.2.65", token, "{}");

            THEN("none of them carries the forgery, none succeeds and the worker was never asked")
            {
                for (auto const* answer : {&alias, &rooms, &profile, &join})
                {
                    REQUIRE(answer->body.find("FORGED") == std::string::npos);
                    REQUIRE(answer->status >= 400U);
                }
                REQUIRE(worker.calls.load() == 0);
            }
        }
    }
}

SCENARIO("A worker's forged membership answers do not reach a join or a knock", "[f-43][integration][membership]")
{
    GIVEN("a worker that answers every call it is handed with a forged success")
    {
        REQUIRE(sodium_init() >= 0);
        auto worker = ForgingWorker{};
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        worker.body = R"({"room_version":"10","event":{"type":"m.room.member"}})";
        worker.install(runtime);
        point_at_closed_port(runtime);
        auto const token = register_and_login(runtime);
        auto const server = std::string{forged_server};

        WHEN("a client joins and knocks on a room that server is said to host")
        {
            auto const join = send_raw(runtime, "POST", "/_matrix/client/v3/join/%21r%3A" + server + "?via=" + server,
                                       "192.0.2.66", token, "{}");
            auto const knock = send_raw(runtime, "POST", "/_matrix/client/v3/knock/%21r%3A" + server + "?via=" + server,
                                        "192.0.2.67", token, "{}");

            THEN("neither succeeds and the worker was never asked")
            {
                REQUIRE(join.status >= 400U);
                REQUIRE(knock.status >= 400U);
                REQUIRE(worker.calls.load() == 0);
            }
        }
    }
}

SCENARIO("Only a call whose answer is checked by signature may be carried by the worker",
         "[f-43][integration][routing]")
{
    GIVEN("a worker that answers every call it is handed, and a closed port for the remote server")
    {
        REQUIRE(sodium_init() >= 0);
        auto worker = ForgingWorker{};
        auto started = merovingian::homeserver::start_client_server(proxy_test_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        worker.body = R"({"pdus":[]})";
        worker.install(runtime);
        point_at_closed_port(runtime);
        auto const signing_key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime.homeserver);
        REQUIRE(signing_key.has_value());
        auto const our_server = runtime.homeserver.config.server().server_name;
        auto const transaction = merovingian::federation::make_outbound_transaction(
            std::string{forged_server}, "GET", "/_matrix/federation/v1/event/%24e", our_server, {});

        WHEN("a call whose answer main does not verify is made")
        {
            auto const [ok, body] = merovingian::homeserver::perform_sync_outbound_call(
                runtime.homeserver, merovingian::homeserver::OutboundAnswerTrust::unverified, {}, transaction,
                signing_key->key_id,
                merovingian::core::SecretBuffer{runtime.homeserver.database.signing_secret_key.bytes()}, "test.f43",
                5U);

            THEN("the worker is not asked and the worker's answer is not the result")
            {
                REQUIRE(worker.calls.load() == 0);
                REQUIRE_FALSE(ok);
                REQUIRE(body.find("pdus") == std::string::npos);
            }
        }

        WHEN("a call whose answer main verifies by signature is made")
        {
            auto const [ok, body] = merovingian::homeserver::perform_sync_outbound_call(
                runtime.homeserver, merovingian::homeserver::OutboundAnswerTrust::signature_verified, {}, transaction,
                signing_key->key_id,
                merovingian::core::SecretBuffer{runtime.homeserver.database.signing_secret_key.bytes()}, "test.f43",
                5U);

            THEN("the worker carries it")
            {
                REQUIRE(worker.calls.load() == 1);
                REQUIRE(ok);
                REQUIRE(body == R"({"pdus":[]})");
            }
        }
    }
}
