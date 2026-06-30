// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         OUT-OF-PROCESS FEDERATION WORKER INTEGRATION TESTS              |
// |                                                                         |
// |  These tests spawn the real merovingian-fed-worker binary over an       |
// |  encrypted AF_UNIX socketpair and exercise room-based sharding, the     |
// |  sign-back channel, and in-process fallback when the worker is down.    |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/federation_request_routing.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/worker_pool.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>

#include <sodium.h>

namespace
{

using merovingian::config::ClientRateLimitsConfig;
using merovingian::config::Config;
using merovingian::config::DatabaseBackend;
using merovingian::config::DatabaseConfig;
using merovingian::config::DatabaseRole;
using merovingian::config::FederationWorkerConfig;
using merovingian::config::ListenersConfig;
using merovingian::config::LogModulesConfig;
using merovingian::config::SecurityConfig;
using merovingian::config::ServerConfig;
using merovingian::homeserver::federation_worker_room_id_from_request;
using merovingian::homeserver::FederationProxy;
using merovingian::homeserver::handle_federation_http_request;
using merovingian::homeserver::LocalHttpRequest;
using merovingian::homeserver::LocalHttpResponse;
using merovingian::homeserver::start_runtime;
using merovingian::homeserver::WorkerPool;
using merovingian::http::OutboundRequest;

#ifndef MEROVINGIAN_TEST_FEDERATION_WORKER
#define MEROVINGIAN_TEST_FEDERATION_WORKER ""
#endif

[[nodiscard]] auto worker_binary_path() -> std::string_view
{
    return MEROVINGIAN_TEST_FEDERATION_WORKER;
}

[[nodiscard]] auto unique_temp_dir(std::string_view prefix) -> std::filesystem::path
{
    auto rng = std::mt19937{std::random_device{}()};
    auto dist = std::uniform_int_distribution<std::uint64_t>{};
    auto parent = merovingian::tests::temporary_directory();
    while (true)
    {
        auto candidate = parent / (std::string{prefix} + "-" + std::to_string(dist(rng)));
        if (!std::filesystem::exists(candidate))
        {
            std::filesystem::create_directories(candidate);
            return candidate;
        }
    }
}

auto write_file(std::filesystem::path const& path, std::string_view content) -> void
{
    // Write in binary mode so WSL does not see Windows CRLF line endings in
    // the worker's key-value config file.
    auto stream = std::ofstream{path, std::ios::binary};
    REQUIRE(stream.is_open());
    stream << content;
}

[[nodiscard]] auto make_federation_worker_config(std::filesystem::path const& tmp) -> Config
{
    std::ignore = tmp; // the worker processes use an in-memory SQLite store

    auto server = ServerConfig{};
    auto database = DatabaseConfig{};
    database.backend = DatabaseBackend::sqlite;
    // Use an in-memory SQLite database so each spawned worker process gets an
    // independent store without contending for the same on-disk file.
    database.sqlite_path = ":memory:";
    database.role = DatabaseRole::runtime;

    auto security = SecurityConfig{};
    security.federation.enabled = true;
    // The IPC channel is now mutually authenticated via a master-key-derived
    // MAC (issue #318). Both the main process and the worker derive the same
    // auth key from this file, so the worker cannot start without it.
    security.secrets.master_key_file = merovingian::tests::master_key_file();

    auto fw = FederationWorkerConfig{};
    fw.shards = 2U;
    fw.threads = 1U;
    fw.request_timeout_seconds = 10U;
    // Default: existing scenarios run the worker WITHOUT the seccomp filter so
    // they do not regress if the worker allowlist is incomplete. The hardened
    // scenario below sets this true to validate the worker runs under the filter.
    fw.apply_hardening = false;

    return Config{server, ListenersConfig{}, database, security, ClientRateLimitsConfig{}, LogModulesConfig{}, fw};
}

auto write_worker_config(std::filesystem::path const& path, Config const& config) -> void
{
    // The worker config parser expects key=value with no surrounding quotes.
    auto content = std::string{};
    content += "server.name=" + config.server().server_name + "\n";
    content += "server.public_baseurl=" + config.server().public_baseurl + "\n";
    content += "database.backend=sqlite\n";
    content += "database.sqlite_path=" + config.database().sqlite_path + "\n";
    content += "database.role=runtime\n";
    content += "security.federation.enabled=true\n";
    content += "security.secrets.master_key_file=" + config.security().secrets.master_key_file + "\n";
    content += "federation.worker.shards=" + std::to_string(config.federation_worker().shards) + "\n";
    content += "federation.worker.threads=" + std::to_string(config.federation_worker().threads) + "\n";
    content += "federation.worker.request_timeout_seconds=" +
               std::to_string(config.federation_worker().request_timeout_seconds) + "\n";
    // Emit the apply_hardening flag so scenarios that opt into the worker
    // seccomp filter (issue #319) get it; the default config sets it false so
    // the bulk of scenarios run the worker unfiltered and do not regress.
    content += "federation.worker.apply_hardening=";
    content += config.federation_worker().apply_hardening ? "true" : "false";
    content += "\n";
    write_file(path, content);
}

[[nodiscard]] auto make_fed_request(std::string method, std::string target, std::string body = {}) -> LocalHttpRequest
{
    auto request = LocalHttpRequest{};
    request.method = std::move(method);
    request.target = std::move(target);
    request.body = std::move(body);
    request.remote_addr = "203.0.113.1";
    return request;
}

[[nodiscard]] auto wait_for_worker(WorkerPool& pool, std::chrono::seconds timeout) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while (!pool.healthy() && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    return pool.healthy();
}

} // namespace

SCENARIO("The federation worker pool starts real worker processes and routes non-room requests",
         "[integration][federation-worker][routing]")
{
    GIVEN("a temporary config and a started main runtime")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-flow");
        auto config = make_federation_worker_config(tmp_dir);
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a WorkerPool is constructed with the real worker binary and two shards")
        {
            auto pool = WorkerPool{config.federation_worker(), runtime, std::string{worker_binary_path()},
                                   config_path.string()};

            THEN("the pool eventually reports all shards healthy")
            {
                REQUIRE(wait_for_worker(pool, std::chrono::seconds{10}));
            }

            AND_WHEN("a non-room federation request is forwarded through the pool")
            {
                auto request = make_fed_request("GET", "/_matrix/federation/v1/query/profile?user_id=@x:y");
                auto response = LocalHttpResponse{};
                auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
                do
                {
                    response = pool.handle(request, "");
                } while (response.status == 503U && std::chrono::steady_clock::now() < deadline);

                THEN("the worker processes the request (any non-503 status proves routing worked)")
                {
                    REQUIRE(response.status != 503U);
                    REQUIRE_FALSE(response.body.find("M_UNAVAILABLE") != std::string::npos);
                }
            }
        }
    }
}

SCENARIO("Room-scoped federation requests are routed to the correct shard",
         "[integration][federation-worker][routing][sharding]")
{
    GIVEN("a two-shard worker pool backed by real worker processes")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-shard");
        auto config = make_federation_worker_config(tmp_dir);
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("room IDs map to different shards")
        {
            auto pool = WorkerPool{config.federation_worker(), runtime, std::string{worker_binary_path()},
                                   config_path.string()};
            REQUIRE(wait_for_worker(pool, std::chrono::seconds{10}));

            auto const room_a = std::string{"!shard-a:test.example.org"};
            auto const room_b = std::string{"!shard-b:test.example.org"};
            auto const shard_a = pool.shard_for(federation_worker_room_id_from_request(
                make_fed_request("GET", "/_matrix/federation/v1/state/" + room_a)));
            auto const shard_b = pool.shard_for(federation_worker_room_id_from_request(
                make_fed_request("GET", "/_matrix/federation/v1/state/" + room_b)));

            THEN("each room ID lands on a valid shard index")
            {
                REQUIRE(shard_a < config.federation_worker().shards);
                REQUIRE(shard_b < config.federation_worker().shards);
            }
        }
    }
}

SCENARIO("Federation requests fall back to in-process handling when the worker pool is stopped",
         "[integration][federation-worker][fallback]")
{
    GIVEN("a running worker pool and a started main runtime")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-fallback");
        auto config = make_federation_worker_config(tmp_dir);
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto pool =
            WorkerPool{config.federation_worker(), runtime, std::string{worker_binary_path()}, config_path.string()};
        REQUIRE(wait_for_worker(pool, std::chrono::seconds{10}));

        WHEN("the worker pool is stopped")
        {
            pool.stop();

            AND_WHEN("a federation request is forwarded through the stopped pool")
            {
                auto const request = make_fed_request("GET", "/_matrix/federation/v1/query/profile?user_id=@x:y");
                auto const response = pool.handle(request, "");

                THEN("the pool reports the worker as unavailable")
                {
                    REQUIRE(response.status == 503U);
                    REQUIRE(response.body.find("M_UNAVAILABLE") != std::string::npos);
                }
            }

            AND_WHEN("the caller falls back to in-process federation handling")
            {
                auto const request = make_fed_request("GET", "/_matrix/federation/v1/query/profile?user_id=@x:y");
                auto const response = handle_federation_http_request(runtime, request);

                THEN("the main runtime processes the request directly")
                {
                    REQUIRE(response.status != 503U);
                }
            }
        }
    }
}

SCENARIO("Room-scoped federation requests are processed by the worker pool",
         "[integration][federation-worker][routing]")
{
    GIVEN("a running two-shard worker pool and a started main runtime")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-room");
        auto config = make_federation_worker_config(tmp_dir);
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto pool =
            WorkerPool{config.federation_worker(), runtime, std::string{worker_binary_path()}, config_path.string()};
        REQUIRE(wait_for_worker(pool, std::chrono::seconds{10}));

        WHEN("a room-scoped state request is routed through the pool")
        {
            auto const room_id = std::string{"!nonexistent-room:example.com"};
            auto const request = make_fed_request("GET", "/_matrix/federation/v1/state/" + room_id);
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};

            auto response = LocalHttpResponse{};
            do
            {
                response = pool.handle(request, room_id);
            } while (response.status == 503U && std::chrono::steady_clock::now() < deadline);

            THEN("the worker processes the request without returning the unavailable code")
            {
                REQUIRE(response.status != 503U);
                REQUIRE_FALSE(response.body.find("M_UNAVAILABLE") != std::string::npos);
            }
        }
    }
}

SCENARIO("PUT /send transactions are routed to a worker and receive a JSON response",
         "[integration][federation-worker][routing][send]")
{
    GIVEN("a running two-shard worker pool and a started main runtime")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-send");
        auto config = make_federation_worker_config(tmp_dir);
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto pool =
            WorkerPool{config.federation_worker(), runtime, std::string{worker_binary_path()}, config_path.string()};
        REQUIRE(wait_for_worker(pool, std::chrono::seconds{10}));

        WHEN("a /send/{txnId} request with a minimal PDU body is routed through the pool")
        {
            auto const room_id = std::string{"!send-room:example.com"};
            auto const pdu = std::string{"{\"room_id\":\""} + room_id +
                             std::string{"\",\"event_id\":\"$x:remote.example\",\"type\":\"m.room.message\"}"};
            auto const body = std::string{"{\"origin\":\"remote.example\",\"origin_server_ts\":1234,\"pdus\":["} + pdu +
                              std::string{"]}"};
            auto const request = make_fed_request("PUT", "/_matrix/federation/v1/send/txn-test", body);
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};

            auto response = LocalHttpResponse{};
            do
            {
                response = pool.handle(request, room_id);
            } while (response.status == 503U && std::chrono::steady_clock::now() < deadline);

            THEN("the worker processes the transaction and returns a parsed JSON response")
            {
                REQUIRE(response.status != 503U);
                REQUIRE_FALSE(response.body.empty());
            }
        }
    }
}

SCENARIO("WorkerPool routes outbound HTTP requests through the federation worker IPC channel",
         "[integration][federation-worker][outbound][ipc]")
{
    GIVEN("a running two-shard worker pool backed by real worker processes")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-outbound");
        auto config = make_federation_worker_config(tmp_dir);
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto pool =
            WorkerPool{config.federation_worker(), runtime, std::string{worker_binary_path()}, config_path.string()};
        REQUIRE(wait_for_worker(pool, std::chrono::seconds{10}));

        WHEN("an outbound HTTP request is dispatched to a connection-refused local address")
        {
            // Use loopback port 9 (discard), which is almost always closed —
            // the TCP stack returns ECONNREFUSED immediately with no network I/O.
            // We pin the address explicitly so libcurl never tries DNS.
            auto request = OutboundRequest{};
            request.method = "GET";
            request.url = "https://fed-worker-outbound-test.local:9/_matrix/key/v2/server";
            request.pinned_addresses = {"fed-worker-outbound-test.local:9:127.0.0.1"};
            request.connect_timeout_seconds = 5U;
            request.total_timeout_seconds = 5U;

            auto const result = pool.send_outbound_request(request, "!room:test.example.com");

            THEN("the IPC round-trip completes and the worker reports a network failure")
            {
                // The connection to 127.0.0.1:9 must be refused. We don't
                // assert the exact error code because it varies by platform and
                // TLS layer, but the request must not succeed and must not hang.
                REQUIRE_FALSE(result.ok);
            }
        }

        AND_WHEN("the same outbound request is dispatched for a different room on the other shard")
        {
            auto request = OutboundRequest{};
            request.method = "GET";
            request.url = "https://fed-worker-outbound-test.local:9/_matrix/key/v2/server";
            request.pinned_addresses = {"fed-worker-outbound-test.local:9:127.0.0.1"};
            request.connect_timeout_seconds = 5U;
            request.total_timeout_seconds = 5U;

            // Use a different room ID so the FNV-1a hash routes to the other shard.
            auto const result_shard_b = pool.send_outbound_request(request, "!other-room:test.example.com");

            THEN("the second shard also completes the IPC round-trip and reports failure")
            {
                REQUIRE_FALSE(result_shard_b.ok);
            }
        }
    }
}

SCENARIO("WorkerPool send_outbound_request returns failure immediately after the pool is stopped",
         "[federation][worker-pool][outbound][resilience]")
{
    GIVEN("a healthy worker pool that is then stopped")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-stopped");
        auto config = make_federation_worker_config(tmp_dir);
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto pool =
            WorkerPool{config.federation_worker(), runtime, std::string{worker_binary_path()}, config_path.string()};
        REQUIRE(wait_for_worker(pool, std::chrono::seconds{10}));

        // Stop the pool so workers_ is emptied. Any subsequent call must fail
        // fast from the index >= workers_.size() guard without IPC.
        pool.stop();

        WHEN("an outbound request is dispatched through the stopped pool")
        {
            auto request = OutboundRequest{};
            request.method = "GET";
            request.url = "https://remote.example.com:8448/_matrix/key/v2/server";
            request.pinned_addresses = {"remote.example.com:8448:203.0.113.1"};
            request.connect_timeout_seconds = 5U;
            request.total_timeout_seconds = 5U;

            auto const result = pool.send_outbound_request(request, "!room:remote.example.com");

            THEN("the call fails immediately and returns a non-empty error detail")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.error_detail.empty());
            }
        }
    }
}

SCENARIO("FederationProxy delegates outbound HTTP requests to the worker pool via IPC",
         "[integration][federation-proxy][outbound][ipc]")
{
    GIVEN("a FederationProxy wrapping a healthy two-shard worker pool")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-proxy-outbound");
        auto config = make_federation_worker_config(tmp_dir);
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto proxy = FederationProxy{config.federation_worker(), runtime, std::string{worker_binary_path()},
                                     config_path.string()};

        // Give workers a moment to complete key exchange before sending.
        std::this_thread::sleep_for(std::chrono::seconds{2});

        WHEN("an outbound HTTP request is dispatched through the proxy to an unreachable address")
        {
            auto request = OutboundRequest{};
            request.method = "GET";
            request.url = "https://fed-proxy-outbound-test.local:9/_matrix/key/v2/server";
            request.pinned_addresses = {"fed-proxy-outbound-test.local:9:127.0.0.1"};
            request.connect_timeout_seconds = 5U;
            request.total_timeout_seconds = 5U;

            auto const result = proxy.send_outbound_request(request, "!room:test.example.com");

            THEN("the proxy forwards the request through IPC and returns a network failure")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("The federation worker starts and serves a request under the worker seccomp filter",
         "[integration][federation-worker][hardening][seccomp]")
{
    GIVEN("a config that enables the worker runtime hardening sequence (issue #319)")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }
#ifdef __SANITIZE_THREAD__
        // ThreadSanitizer needs syscalls the strict worker filter may not
        // enumerate; the startup-hardening tests skip under TSan for the same
        // reason. The allowlist itself is validated in unit tests.
        SKIP("worker seccomp scenario skipped under ThreadSanitizer");
#endif

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-hardened");
        auto config = make_federation_worker_config(tmp_dir);
        config.federation_worker().apply_hardening = true;
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a WorkerPool is constructed with the hardened worker binary")
        {
            auto pool = WorkerPool{config.federation_worker(), runtime, std::string{worker_binary_path()},
                                   config_path.string()};

            THEN("the worker installs the filter and still reaches healthy")
            {
                // If the worker allowlist were incomplete the child would be
                // killed by SECCOMP_RET_KILL_PROCESS at startup and the pool
                // would never go healthy, failing here rather than hanging.
                REQUIRE(wait_for_worker(pool, std::chrono::seconds{15}));
            }

            AND_WHEN("a non-room federation request is forwarded through the hardened worker")
            {
                auto request = make_fed_request("GET", "/_matrix/federation/v1/query/profile?user_id=@x:y");
                auto response = LocalHttpResponse{};
                auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
                do
                {
                    response = pool.handle(request, "");
                } while (response.status == 503U && std::chrono::steady_clock::now() < deadline);

                THEN("the worker handles the request end-to-end under the filter (any non-503 status)")
                {
                    REQUIRE(response.status != 503U);
                }
            }
        }
    }
}
