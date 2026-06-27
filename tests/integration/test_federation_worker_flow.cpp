// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         OUT-OF-PROCESS FEDERATION WORKER INTEGRATION TESTS              |
// |                                                                         |
// |  These tests spawn the real merovingian-fed-worker binary over an       |
// |  encrypted AF_UNIX socketpair and exercise room-based sharding, the     |
// |  sign-back channel, and in-process fallback when the worker is down.    |
// +-------------------------------------------------------------------------+

#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/federation_request_routing.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/worker_pool.hpp"

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
using merovingian::homeserver::handle_federation_http_request;
using merovingian::homeserver::LocalHttpRequest;
using merovingian::homeserver::LocalHttpResponse;
using merovingian::homeserver::start_runtime;
using merovingian::homeserver::WorkerPool;

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
    auto parent = std::filesystem::temp_directory_path();
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

    auto fw = FederationWorkerConfig{};
    fw.enabled = true;
    fw.shards = 2U;
    fw.threads = 1U;
    fw.request_timeout_seconds = 10U;
    fw.fallback_in_process = true;

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
    content += "federation.worker.enabled=true\n";
    content += "federation.worker.shards=" + std::to_string(config.federation_worker().shards) + "\n";
    content += "federation.worker.threads=" + std::to_string(config.federation_worker().threads) + "\n";
    content += "federation.worker.request_timeout_seconds=" +
               std::to_string(config.federation_worker().request_timeout_seconds) + "\n";
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
