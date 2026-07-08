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
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/federation_request_routing.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/worker_pool.hpp"
#include "merovingian/homeserver/worker_supervisor.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/ipc/channel.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <thread>

#include <sodium.h>
#include <sys/socket.h>

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
using merovingian::homeserver::WorkerSupervisor;
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
    content += "federation.worker.relay_threads=" + std::to_string(config.federation_worker().relay_threads) + "\n";
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

[[nodiscard]] auto wait_for_healthy(FederationProxy& proxy, std::chrono::seconds timeout) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while (!proxy.healthy() && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    return proxy.healthy();
}

// Mirrors ipc::ipc_json_str's escaping for a JSON string embedded inside one
// of the *_ingest wire frames built by hand in this file's scenarios — the
// same escaping every *_ingest scenario below needs for its embedded event/
// content JSON.
[[nodiscard]] auto ipc_escape_json_string(std::string_view raw) -> std::string
{
    auto escaped = std::string{'"'};
    for (auto const ch : raw)
    {
        if (ch == '"' || ch == '\\')
        {
            escaped += '\\';
        }
        escaped += ch;
    }
    escaped += '"';
    return escaped;
}

// The scenarios above all call handle_edu_ingest_request()/handle_*_ingest_request()
// directly, in-process — none of them actually send bytes over the encrypted
// AF_UNIX channel a real worker uses. That leaves one layer of the production
// path completely untested: whether a large, deeply nested EDU payload
// survives serialize -> AEAD-encrypt -> frame -> decrypt -> deserialize on a
// *real* ipc::IpcChannel pair, the same transport worker_event_loop.cpp's
// edu_sink override and worker_pool.cpp's request handler actually use. This
// mirrors test_ipc_framing.cpp's socketpair/channel-pair fixture (not shared
// via tests/support/ per its own rule that I/O helpers don't belong there).
struct IpcTestSocketPair final
{
    merovingian::core::FileDescriptor server_fd{};
    merovingian::core::FileDescriptor client_fd{};
};

[[nodiscard]] auto make_ipc_test_socketpair() -> IpcTestSocketPair
{
    auto fds = std::array<int, 2>{-1, -1};
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()) == 0);
    return {merovingian::core::FileDescriptor{fds[0]}, merovingian::core::FileDescriptor{fds[1]}};
}

struct IpcTestChannelPair final
{
    std::unique_ptr<merovingian::ipc::IpcChannel> server{};
    std::unique_ptr<merovingian::ipc::IpcChannel> client{};
};

// Constructs a server and client IpcChannel concurrently — required because
// the constructor performs a blocking key-exchange handshake that deadlocks
// if built sequentially on one thread.
[[nodiscard]] auto make_ipc_test_channel_pair() -> IpcTestChannelPair
{
    auto [server_fd, client_fd] = make_ipc_test_socketpair();
    auto const seed = std::string_view{"fed-worker-flow-ipc-test-key"};
    auto const auth_key = merovingian::crypto::derive_ipc_auth_key(
        std::span<std::uint8_t const>{reinterpret_cast<std::uint8_t const*>(seed.data()), seed.size()});
    REQUIRE(auth_key.has_value());

    auto pair = IpcTestChannelPair{};
    auto server_ex = std::exception_ptr{};
    auto client_ex = std::exception_ptr{};

    auto t1 = std::thread{[&]() {
        try
        {
            pair.server = std::make_unique<merovingian::ipc::IpcChannel>(
                std::move(server_fd), merovingian::ipc::IpcChannel::Role::server, *auth_key);
        }
        catch (...)
        {
            server_ex = std::current_exception();
        }
    }};
    auto t2 = std::thread{[&]() {
        try
        {
            pair.client = std::make_unique<merovingian::ipc::IpcChannel>(
                std::move(client_fd), merovingian::ipc::IpcChannel::Role::client, *auth_key);
        }
        catch (...)
        {
            client_ex = std::current_exception();
        }
    }};
    t1.join();
    t2.join();

    REQUIRE(server_ex == nullptr);
    REQUIRE(client_ex == nullptr);
    REQUIRE(pair.server != nullptr);
    REQUIRE(pair.client != nullptr);
    return pair;
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

        WHEN("a request-derived shard is compared against notify_room_changed()'s own shard for the same room")
        {
            // notify_room_changed() (room_service.cpp) always hashes the plain,
            // already-decoded room_id — it never touches a URL. The federation
            // proxy instead hashes whatever federation_worker_room_id_from_request()
            // extracts from the live HTTP request. If those two ever disagree for
            // the same logical room, the room-sync notification and the inbound
            // request it's meant to serve land on different shards: the serving
            // shard's local store never learns the room exists, and every
            // room-scoped request against it 404s forever — indistinguishable
            // from real staleness (see docs/architecture.md, "Federation worker
            // room staleness") except that retries never heal it. This is the
            // actual invariant that broke in production; "lands on *a* valid
            // shard" (above) does not catch it.
            auto pool = WorkerPool{config.federation_worker(), runtime, std::string{worker_binary_path()},
                                   config_path.string()};
            REQUIRE(wait_for_worker(pool, std::chrono::seconds{10}));

            auto const room_id = std::string{"!consistency-check:test.example.org"};
            auto const notify_side_shard = pool.shard_for(room_id);

            THEN("a plain (unencoded) request path resolves to the same room ID (and therefore shard) "
                 "notify_room_changed() would use")
            {
                auto const extracted = federation_worker_room_id_from_request(make_fed_request(
                    "GET", "/_matrix/federation/v1/make_join/" + room_id + "/@user:remote.example?ver=12"));
                // Assert on the extracted string itself, not just the resulting
                // shard index: with only a handful of shards, two different
                // strings can coincidentally hash to the same bucket, which
                // would let a real mismatch slip through a shard-only check.
                REQUIRE(extracted == room_id);
                REQUIRE(pool.shard_for(extracted) == notify_side_shard);
            }

            AND_THEN("a real client's percent-encoded request path also resolves to the same room ID and shard")
            {
                // '!' -> %21, ':' -> %3A — exactly how Synapse encodes the room
                // ID in a real make_join path. This is the case that broke.
                auto const encoded_room_id = std::string{"%21consistency-check%3Atest.example.org"};
                auto const extracted = federation_worker_room_id_from_request(make_fed_request(
                    "GET", "/_matrix/federation/v1/make_join/" + encoded_room_id + "/@user:remote.example?ver=12"));
                REQUIRE(extracted == room_id);
                REQUIRE(pool.shard_for(extracted) == notify_side_shard);
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

SCENARIO("handle_membership_ingest_request persists a worker-relayed federated join to main's own store",
         "[integration][federation-worker][membership][send_join]")
{
    // This drives the actual new code from this fix — worker_pool.cpp's
    // handle_membership_ingest_request() — through its real wire format: a raw
    // JSON string shaped exactly like worker_event_loop.cpp's
    // serialize_membership_ingest() produces, in and out. Driving a real
    // send_join through a real worker subprocess end-to-end would additionally
    // require it to pass the "remote is unknown" federation-policy gate ahead
    // of membership_acceptor (src/federation/inbound_request.cpp), which needs
    // a live, network-resolvable remote signing key — orthogonal infrastructure
    // this bug isn't about. That gate is exactly why this file's *other*
    // scenarios only assert `status != 503` rather than a specific success
    // code; none of them exercise real acceptance logic either. Calling
    // handle_membership_ingest_request directly, with the same JSON a worker
    // would actually send, verifies the real claim this fix makes — that a
    // relayed acceptance persists into main's own store — without fighting
    // that unrelated gate.
    GIVEN("a resident room and a runtime with the default federation callbacks wired")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-membership");
        auto config = make_federation_worker_config(tmp_dir);
        // sqlite ":memory:" (this file's default, fine for scenarios that never
        // write) opens a brand-new, schema-less connection on every single
        // write/read call (see detail::persist_transaction_to_backend) — every
        // persistence call would silently no-op against an empty ephemeral
        // database, making this test pass vacuously. Use a real file so writes
        // and reads share the same underlying database, as they do in production.
        config.database().sqlite_path = (tmp_dir / "membership-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.membership_acceptor);

        auto const room_id = std::string{"!membership-room:example.com"};
        // membership_acceptor's only precondition is that the room exists —
        // a bare room row is enough; no create/power_levels/join_rules state is
        // required to persist a join and its m.room.member state row.
        REQUIRE(
            merovingian::database::store_room(runtime.database.persistent_store, {room_id, "@resident:example.com"}));

        WHEN("a membership_ingest request shaped like a real worker's is handled")
        {
            auto const sender = std::string{"@remote:matrix.example.org"};
            auto const event_json = std::string{R"({"room_id":")"} + room_id + R"(","sender":")" + sender +
                                    R"(","origin_server_ts":1234,"type":"m.room.member",)" + R"("state_key":")" +
                                    sender + R"(","content":{"membership":"join"}})";
            auto const request_json =
                std::string{
                    R"({"type":"membership_ingest","endpoint":"send_join","event_id":"$placeholder-event-id")"} +
                R"(,"room_id":")" + room_id + R"(","room_version":"10","sender":")" + sender +
                R"(","event_type":"m.room.member","state_key":")" + sender +
                R"(","origin_server_ts":1234,"depth":0,"auth_event_ids":[],"prev_event_ids":[],"signatures":[],)" +
                R"("json":)" +
                [&] {
                    // Mirror ipc::ipc_json_str's escaping for the embedded event JSON.
                    auto escaped = std::string{'"'};
                    for (auto const ch : event_json)
                    {
                        if (ch == '"' || ch == '\\')
                        {
                            escaped += '\\';
                        }
                        escaped += ch;
                    }
                    escaped += '"';
                    return escaped;
                }() +
                "}";

            auto const response_json = merovingian::homeserver::handle_membership_ingest_request(runtime, request_json);

            THEN("the response reports the join as accepted with a 200 status")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("accepted":true)") != std::string::npos);
                REQUIRE(response_json.find(R"("status":200)") != std::string::npos);
            }

            AND_THEN("main's own store has the new member's m.room.member state, so a later /send message from "
                     "that sender (authorized by pdu_sink against this same store) sees them as joined — the bug "
                     "this fix closes: membership_acceptor previously ran unmodified inside the worker process "
                     "instead of being relayed here, writing only to the worker's own, separate store")
            {
                auto const has_join_state = std::ranges::any_of(
                    runtime.database.persistent_store.state, [&](merovingian::database::PersistentStateEvent const& s) {
                        return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == sender;
                    });
                REQUIRE(has_join_state);

                auto const has_membership_row = std::ranges::any_of(
                    runtime.database.persistent_store.memberships,
                    [&](merovingian::database::PersistentMembership const& m) {
                        return m.room_id == room_id && m.user_id == sender && m.membership == "join";
                    });
                REQUIRE(has_membership_row);
            }
        }
    }
}

SCENARIO("handle_membership_ingest_request rejects a relayed join for a room main does not have",
         "[integration][federation-worker][membership][send_join][error-paths]")
{
    // The default membership_acceptor's only precondition is that the room
    // row already exists (see local_http_router.cpp: "room not found", 404).
    // A worker relaying a send_join for a room main never learned about
    // (e.g. a stale worker snapshot, or a genuinely bogus remote request)
    // must not silently persist a member into a non-existent room.
    GIVEN("a runtime with the default federation callbacks wired and no rooms stored")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-membership-404");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "membership-404-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.membership_acceptor);

        WHEN("a membership_ingest request targets a room that was never stored")
        {
            auto const room_id = std::string{"!never-stored:example.com"};
            auto const sender = std::string{"@remote:matrix.example.org"};
            auto const event_json = std::string{R"({"room_id":")"} + room_id + R"(","sender":")" + sender +
                                    R"(","origin_server_ts":1234,"type":"m.room.member",)" + R"("state_key":")" +
                                    sender + R"(","content":{"membership":"join"}})";
            auto const request_json =
                std::string{
                    R"({"type":"membership_ingest","endpoint":"send_join","event_id":"$placeholder-event-id")"} +
                R"(,"room_id":")" + room_id + R"(","room_version":"10","sender":")" + sender +
                R"(","event_type":"m.room.member","state_key":")" + sender +
                R"(","origin_server_ts":1234,"depth":0,"auth_event_ids":[],"prev_event_ids":[],"signatures":[],)" +
                R"("json":)" + ipc_escape_json_string(event_json) + "}";

            auto const response_json = merovingian::homeserver::handle_membership_ingest_request(runtime, request_json);

            THEN("the response reports the join as rejected with a 404 status, not silently persisted")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("accepted":false)") != std::string::npos);
                REQUIRE(response_json.find(R"("status":404)") != std::string::npos);
            }

            AND_THEN("main's own store gained no membership row for the non-existent room")
            {
                auto const has_membership_row =
                    std::ranges::any_of(runtime.database.persistent_store.memberships,
                                        [&](merovingian::database::PersistentMembership const& m) {
                                            return m.room_id == room_id;
                                        });
                REQUIRE_FALSE(has_membership_row);
            }
        }
    }
}

SCENARIO("handle_membership_ingest_request reports 501 when membership_acceptor is not wired",
         "[integration][federation-worker][membership][error-paths]")
{
    // Guards the explicit fallback branch in handle_membership_ingest_request:
    // if a future refactor ever reaches main with membership_acceptor unset
    // (e.g. an ordering bug in startup wiring), the relay must fail closed
    // with a clear 501 rather than segfaulting on an empty std::function or
    // silently dropping the join.
    GIVEN("a runtime whose federation callbacks were never wired")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-membership-unwired");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "membership-unwired-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE_FALSE(runtime.federation.membership_acceptor);

        WHEN("a membership_ingest request is handled anyway")
        {
            auto const request_json = std::string{
                R"({"type":"membership_ingest","endpoint":"send_join","event_id":"$x","room_id":"!x:example.com",)"
                R"("room_version":"10","sender":"@remote:example.org","event_type":"m.room.member",)"
                R"("state_key":"@remote:example.org","origin_server_ts":1234,"depth":0,)"
                R"("auth_event_ids":[],"prev_event_ids":[],"signatures":[],"json":"{}"})"};

            auto const response_json = merovingian::homeserver::handle_membership_ingest_request(runtime, request_json);

            THEN("the response reports 501 rather than crashing or silently dropping the join")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("accepted":false)") != std::string::npos);
                REQUIRE(response_json.find(R"("status":501)") != std::string::npos);
            }
        }
    }
}

SCENARIO("handle_edu_ingest_request delivers a worker-relayed m.direct_to_device EDU to main's to-device queue",
         "[integration][federation-worker][edu][to-device][e2ee]")
{
    // Drives worker_pool.cpp's handle_edu_ingest_request() through its real
    // wire format: a raw JSON string shaped exactly like
    // worker_event_loop.cpp's serialize_edu_ingest() produces, in and out —
    // the same pattern the membership_ingest scenario above uses, and for the
    // same reason: exercising the real relay logic without needing a live
    // remote signing key to clear the federation-policy gate ahead of it.
    //
    // This pins the fix for the bug where the federation worker's edu_sink
    // was a hard no-op (`runtime.federation.edu_sink = {};`), silently
    // dropping every inbound EDU — including m.direct_to_device, the
    // transport for E2EE megolm room-key shares. A recipient whose key-share
    // transaction landed on a worker shard was left permanently unable to
    // decrypt the corresponding room event, with nothing in the server logs
    // to show why (inbound_request.cpp counts an EDU with no edu_sink
    // installed as "dispatched", not "dropped").
    GIVEN("a runtime with the default federation callbacks wired")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-edu");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "edu-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.edu_sink);

        WHEN("an edu_ingest request carrying an m.direct_to_device megolm room-key share is handled")
        {
            auto const sender = std::string{"@remote:matrix.example.org"};
            auto const target_user = std::string{"@local:example.com"};
            auto const target_device = std::string{"DEVICE1"};
            auto const content_json = std::string{R"({"sender":")"} + sender +
                                      R"(","type":"m.room_key","message_id":"m1","messages":{")" + target_user +
                                      R"(":{")" + target_device +
                                      R"(":{"algorithm":"m.megolm.v1.aes-sha2","room_id":"!room:example.com",)" +
                                      R"("session_id":"sess123","session_key":"deadbeef"}}}})";

            // Mirror ipc::ipc_json_str's escaping for the embedded content_json,
            // same as the membership_ingest scenario above does for its "json" field.
            auto const escape = [](std::string_view raw) {
                auto escaped = std::string{'"'};
                for (auto const ch : raw)
                {
                    if (ch == '"' || ch == '\\')
                    {
                        escaped += '\\';
                    }
                    escaped += ch;
                }
                escaped += '"';
                return escaped;
            };

            auto const request_json = std::string{R"({"type":"edu_ingest","edu_type":"m.direct_to_device",)"} +
                                      R"("origin":"matrix.example.org","content_json":)" + escape(content_json) + "}";

            auto const response_json = merovingian::homeserver::handle_edu_ingest_request(runtime, request_json);

            THEN("the response reports the EDU as accepted")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("status":"accepted")") != std::string::npos);
            }

            AND_THEN("the room-key share reaches main's own to-device queue for the target device — the bug this "
                     "fix closes: edu_sink was previously a hard no-op inside the worker process, so this message "
                     "would silently vanish instead of ever reaching main's PersistentStore")
            {
                auto const has_key_share =
                    std::ranges::any_of(runtime.database.persistent_store.to_device_messages,
                                        [&](merovingian::database::PersistentToDeviceMessage const& m) {
                                            return m.sender_user_id == sender && m.target_user_id == target_user &&
                                                   m.target_device_id == target_device &&
                                                   m.message_type == "m.room_key" &&
                                                   m.content_json.find("sess123") != std::string::npos;
                                        });
                REQUIRE(has_key_share);
            }
        }
    }
}

SCENARIO("handle_edu_ingest_request delivers a realistically-shaped Olm-encrypted m.direct_to_device EDU",
         "[integration][federation-worker][edu][to-device][e2ee]")
{
    // The scenario above uses a flat, small, plaintext-shaped content object
    // ({"algorithm":...,"room_id":...,"session_id":...,"session_key":...}) —
    // that is NOT what a real m.room_key share looks like on the wire. Real
    // clients always send the room key Olm-encrypted, which means the actual
    // EDU content is one level deeper and shaped like:
    //   {"algorithm":"m.olm.v1.curve25519-aes-sha2",
    //    "ciphertext":{"<curve25519 identity key>":{"body":"<b64 ciphertext>","type":1}},
    //    "sender_key":"<curve25519 identity key>"}
    // with the EDU's own "type" field being "m.room.encrypted" (not
    // "m.room_key" — the recipient only learns that after decrypting the
    // Olm ciphertext locally). This exercises that real shape end to end:
    // a nested object keyed by a dynamic base64 string, and a "body" value
    // long enough to be a real Olm ciphertext rather than a short token.
    GIVEN("a runtime with the default federation callbacks wired")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-edu-realistic");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "edu-realistic-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.edu_sink);

        WHEN("an edu_ingest request carrying an Olm-encrypted m.room.encrypted-wrapped room key is handled")
        {
            auto const sender = std::string{"@james:matrix.ping.me.uk"};
            auto const target_user = std::string{"@james:pong.ping.me.uk"};
            auto const target_device = std::string{"DEVICE1"};
            auto const identity_key = std::string{"Ca5s7Jdb83Eak12tAADQBgE0QJRyF4EC3rcWZwhaNwQ"};
            // ~2KB placeholder ciphertext body — long enough to match a real
            // Olm-encrypted payload's size, not just its alphabet.
            auto const ciphertext_body = std::string(2048U, 'A');

            auto const content_json =
                std::string{"{\"sender\":\""} + sender +
                "\",\"type\":\"m.room.encrypted\",\"message_id\":\"m1\",\"messages\":{\"" + target_user + "\":{\"" +
                target_device + "\":{\"algorithm\":\"m.olm.v1.curve25519-aes-sha2\",\"ciphertext\":{\"" + identity_key +
                "\":{\"body\":\"" + ciphertext_body + "\",\"type\":1}},\"sender_key\":\"" + identity_key + "\"}}}}";

            auto const request_json = std::string{R"({"type":"edu_ingest","edu_type":"m.direct_to_device",)"} +
                                      R"("origin":"matrix.ping.me.uk","content_json":)" +
                                      ipc_escape_json_string(content_json) + "}";

            auto const response_json = merovingian::homeserver::handle_edu_ingest_request(runtime, request_json);

            THEN("the response reports the EDU as accepted")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("status":"accepted")") != std::string::npos);
            }

            AND_THEN("the key share reaches main's own to-device queue for the target device")
            {
                auto const has_key_share =
                    std::ranges::any_of(runtime.database.persistent_store.to_device_messages,
                                        [&](merovingian::database::PersistentToDeviceMessage const& m) {
                                            return m.sender_user_id == sender && m.target_user_id == target_user &&
                                                   m.target_device_id == target_device &&
                                                   m.message_type == "m.room.encrypted" &&
                                                   m.content_json.find(ciphertext_body) != std::string::npos;
                                        });
                REQUIRE(has_key_share);
            }
        }
    }
}

SCENARIO("A realistically-shaped Olm-encrypted m.direct_to_device EDU survives a real encrypted IPC round trip",
         "[integration][federation-worker][edu][to-device][e2ee][ipc]")
{
    // Every scenario above calls handle_edu_ingest_request() (or the local
    // transaction-body-parser path in test_federation_inbound_flow.cpp)
    // in-process, as a plain function call. None of them send a single byte
    // over the real transport a worker actually uses: worker_event_loop.cpp's
    // edu_sink override serializes the envelope and calls
    // IpcChannel::send_request(), which AEAD-encrypts and frames it before it
    // ever reaches main's request handler. If a large, deeply nested payload
    // were mis-sized against the frame cap, truncated by the AEAD framing, or
    // mangled by the JSON string-escaping serialize_edu_ingest applies before
    // handing it to the channel, none of the in-process scenarios above would
    // ever catch it — they never touch that code. This scenario wires a real
    // ipc::IpcChannel pair over a real AF_UNIX socketpair (the same encrypted,
    // authenticated transport, just without a second process) and drives the
    // exact "edu_ingest" wire frame a worker would send through it end to end.
    GIVEN("a runtime with the default federation callbacks wired and a real IpcChannel pair standing in for the "
          "worker/main link")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-edu-ipc");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "edu-ipc-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.edu_sink);

        auto channels = make_ipc_test_channel_pair();
        // Mirrors worker_pool.cpp's WorkerSupervisor::set_request_handler's
        // "edu_ingest" branch: dispatch the request body to
        // handle_edu_ingest_request() against main's own runtime and send the
        // result back over the same channel.
        channels.server->set_request_handler(
            [&runtime, srv = channels.server.get()](std::uint64_t id, std::string json) {
                auto const response = merovingian::homeserver::handle_edu_ingest_request(runtime, json);
                srv->send_response(id, response);
            });
        channels.server->start();
        // The client also needs its reader thread running: send_request()
        // blocks on a condition variable that only the reader thread signals
        // when it reads a matching reply_to frame back from the server.
        // Without this, every send_request() call times out even though the
        // server processes the request and writes to the database correctly
        // — exactly the trap this scenario exists to avoid falling into.
        channels.client->start();

        WHEN("the worker side sends a real edu_ingest wire frame carrying an Olm-encrypted room-key share over the "
             "encrypted channel")
        {
            auto const sender = std::string{"@james:matrix.ping.me.uk"};
            auto const target_user = std::string{"@james:pong.ping.me.uk"};
            auto const target_device = std::string{"DEVICE1"};
            auto const identity_key = std::string{"Ca5s7Jdb83Eak12tAADQBgE0QJRyF4EC3rcWZwhaNwQ"};
            // ~2KB placeholder ciphertext body — long enough to match a real
            // Olm-encrypted payload's size, not just its alphabet.
            auto const ciphertext_body = std::string(2048U, 'A');

            auto const content_json =
                std::string{"{\"sender\":\""} + sender +
                "\",\"type\":\"m.room.encrypted\",\"message_id\":\"m1\",\"messages\":{\"" + target_user + "\":{\"" +
                target_device + "\":{\"algorithm\":\"m.olm.v1.curve25519-aes-sha2\",\"ciphertext\":{\"" + identity_key +
                "\":{\"body\":\"" + ciphertext_body + "\",\"type\":1}},\"sender_key\":\"" + identity_key + "\"}}}}";

            auto const request_json = std::string{R"({"type":"edu_ingest","edu_type":"m.direct_to_device",)"} +
                                      R"("origin":"matrix.ping.me.uk","content_json":)" +
                                      ipc_escape_json_string(content_json) + "}";

            auto const reply = channels.client->send_request(request_json, std::chrono::seconds{10});

            THEN("a reply arrives reporting the EDU as accepted")
            {
                REQUIRE(reply.has_value());
                INFO("reply: " << *reply);
                REQUIRE(reply->find(R"("status":"accepted")") != std::string::npos);
            }

            AND_THEN("the key share reaches main's own to-device queue for the target device, unmodified by the "
                     "encrypted transport")
            {
                auto const has_key_share =
                    std::ranges::any_of(runtime.database.persistent_store.to_device_messages,
                                        [&](merovingian::database::PersistentToDeviceMessage const& m) {
                                            return m.sender_user_id == sender && m.target_user_id == target_user &&
                                                   m.target_device_id == target_device &&
                                                   m.message_type == "m.room.encrypted" &&
                                                   m.content_json.find(ciphertext_body) != std::string::npos;
                                        });
                REQUIRE(has_key_share);
            }
        }

        channels.server->stop();
        channels.client->stop();
    }
}

SCENARIO("handle_edu_ingest_request rejects a malformed m.direct_to_device EDU instead of accepting it",
         "[integration][federation-worker][edu][error-paths]")
{
    // federation::parse_inbound_edu_envelope validates content_json shape per
    // EDU type before deserialize_edu_ingest ever builds an envelope (see
    // edu_content_is_valid: direct_to_device requires sender/type/messages).
    // A worker relaying a malformed EDU — or a bug in the worker's own
    // serialize_edu_ingest — must not silently succeed or reach the to-device
    // queue with garbage.
    GIVEN("a runtime with the default federation callbacks wired")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-edu-malformed");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "edu-malformed-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.edu_sink);

        WHEN("an edu_ingest request's content_json is missing the required \"messages\" field")
        {
            auto const content_json =
                std::string{R"({"sender":"@remote:matrix.example.org","type":"m.room_key","message_id":"m1"})"};
            auto const request_json = std::string{R"({"type":"edu_ingest","edu_type":"m.direct_to_device",)"} +
                                      R"("origin":"matrix.example.org","content_json":)" +
                                      ipc_escape_json_string(content_json) + "}";

            auto const response_json = merovingian::homeserver::handle_edu_ingest_request(runtime, request_json);

            THEN("the response reports the EDU as rejected_invalid, not accepted")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("status":"rejected_invalid")") != std::string::npos);
            }

            AND_THEN("nothing was written to main's to-device queue")
            {
                REQUIRE(runtime.database.persistent_store.to_device_messages.empty());
            }
        }
    }
}

SCENARIO("handle_edu_ingest_request reports rejected_invalid when edu_sink is not wired",
         "[integration][federation-worker][edu][error-paths]")
{
    GIVEN("a runtime whose federation callbacks were never wired")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-edu-unwired");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "edu-unwired-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE_FALSE(runtime.federation.edu_sink);

        WHEN("a well-formed edu_ingest request is handled anyway")
        {
            auto const content_json = std::string{
                R"({"sender":"@remote:matrix.example.org","type":"m.room_key","message_id":"m1","messages":{}})"};
            auto const request_json = std::string{R"({"type":"edu_ingest","edu_type":"m.direct_to_device",)"} +
                                      R"("origin":"matrix.example.org","content_json":)" +
                                      ipc_escape_json_string(content_json) + "}";

            auto const response_json = merovingian::homeserver::handle_edu_ingest_request(runtime, request_json);

            THEN("the response reports rejected_invalid rather than crashing or silently dropping the EDU")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("status":"rejected_invalid")") != std::string::npos);
                REQUIRE(response_json.find("edu_sink not wired") != std::string::npos);
            }
        }
    }
}

SCENARIO("handle_invite_ingest_request persists a worker-relayed federated invite to main's own store",
         "[integration][federation-worker][invite]")
{
    // Drives worker_pool.cpp's handle_invite_ingest_request() through its
    // real wire format: a raw JSON string shaped exactly like
    // worker_event_loop.cpp's serialize_invite_ingest() produces, in and out
    // — the same pattern the membership_ingest and edu_ingest scenarios
    // above use, and for the same reason: a real end-to-end PUT
    // /_matrix/federation/{v1,v2}/invite through a real worker subprocess
    // would additionally need to clear the unrelated "remote is unknown"
    // federation-policy gate ahead of invite_handler, which needs a live,
    // network-resolvable remote signing key.
    //
    // This pins the fix for the bug where invite_handler's default
    // implementation (local_http_router.cpp) persisted the invite's
    // membership row, invite metadata, and event straight into whichever
    // process's PersistentStore ran it — and since PUT /invite is
    // room-scoped, with federation.worker.shards >= 1 (the shipped example
    // config) that process is a worker, never main. A remote server's
    // invite to a local user was silently swallowed: nothing else ever
    // syncs an invite into main's store, so the invited user's own /sync
    // (served exclusively by main) never saw it.
    GIVEN("a runtime with the default federation callbacks wired and a local invitee")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-invite");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "invite-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.invite_handler);

        auto const target_user = std::string{"@local:"} + config.server().server_name;
        // invite_handler's local_user_exists() checks HomeserverRuntime::database.users
        // (the LocalUser cache) — a different vector from
        // database.persistent_store.users — so the invitee must be registered there,
        // not via database::store_user().
        runtime.database.users.push_back({target_user, "", false, false, false});

        WHEN("an invite_ingest request shaped like a real worker's is handled")
        {
            auto const room_id = std::string{"!invite-room:matrix.example.org"};
            auto const sender = std::string{"@remote:matrix.example.org"};
            auto const event_json = std::string{R"({"room_id":")"} + room_id + R"(","sender":")" + sender +
                                    R"(","origin_server_ts":1234,"type":"m.room.member",)" + R"("state_key":")" +
                                    target_user + R"(","content":{"membership":"invite"}})";

            // Mirror ipc::ipc_json_str's escaping for the embedded event JSON,
            // same as the membership_ingest scenario above does.
            auto const escape = [](std::string_view raw) {
                auto escaped = std::string{'"'};
                for (auto const ch : raw)
                {
                    if (ch == '"' || ch == '\\')
                    {
                        escaped += '\\';
                    }
                    escaped += ch;
                }
                escaped += '"';
                return escaped;
            };

            auto const request_json = std::string{R"({"type":"invite_ingest","room_id":)"} + escape(room_id) +
                                      R"(,"event_id":"$placeholder-event-id","room_version":"10",)" +
                                      R"("invite_event_json":)" + escape(event_json) +
                                      R"(,"invite_room_state_json":[]})";

            auto const response_json = merovingian::homeserver::handle_invite_ingest_request(runtime, request_json);

            THEN("the response reports the invite as accepted")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("accepted":true)") != std::string::npos);
                REQUIRE(response_json.find(R"("status":200)") != std::string::npos);
            }

            AND_THEN("main's own store has the invite's membership row and event — the bug this fix closes: "
                     "invite_handler previously ran unmodified inside the worker process instead of being relayed "
                     "here, writing only to the worker's own, separate store, so the invited user's own /sync "
                     "(served exclusively by main) never saw the invite at all")
            {
                auto const has_invite_membership = std::ranges::any_of(
                    runtime.database.persistent_store.memberships,
                    [&](merovingian::database::PersistentMembership const& m) {
                        return m.room_id == room_id && m.user_id == target_user && m.membership == "invite";
                    });
                REQUIRE(has_invite_membership);

                auto const has_invite_row = std::ranges::any_of(
                    runtime.database.persistent_store.invites, [&](merovingian::database::PersistentInvite const& i) {
                        return i.room_id == room_id && i.user_id == target_user;
                    });
                REQUIRE(has_invite_row);
            }
        }
    }
}

SCENARIO("handle_invite_ingest_request rejects a federated invite to a user this server does not host",
         "[integration][federation-worker][invite][error-paths]")
{
    // Mirrors the invite_handler branch in local_http_router.cpp: {false,
    // 404, "invited local user not found"} when the invite's target state_key
    // is not registered locally. A worker must relay this rejection through
    // main unchanged, not silently drop it or persist a membership row for a
    // user main has never heard of.
    GIVEN("a runtime with the default federation callbacks wired and no matching local invitee")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-invite-404");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "invite-404-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.invite_handler);
        // Deliberately do NOT register target_user in runtime.database.users.

        WHEN("an invite_ingest request targets a user who was never registered locally")
        {
            auto const room_id = std::string{"!invite-room-404:matrix.example.org"};
            auto const sender = std::string{"@remote:matrix.example.org"};
            auto const target_user = std::string{"@nobody:"} + config.server().server_name;
            auto const event_json = std::string{R"({"room_id":")"} + room_id + R"(","sender":")" + sender +
                                    R"(","origin_server_ts":1234,"type":"m.room.member",)" + R"("state_key":")" +
                                    target_user + R"(","content":{"membership":"invite"}})";

            auto const request_json =
                std::string{R"({"type":"invite_ingest","room_id":)"} + ipc_escape_json_string(room_id) +
                R"(,"event_id":"$placeholder-event-id","room_version":"10",)" + R"("invite_event_json":)" +
                ipc_escape_json_string(event_json) + R"(,"invite_room_state_json":[]})";

            auto const response_json = merovingian::homeserver::handle_invite_ingest_request(runtime, request_json);

            THEN("the response reports the invite as rejected with a 404 status")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("accepted":false)") != std::string::npos);
                REQUIRE(response_json.find(R"("status":404)") != std::string::npos);
            }

            AND_THEN("main's own store gained no membership or invite row for the unknown user")
            {
                auto const has_membership_row =
                    std::ranges::any_of(runtime.database.persistent_store.memberships,
                                        [&](merovingian::database::PersistentMembership const& m) {
                                            return m.user_id == target_user;
                                        });
                REQUIRE_FALSE(has_membership_row);

                auto const has_invite_row = std::ranges::any_of(runtime.database.persistent_store.invites,
                                                                [&](merovingian::database::PersistentInvite const& i) {
                                                                    return i.user_id == target_user;
                                                                });
                REQUIRE_FALSE(has_invite_row);
            }
        }
    }
}

SCENARIO("handle_invite_ingest_request reports 501 when invite_handler is not wired",
         "[integration][federation-worker][invite][error-paths]")
{
    GIVEN("a runtime whose federation callbacks were never wired")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-invite-unwired");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "invite-unwired-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE_FALSE(runtime.federation.invite_handler);

        WHEN("an invite_ingest request is handled anyway")
        {
            auto const request_json =
                std::string{R"({"type":"invite_ingest","room_id":"!x:example.com","event_id":"$x","room_version":"10",)"
                            R"("invite_event_json":"{}","invite_room_state_json":[]})"};

            auto const response_json = merovingian::homeserver::handle_invite_ingest_request(runtime, request_json);

            THEN("the response reports 501 rather than crashing or silently dropping the invite")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("accepted":false)") != std::string::npos);
                REQUIRE(response_json.find(R"("status":501)") != std::string::npos);
            }
        }
    }
}

SCENARIO("handle_otk_claim_ingest_request decides a one-time-key claim against main's own store",
         "[integration][federation-worker][e2ee][otk]")
{
    // Drives worker_pool.cpp's handle_otk_claim_ingest_request() through its
    // real wire format, the same pattern the other *_ingest scenarios in
    // this file use.
    //
    // This pins the fix for the bug where one_time_keys_claim_provider's
    // default implementation (local_http_router.cpp) decided key
    // availability from PersistentStore::one_time_keys — a per-process
    // in-memory snapshot hydrated once at worker startup — before issuing a
    // DELETE. Two independent processes (main and a worker, or two workers)
    // could each believe the same key was still available and both return
    // it to their own caller, reusing an Olm one-time prekey. Routing every
    // claim through main's single authoritative copy via a new
    // otk_claim_ingest IPC call removes that split-brain.
    GIVEN("a runtime with the default federation callbacks wired and a one-time key on a local device")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-otk");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "otk-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.one_time_keys_claim_provider);

        auto const user_id = std::string{"@local:"} + config.server().server_name;
        auto const device_id = std::string{"DEVICE1"};
        auto const key_id = std::string{"signed_curve25519:AAAAAA"};
        REQUIRE(merovingian::database::store_one_time_key(
            runtime.database.persistent_store, {user_id, device_id, key_id, R"({"key":"fakeCurve25519KeyMaterial"})"}));

        WHEN("an otk_claim_ingest request shaped like a real worker's is handled")
        {
            auto const claim_request_body =
                std::string{R"({"one_time_keys":{")"} + user_id + R"(":{")" + device_id + R"(":"signed_curve25519"}}})";

            // Mirror ipc::ipc_json_str's escaping, same as the other scenarios above.
            auto const escape = [](std::string_view raw) {
                auto escaped = std::string{'"'};
                for (auto const ch : raw)
                {
                    if (ch == '"' || ch == '\\')
                    {
                        escaped += '\\';
                    }
                    escaped += ch;
                }
                escaped += '"';
                return escaped;
            };

            auto const request_json =
                std::string{R"({"type":"otk_claim_ingest","request_body":)"} + escape(claim_request_body) + "}";

            auto const response_json = merovingian::homeserver::handle_otk_claim_ingest_request(runtime, request_json);

            THEN("the response echoes the claimed key back for the requested device")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(device_id) != std::string::npos);
                REQUIRE(response_json.find("fakeCurve25519KeyMaterial") != std::string::npos);
            }

            AND_THEN("the key is gone from main's own store — the bug this fix closes: a worker claiming a key "
                     "locally deleted it only from its own snapshot, so main (or another worker) could still "
                     "believe the same key was available and hand it out a second time")
            {
                auto const still_present = std::ranges::any_of(
                    runtime.database.persistent_store.one_time_keys,
                    [&](merovingian::database::PersistentOneTimeKey const& k) {
                        return k.user_id == user_id && k.device_id == device_id && k.key_id == key_id;
                    });
                REQUIRE_FALSE(still_present);
            }
        }
    }
}

SCENARIO("handle_otk_claim_ingest_request cannot reissue a one-time key a prior claim already consumed",
         "[integration][federation-worker][e2ee][otk][error-paths]")
{
    // This is the actual split-brain scenario 0.10.21 closes, driven entirely
    // through the ingest entry point rather than two racing processes: the
    // first claim must consume the key from main's single store so an
    // immediately following second claim for the identical (user, device,
    // algorithm) gets nothing back. Before the fix, two independent
    // processes each holding their own PersistentStore snapshot could both
    // answer such a pair of claims with the same key material; routing both
    // claims through this one function against one store is what prevents it.
    GIVEN("a runtime with a single one-time key already claimed once via otk_claim_ingest")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-otk-doubleclaim");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "otk-doubleclaim-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.one_time_keys_claim_provider);

        auto const user_id = std::string{"@local:"} + config.server().server_name;
        auto const device_id = std::string{"DEVICE1"};
        auto const key_id = std::string{"signed_curve25519:AAAAAA"};
        REQUIRE(merovingian::database::store_one_time_key(
            runtime.database.persistent_store, {user_id, device_id, key_id, R"({"key":"fakeCurve25519KeyMaterial"})"}));

        auto const claim_request_body =
            std::string{R"({"one_time_keys":{")"} + user_id + R"(":{")" + device_id + R"(":"signed_curve25519"}}})";
        auto const request_json = std::string{R"({"type":"otk_claim_ingest","request_body":)"} +
                                  ipc_escape_json_string(claim_request_body) + "}";

        auto const first_response = merovingian::homeserver::handle_otk_claim_ingest_request(runtime, request_json);
        REQUIRE(first_response.find("fakeCurve25519KeyMaterial") != std::string::npos);

        WHEN("a second otk_claim_ingest request for the same user/device/algorithm is handled immediately after")
        {
            auto const second_response =
                merovingian::homeserver::handle_otk_claim_ingest_request(runtime, request_json);

            THEN("no key material is returned — the one-time key was already consumed by the first claim")
            {
                INFO("response: " << second_response);
                REQUIRE(second_response.find("fakeCurve25519KeyMaterial") == std::string::npos);
                REQUIRE(second_response.find(device_id) == std::string::npos);
            }
        }
    }
}

SCENARIO("handle_otk_claim_ingest_request returns no keys when the requested device has none available",
         "[integration][federation-worker][e2ee][otk][error-paths]")
{
    GIVEN("a runtime with the default federation callbacks wired and no one-time keys stored for the device")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-otk-none");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "otk-none-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.one_time_keys_claim_provider);

        auto const user_id = std::string{"@local:"} + config.server().server_name;
        auto const device_id = std::string{"DEVICE-WITH-NO-KEYS"};

        WHEN("an otk_claim_ingest request is handled for a device with no stored one-time or fallback key")
        {
            auto const claim_request_body =
                std::string{R"({"one_time_keys":{")"} + user_id + R"(":{")" + device_id + R"(":"signed_curve25519"}}})";
            auto const request_json = std::string{R"({"type":"otk_claim_ingest","request_body":)"} +
                                      ipc_escape_json_string(claim_request_body) + "}";

            auto const response_json = merovingian::homeserver::handle_otk_claim_ingest_request(runtime, request_json);

            THEN("the response body carries an empty one_time_keys object rather than an error or crash")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"(\"one_time_keys\":{}})") != std::string::npos);
            }
        }
    }
}

SCENARIO("handle_user_devices_ingest_request reads a device list from main's own store",
         "[integration][federation-worker][e2ee][query-relay]")
{
    // Drives worker_pool.cpp's handle_user_devices_ingest_request() through
    // its real wire format, the same pattern the *_ingest scenarios above
    // use.
    //
    // This pins the fix for the bug where user_devices_provider's default
    // implementation (local_http_router.cpp) read PersistentStore::
    // device_keys — a per-process in-memory snapshot hydrated once at worker
    // startup — with no mechanism to ever refresh it, since GET
    // /_matrix/federation/v1/user/devices/{userId} carries no room ID for
    // room_sync to key off. A device whose keys were uploaded through main
    // after a worker started was therefore permanently invisible to that
    // worker, returning a spurious 404 for a device that genuinely exists.
    // Routing the query through main's single authoritative copy via a new
    // user_devices_ingest IPC call removes the staleness structurally.
    GIVEN("a runtime with the default federation callbacks wired and a device key stored on main's own store")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-user-devices");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "user-devices-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.user_devices_provider);

        auto const user_id = std::string{"@local:"} + config.server().server_name;
        auto const device_id = std::string{"DEVICE1"};
        REQUIRE(merovingian::database::store_device_key(
            runtime.database.persistent_store,
            {user_id, device_id, R"({"algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{}})"}));

        WHEN("a user_devices_ingest request shaped like a real worker's is handled")
        {
            auto const request_json =
                std::string{R"({"type":"user_devices_ingest","user_id":)"} + ipc_escape_json_string(user_id) + "}";

            auto const response_json =
                merovingian::homeserver::handle_user_devices_ingest_request(runtime, request_json);

            THEN("the response reflects main's own store rather than an empty worker-local snapshot")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(device_id) != std::string::npos);
            }
        }
    }
}

SCENARIO("handle_device_keys_query_ingest_request reads device keys from main's own store",
         "[integration][federation-worker][e2ee][query-relay]")
{
    // Same stale-snapshot failure mode as handle_user_devices_ingest_request
    // above, for POST /_matrix/federation/v1/user/keys/query instead of
    // GET /user/devices/{userId}.
    GIVEN("a runtime with the default federation callbacks wired and a device key stored on main's own store")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-device-keys-query");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "device-keys-query-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.device_keys_query_provider);

        auto const user_id = std::string{"@local:"} + config.server().server_name;
        auto const device_id = std::string{"DEVICE1"};
        REQUIRE(merovingian::database::store_device_key(
            runtime.database.persistent_store,
            {user_id, device_id, R"({"algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{}})"}));

        WHEN("a device_keys_query_ingest request shaped like a real worker's is handled")
        {
            auto const query_request_body = std::string{R"({"device_keys":{")"} + user_id + R"(":[]}})";
            auto const request_json = std::string{R"({"type":"device_keys_query_ingest","request_body":)"} +
                                      ipc_escape_json_string(query_request_body) + "}";

            auto const response_json =
                merovingian::homeserver::handle_device_keys_query_ingest_request(runtime, request_json);

            THEN("the response reflects main's own store rather than an empty worker-local snapshot")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(device_id) != std::string::npos);
            }
        }
    }
}

SCENARIO("handle_profile_query_ingest_request reads a profile from main's own store",
         "[integration][federation-worker][query-relay]")
{
    // Same stale-snapshot failure mode as handle_user_devices_ingest_request
    // above, for GET /_matrix/federation/v1/query/profile: PersistentStore::
    // profiles is likewise a worker-startup snapshot never refreshed by a
    // later client-server profile update on main.
    GIVEN("a runtime with the default federation callbacks wired and a profile stored on main's own store")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-profile-query");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "profile-query-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.profile_query_provider);

        auto const user_id = std::string{"@local:"} + config.server().server_name;
        REQUIRE(merovingian::database::store_profile(runtime.database.persistent_store,
                                                     {user_id, "Test Display Name", "mxc://example.com/avatar"}));

        WHEN("a profile_query_ingest request shaped like a real worker's is handled")
        {
            auto const request_json =
                std::string{R"({"type":"profile_query_ingest","user_id":)"} + ipc_escape_json_string(user_id) + "}";

            auto const response_json =
                merovingian::homeserver::handle_profile_query_ingest_request(runtime, request_json);

            THEN("the response reflects main's own store rather than an empty worker-local snapshot")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("found":true)") != std::string::npos);
                REQUIRE(response_json.find("Test Display Name") != std::string::npos);
                REQUIRE(response_json.find("mxc://example.com/avatar") != std::string::npos);
            }
        }
    }
}

SCENARIO("handle_event_query_ingest_request reads an event from main's own store regardless of shard ownership",
         "[integration][federation-worker][query-relay]")
{
    // Drives worker_pool.cpp's handle_event_query_ingest_request() through
    // its real wire format, the same pattern the *_ingest scenarios above
    // use.
    //
    // This pins the fix for a routing-alignment bug distinct from the
    // stale-snapshot bug the three scenarios above fix: GET
    // /_matrix/federation/v1/event/{eventId} carries no room ID, so
    // room_endpoint_prefixes() cannot route it to the shard that actually
    // owns the event's room the way state/state_ids/backfill/
    // get_missing_events are — it always lands on shard 0. A shard that
    // never received that room's room_sync notifications (because it isn't
    // the hash-selected owner) would 404 for an event that genuinely exists
    // on the shard that does own the room. Relaying through main — which
    // receives every event via pdu_sink regardless of which shard accepted
    // it — answers correctly no matter which shard the request lands on.
    GIVEN("a runtime with the default federation callbacks wired and an event stored on main's own store")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-event-query");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "event-query-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.event_query_provider);

        auto const event_id = std::string{"$eventquerytest:"} + config.server().server_name;
        auto const room_id = std::string{"!room:"} + config.server().server_name;
        REQUIRE(merovingian::database::store_event(
            runtime.database.persistent_store,
            {event_id, room_id, std::string{"@sender:"} + config.server().server_name,
             R"({"type":"m.room.message","content":{"body":"event-query-relay-marker"}})"}));

        WHEN("an event_query_ingest request shaped like a real worker's is handled")
        {
            auto const request_json =
                std::string{R"({"type":"event_query_ingest","event_id":)"} + ipc_escape_json_string(event_id) + "}";

            auto const response_json =
                merovingian::homeserver::handle_event_query_ingest_request(runtime, request_json);

            THEN("the response reflects main's own store rather than an empty worker-local snapshot")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find("event-query-relay-marker") != std::string::npos);
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
        REQUIRE(wait_for_healthy(proxy, std::chrono::seconds{15}));

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

SCENARIO("WorkerSupervisor::stop() returns promptly when the worker is healthy",
         "[integration][federation-worker][supervisor][lifecycle]")
{
    GIVEN("a running real worker supervised directly")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-stop");
        auto config = make_federation_worker_config(tmp_dir);
        config.federation_worker().request_timeout_seconds = 2U;
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);

        auto supervisor = WorkerSupervisor{std::string{worker_binary_path()}, config_path.string(),
                                           config.federation_worker().request_timeout_seconds, 0U,
                                           config.security().secrets.master_key_file};
        supervisor.start();

        auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{15};
        while (!supervisor.healthy() && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        REQUIRE(supervisor.healthy());
        REQUIRE(supervisor.worker_pid() > 0);

        WHEN("stop() is called on a healthy worker")
        {
            auto const stop_start = std::chrono::steady_clock::now();
            supervisor.stop();
            auto const stop_elapsed = std::chrono::steady_clock::now() - stop_start;

            THEN("stop() returns within a bounded time and the supervisor is no longer healthy")
            {
                // Two timeout windows: graceful wait + SIGTERM escalation. Anything
                // orders of magnitude beyond that means the old infinite-waitpid bug
                // has regressed.
                REQUIRE(stop_elapsed < std::chrono::seconds{10});
                REQUIRE_FALSE(supervisor.healthy());
                REQUIRE(supervisor.worker_pid() == -1);
            }
        }
    }
}

SCENARIO("WorkerSupervisor restarts an unexpectedly exited worker with exponential backoff",
         "[integration][federation-worker][supervisor][lifecycle]")
{
    GIVEN("a running real worker supervised directly")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-restart");
        auto config = make_federation_worker_config(tmp_dir);
        config.federation_worker().request_timeout_seconds = 2U;
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);

        auto supervisor = WorkerSupervisor{std::string{worker_binary_path()}, config_path.string(),
                                           config.federation_worker().request_timeout_seconds, 0U,
                                           config.security().secrets.master_key_file};
        supervisor.start();

        auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{15};
        while (!supervisor.healthy() && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        REQUIRE(supervisor.healthy());

        auto const original_pid = supervisor.worker_pid();
        REQUIRE(original_pid > 0);

        WHEN("the worker process is killed unexpectedly")
        {
            std::ignore = ::kill(original_pid, SIGKILL);

            THEN("the supervisor eventually reaps the old process, restarts the worker, and becomes healthy again")
            {
                auto const restart_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
                while (supervisor.worker_pid() == original_pid && std::chrono::steady_clock::now() < restart_deadline)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{50});
                }
                REQUIRE(supervisor.worker_pid() != original_pid);

                while (!supervisor.healthy() && std::chrono::steady_clock::now() < restart_deadline)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{50});
                }
                REQUIRE(supervisor.healthy());

                supervisor.stop();
                REQUIRE_FALSE(supervisor.healthy());
                REQUIRE(supervisor.worker_pid() == -1);
            }
        }
    }
}

SCENARIO("WorkerSupervisor::stop() escalates to SIGKILL when the worker ignores shutdown",
         "[integration][federation-worker][supervisor][lifecycle]")
{
    GIVEN("a running real worker supervised directly")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-stop-kill");
        auto config = make_federation_worker_config(tmp_dir);
        config.federation_worker().request_timeout_seconds = 2U;
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);

        auto started = start_runtime(config);
        REQUIRE(started.started);

        auto supervisor = WorkerSupervisor{std::string{worker_binary_path()}, config_path.string(),
                                           config.federation_worker().request_timeout_seconds, 0U,
                                           config.security().secrets.master_key_file};
        supervisor.start();

        auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{15};
        while (!supervisor.healthy() && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        REQUIRE(supervisor.healthy());

        auto const pid = supervisor.worker_pid();
        REQUIRE(pid > 0);

        WHEN("the worker is frozen with SIGSTOP so it cannot respond to the graceful shutdown notification")
        {
            std::ignore = ::kill(pid, SIGSTOP);

            THEN("stop() still returns within a bounded time after escalating to SIGKILL")
            {
                auto const stop_start = std::chrono::steady_clock::now();
                supervisor.stop();
                auto const stop_elapsed = std::chrono::steady_clock::now() - stop_start;

                REQUIRE(stop_elapsed < std::chrono::seconds{10});
                REQUIRE_FALSE(supervisor.healthy());
                REQUIRE(supervisor.worker_pid() == -1);
            }
        }
    }
}
