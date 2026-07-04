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
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/federation_request_routing.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/worker_pool.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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
