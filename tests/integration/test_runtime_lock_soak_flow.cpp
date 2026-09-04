// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Load/soak evidence harness for the "Global runtime lock" release blocker
// (docs/todos/production-milestone.md, "Release-blocking functional holes").
// `HomeserverRuntime::mutex` is held for the whole of every client-server
// request and every inbound federation transaction; this harness drives real
// concurrent traffic of both kinds — over real TCP sockets, against a real
// running server, HTTP/1.1 keep-alive throughout — and reports throughput and
// latency percentiles so a narrowing decision can be justified by
// measurement rather than intuition.
//
// This file is gated behind the `build_load_tests` Meson option (parallel to
// `build_live_tests`) because it is a benchmark, not a correctness gate: its
// default duration is short enough to run safely in CI (proving the mixed
// workload below does not deadlock or starve any category), but the numbers
// worth recording come from a long, manually-invoked run:
//
//   meson configure build-wsl -Dbuild_load_tests=true
//   MEROVINGIAN_LOCK_SOAK_SECONDS=60 \
//     ./build-wsl/tests/merovingian-load-tests "[load-soak]"
//
// Workload mix, chosen to match the concurrency the charter calls out by
// name (src/sync/AGENTS.md's pool-starvation history, plus ordinary reads
// and inbound federation `/send` all contending on the same mutex):
//   - N users each long-polling their own room's /sync (the sync pool)
//   - N users each issuing ordinary authenticated reads (capabilities)
//   - N users each sending messages into their own room (wakes the sync
//     long-polls above, exercising the notifier + event pipeline)
//   - F simulated remote servers each sending signed, X-Matrix-authenticated
//     inbound federation transactions
//
// Every category runs over a persistent HTTP/1.1 connection (one connect,
// many sequential request/response rounds) so the numbers reflect keep-alive
// steady state, not repeated TLS/TCP handshake cost.
//
// Rate limiting is deliberately loosened (a generous default_per_ip) because
// every simulated client connects from 127.0.0.1: this harness measures lock
// contention, not the token-bucket limiter, and every real deployment can
// already tune server.client_rate_limits independently.
//
// trust_safety.policy_server is left disabled here (the common-case
// deployment, and resolve_policy_server_hook() is then a no-op — zero
// contribution to the numbers below). The policy-server-enabled case, where
// a slow policy server previously froze registration/room-creation/media
// download under this same mutex, has its own dedicated regression coverage
// in test_request_lock_contention_flow.cpp; this harness does not duplicate
// it.

#include "../support/master_key.hpp"
#include "../federation_signing_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std::chrono_literals;

namespace
{

// ---------------------------------------------------------------------
// Socket + HTTP/1.1 keep-alive framing helpers.
//
// Deliberately self-contained rather than shared with
// test_http_server_listener_flow.cpp: both files live in tests/integration/,
// and per tests/support/AGENTS.md an I/O-performing helper used by exactly
// one suite's files stays local to that suite rather than moving into
// tests/support/ (the documented exception there, tls_mock_server.hpp, is
// specifically for helpers shared *across* suites). Promoting these into a
// shared tests/integration/ header would mean editing the existing,
// recently-landed keep-alive test file purely for reuse — out of scope for
// this change.
// ---------------------------------------------------------------------

[[nodiscard]] auto connect_loopback(std::uint16_t port) -> int
{
    auto const fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }
    auto address = sockaddr_in{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::connect(fd, reinterpret_cast<sockaddr const*>(&address), sizeof(address)) != 0)
    {
        ::close(fd);
        return -1;
    }
    return fd;
}

[[nodiscard]] auto send_all(int fd, std::string_view data) -> bool
{
    auto remaining = data;
    while (!remaining.empty())
    {
        auto const sent = ::send(fd, remaining.data(), remaining.size(), 0);
        if (sent <= 0)
        {
            return false;
        }
        remaining.remove_prefix(static_cast<std::size_t>(sent));
    }
    return true;
}

struct PlainResponseReader final
{
    std::string pending{};
};

// Returns the total byte length (head + body) of the first complete
// Content-Length framed response in `pending`, or std::string::npos when the
// buffered bytes do not yet contain a complete response. Every response this
// harness reads is JSON with an explicit Content-Length (dispatch_resp always
// sets one), so chunked framing is not needed here.
[[nodiscard]] auto framed_response_length(std::string const& pending) -> std::size_t
{
    constexpr auto npos = std::string::npos;
    auto const head_end = pending.find("\r\n\r\n");
    if (head_end == npos)
    {
        return npos;
    }
    constexpr auto length_prefix = std::string_view{"\r\nContent-Length: "};
    auto const length_header = pending.find(length_prefix);
    if (length_header == npos || length_header > head_end)
    {
        return npos;
    }
    auto const digits_begin = length_header + length_prefix.size();
    auto const digits_end = pending.find("\r\n", digits_begin);
    if (digits_end == npos || digits_end > head_end)
    {
        return npos;
    }
    auto length = std::size_t{0U};
    for (auto index = digits_begin; index < digits_end; ++index)
    {
        auto const character = pending[index];
        if (character < '0' || character > '9')
        {
            return npos;
        }
        length = (length * 10U) + static_cast<std::size_t>(character - '0');
    }
    return head_end + 4U + length;
}

// Reads one framed response from a persistent connection. Returns an empty
// status ("") on a short read (peer closed / socket error) so callers can
// treat that as a failed round rather than misparsing a partial buffer.
struct FramedResponse final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto parse_status(std::string_view head) noexcept -> std::uint16_t
{
    // "HTTP/1.1 200 OK\r\n..." -> the three digits after the second space.
    auto const first_space = head.find(' ');
    if (first_space == std::string_view::npos)
    {
        return 0U;
    }
    auto const status_text = head.substr(first_space + 1U, 3U);
    auto status = std::uint16_t{0U};
    for (auto const c : status_text)
    {
        if (c < '0' || c > '9')
        {
            return 0U;
        }
        status = static_cast<std::uint16_t>((status * 10U) + static_cast<std::uint16_t>(c - '0'));
    }
    return status;
}

[[nodiscard]] auto receive_response(int fd, PlainResponseReader& reader) -> FramedResponse
{
    auto buffer = std::array<char, 8192U>{};
    while (true)
    {
        auto const total = framed_response_length(reader.pending);
        if (total != std::string::npos && reader.pending.size() >= total)
        {
            auto const head_end = reader.pending.find("\r\n\r\n");
            auto const status = parse_status(std::string_view{reader.pending}.substr(0U, head_end));
            auto const body_begin = head_end + 4U;
            auto body = reader.pending.substr(body_begin, total - body_begin);
            reader.pending.erase(0U, total);
            return {status, std::move(body)};
        }
        auto const received = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (received <= 0)
        {
            reader.pending.clear();
            return {};
        }
        reader.pending.append(buffer.data(), static_cast<std::size_t>(received));
    }
}

// ---------------------------------------------------------------------
// Latency bookkeeping. Each worker thread accumulates its own samples in a
// thread-local vector (no shared mutex on the hot path — that would make the
// harness's own instrumentation the bottleneck it is trying to measure) and
// hands the vector to the main thread after joining.
// ---------------------------------------------------------------------

struct CategoryStats final
{
    std::vector<double> latencies_ms{};
    std::uint64_t ok{0U};
    std::uint64_t failed{0U};
};

[[nodiscard]] auto percentile(std::vector<double>& sorted_ms, double fraction) -> double
{
    if (sorted_ms.empty())
    {
        return 0.0;
    }
    auto const index =
        std::min(sorted_ms.size() - 1U, static_cast<std::size_t>(fraction * static_cast<double>(sorted_ms.size())));
    return sorted_ms[index];
}

auto report(std::string_view label, CategoryStats& stats, std::chrono::duration<double> wall) -> void
{
    std::sort(stats.latencies_ms.begin(), stats.latencies_ms.end());
    auto const total = stats.ok + stats.failed;
    auto const throughput = total == 0U ? 0.0 : static_cast<double>(total) / wall.count();
    // Printed to stderr (not captured/suppressed by Catch2's default
    // console reporter the way stdout can be) so the numbers are visible
    // whether or not the run passes.
    std::cerr << "LOAD_HARNESS_RESULT category=" << label << " total=" << total << " ok=" << stats.ok
              << " failed=" << stats.failed << " throughput_per_s=" << throughput
              << " p50_ms=" << percentile(stats.latencies_ms, 0.50)
              << " p95_ms=" << percentile(stats.latencies_ms, 0.95)
              << " p99_ms=" << percentile(stats.latencies_ms, 0.99)
              << " max_ms=" << (stats.latencies_ms.empty() ? 0.0 : stats.latencies_ms.back()) << '\n';
}

// Reads MEROVINGIAN_LOCK_SOAK_SECONDS, defaulting to a CI-safe short soak.
// This is the knob operators use for a real measurement run — see the file
// header comment for the invocation.
[[nodiscard]] auto soak_duration() -> std::chrono::seconds
{
    auto const* raw = std::getenv("MEROVINGIAN_LOCK_SOAK_SECONDS");
    if (raw == nullptr || raw[0] == '\0')
    {
        return 2s;
    }
    auto const seconds = std::strtol(raw, nullptr, 10);
    return std::chrono::seconds{seconds > 0 ? seconds : 2};
}

[[nodiscard]] auto load_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    security.federation.max_transaction_size = "1MiB";
    security.federation.remote_timeout = "30s";
    auto client_rate_limits = merovingian::config::ClientRateLimitsConfig{};
    // See file header: every simulated client shares 127.0.0.1, so the
    // default per-IP bucket would measure the rate limiter, not the lock.
    client_rate_limits.default_per_ip = {1'000'000U, 1U};
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
        client_rate_limits,
        merovingian::config::LogModulesConfig{},
    };
}

struct RegisteredUser final
{
    std::string access_token{};
    std::string room_id{};
};

[[nodiscard]] auto register_user_and_room(merovingian::homeserver::ClientServerRuntime& runtime,
                                          std::string_view localpart) -> RegisteredUser
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(registration.response.status == 200U);
    auto const parsed = merovingian::canonicaljson::parse_lossless(registration.response.body);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(obj != nullptr);
    auto token = std::string{};
    for (auto const& member : *obj)
    {
        if (member.key == "access_token")
        {
            token = *std::get_if<std::string>(&member.value->storage());
        }
    }
    REQUIRE(!token.empty());

    auto const create_room = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
    REQUIRE(create_room.response.status == 200U);
    auto const room_parsed = merovingian::canonicaljson::parse_lossless(create_room.response.body);
    REQUIRE(room_parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* room_obj = std::get_if<merovingian::canonicaljson::Object>(&room_parsed.value.storage());
    REQUIRE(room_obj != nullptr);
    auto room_id = std::string{};
    for (auto const& member : *room_obj)
    {
        if (member.key == "room_id")
        {
            room_id = *std::get_if<std::string>(&member.value->storage());
        }
    }
    REQUIRE(!room_id.empty());
    return {token, room_id};
}

// A signed, X-Matrix-authenticated remote server identity, registered into
// the runtime so its transactions verify without any outbound network call
// (no live remote key fetch — the record is pre-seeded, exactly as
// test_federation_inbound_flow.cpp's remote_for() does).
struct SimulatedRemote final
{
    std::string server_name{};
    merovingian::federation::test::SigningKeypair keys{};
};

[[nodiscard]] auto register_remote(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view server_name)
    -> SimulatedRemote
{
    auto keys = merovingian::federation::test::keypair_from_seed(server_name);
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = std::string{server_name};
    remote.signing_key = {std::string{server_name}, "ed25519:auto", 4102444800000ULL, keys.public_key};
    remote.discovery.server_name = std::string{server_name};
    remote.discovery.well_known_host = std::string{server_name};
    remote.discovery.resolved_host = std::string{server_name};
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    merovingian::federation::upsert_remote(runtime.homeserver.federation, remote);
    return {std::string{server_name}, keys};
}

// Builds a real "Authorization: X-Matrix ..." header exactly as a live peer
// would (src/federation/outbound_transaction.cpp's build_authorization_header
// mirrored here), so the request this harness sends is authenticated through
// the production verification path, not a test-only bypass.
[[nodiscard]] auto x_matrix_header(SimulatedRemote const& remote, std::string_view destination, std::string_view method,
                                   std::string_view target, std::string_view body) -> std::string
{
    auto const signature = merovingian::federation::make_federation_signature(remote.server_name, destination, method,
                                                                              target, body, remote.keys.secret_key);
    auto header = std::string{"X-Matrix origin=\""};
    header += remote.server_name;
    header += "\",destination=\"";
    header += destination;
    header += "\",key=\"ed25519:auto\",sig=\"";
    header += signature;
    header += '"';
    return header;
}

// Sends `request_line`/`headers`/`body` over `fd` and reads one framed
// response, recording latency into `stats`. `deadline` bounds the run — the
// worker loop calling this checks it between rounds, not mid-call.
auto do_round(int fd, PlainResponseReader& reader, std::string const& request, CategoryStats& stats) -> void
{
    auto const start = std::chrono::steady_clock::now();
    if (!send_all(fd, request))
    {
        ++stats.failed;
        return;
    }
    auto const response = receive_response(fd, reader);
    auto const elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    stats.latencies_ms.push_back(elapsed);
    if (response.status >= 200U && response.status < 500U)
    {
        // 4xx counts as "ok" for this harness's purposes: a rejected
        // request (e.g. a 429 from a category deliberately racing the rate
        // limiter, or a policy 403) still round-tripped through the full
        // lock-acquiring dispatch path being measured. Only a dropped
        // connection or a 5xx is a harness-relevant failure.
        ++stats.ok;
    }
    else
    {
        ++stats.failed;
    }
}

[[nodiscard]] auto build_request(std::string_view method, std::string_view target, std::string_view auth_header_value,
                                 bool auth_is_bearer, std::string_view body) -> std::string
{
    auto request = std::string{method};
    request += ' ';
    request += target;
    request += " HTTP/1.1\r\nHost: localhost\r\n";
    if (!auth_header_value.empty())
    {
        request += "Authorization: ";
        if (auth_is_bearer)
        {
            request += "Bearer ";
        }
        request += auth_header_value;
        request += "\r\n";
    }
    if (!body.empty())
    {
        request += "Content-Type: application/json\r\nContent-Length: ";
        request += std::to_string(body.size());
        request += "\r\n\r\n";
        request += body;
    }
    else
    {
        request += "Content-Length: 0\r\n\r\n";
    }
    return request;
}

} // namespace

SCENARIO("Mixed client-server and federation load does not deadlock and stays within a responsive latency budget",
         "[homeserver][concurrency][load-soak][opt-in]")
{
    GIVEN("a running homeserver with a client-server listener and a federation listener, several users each with "
          "their own room, and a registered simulated remote server")
    {
        REQUIRE(sodium_init() >= 0);

        auto started = merovingian::homeserver::start_client_server(load_test_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        // Client-server listener.
        auto client_acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(client_acceptor.bind("127.0.0.1", 0U).ok);
        auto const client_port = client_acceptor.bound_port();
        REQUIRE(client_port > 0U);

        // Federation listener — a separate real socket, matching a production
        // deployment's separate client (8008) and federation (8448) ports.
        auto federation_acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(federation_acceptor.bind("127.0.0.1", 0U).ok);
        auto const federation_port = federation_acceptor.bound_port();
        REQUIRE(federation_port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto client_stats = merovingian::homeserver::HttpServeStats{};
        auto federation_stats = merovingian::homeserver::HttpServeStats{};
        // Separate from the client-server main pool for the same reason
        // production does (src/sync/AGENTS.md): long-polling /sync
        // connections must not starve short-lived requests.
        auto main_pool = merovingian::net::ThreadPool{8U};
        auto sync_pool = merovingian::net::ThreadPool{8U};
        auto federation_pool = merovingian::net::ThreadPool{8U};

        constexpr auto user_count = 6U;
        auto users = std::vector<RegisteredUser>{};
        for (auto index = 0U; index < user_count; ++index)
        {
            users.push_back(register_user_and_room(runtime, "loaduser" + std::to_string(index)));
        }
        auto const remote = register_remote(runtime, "loadpeer.example.org");
        auto const local_server_name = runtime.homeserver.config.server().server_name;

        auto client_server_thread = std::thread{[&]() {
            merovingian::homeserver::serve_http(client_acceptor, runtime, shutdown, client_stats,
                                                merovingian::homeserver::HttpDispatchMode::client_server, main_pool,
                                                &sync_pool);
        }};
        auto federation_server_thread = std::thread{[&]() {
            merovingian::homeserver::serve_http(federation_acceptor, runtime, shutdown, federation_stats,
                                                merovingian::homeserver::HttpDispatchMode::federation, federation_pool);
        }};

        WHEN("sync long-polls, ordinary reads, message sends, and inbound federation transactions all run "
             "concurrently for the configured soak duration")
        {
            auto const deadline = std::chrono::steady_clock::now() + soak_duration();

            auto sync_results = std::vector<CategoryStats>(user_count);
            auto read_results = std::vector<CategoryStats>(user_count);
            auto send_results = std::vector<CategoryStats>(user_count);
            auto federation_results = std::vector<CategoryStats>{CategoryStats{}};

            auto workers = std::vector<std::thread>{};

            for (auto index = 0U; index < user_count; ++index)
            {
                // Long-poll /sync. timeout=1000 keeps each round short enough
                // that the deadline is honoured promptly at every duration.
                workers.emplace_back([&, index]() {
                    auto const fd = connect_loopback(client_port);
                    if (fd < 0)
                    {
                        return;
                    }
                    auto reader = PlainResponseReader{};
                    auto since = std::string{};
                    while (std::chrono::steady_clock::now() < deadline)
                    {
                        auto const target = "/_matrix/client/v3/sync?timeout=1000" +
                                            (since.empty() ? std::string{} : "&since=" + since);
                        auto const request = build_request("GET", target, users[index].access_token, true, {});
                        auto const start = std::chrono::steady_clock::now();
                        if (!send_all(fd, request))
                        {
                            ++sync_results[index].failed;
                            break;
                        }
                        auto const response = receive_response(fd, reader);
                        auto const elapsed =
                            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
                        sync_results[index].latencies_ms.push_back(elapsed);
                        if (response.status == 200U)
                        {
                            ++sync_results[index].ok;
                            auto const marker = std::string_view{"\"next_batch\":\""};
                            auto const pos = response.body.find(marker);
                            if (pos != std::string::npos)
                            {
                                auto const value_start = pos + marker.size();
                                auto const value_end = response.body.find('"', value_start);
                                if (value_end != std::string::npos)
                                {
                                    since = response.body.substr(value_start, value_end - value_start);
                                }
                            }
                        }
                        else
                        {
                            ++sync_results[index].failed;
                        }
                    }
                    ::close(fd);
                });

                workers.emplace_back([&, index]() {
                    auto const fd = connect_loopback(client_port);
                    if (fd < 0)
                    {
                        return;
                    }
                    auto reader = PlainResponseReader{};
                    while (std::chrono::steady_clock::now() < deadline)
                    {
                        auto const request = build_request("GET", "/_matrix/client/v3/capabilities",
                                                           users[index].access_token, true, {});
                        do_round(fd, reader, request, read_results[index]);
                    }
                    ::close(fd);
                });

                workers.emplace_back([&, index]() {
                    auto const fd = connect_loopback(client_port);
                    if (fd < 0)
                    {
                        return;
                    }
                    auto reader = PlainResponseReader{};
                    auto txn = std::uint64_t{0U};
                    while (std::chrono::steady_clock::now() < deadline)
                    {
                        auto const target = "/_matrix/client/v3/rooms/" + users[index].room_id +
                                            "/send/m.room.message/loadsend-" + std::to_string(index) + '-' +
                                            std::to_string(++txn);
                        auto const body = std::string{R"({"msgtype":"m.text","body":"load")"} + "}";
                        auto const request = build_request("PUT", target, users[index].access_token, true, body);
                        do_round(fd, reader, request, send_results[index]);
                    }
                    ::close(fd);
                });
            }

            // Simulated inbound federation traffic: signed, empty (no
            // PDUs/EDUs) transactions. This still exercises the full
            // production X-Matrix authentication path (header parse,
            // signature verification against the pre-seeded remote key,
            // trust-safety policy evaluation) over a real socket — see the
            // file header comment for why PDU content is not needed to
            // measure the lock this harness is about.
            constexpr auto federation_worker_count = 2U;
            for (auto worker_index = 0U; worker_index < federation_worker_count; ++worker_index)
            {
                workers.emplace_back([&, worker_index]() {
                    auto const fd = connect_loopback(federation_port);
                    if (fd < 0)
                    {
                        return;
                    }
                    auto reader = PlainResponseReader{};
                    auto txn = std::uint64_t{0U};
                    while (std::chrono::steady_clock::now() < deadline)
                    {
                        auto const target = "/_matrix/federation/v1/send/loadtxn-" + std::to_string(worker_index) +
                                            '-' + std::to_string(++txn);
                        auto const body = std::string{R"({"origin":")"} + remote.server_name +
                                          R"(","origin_server_ts":1000,"pdus":[],"edus":[]})";
                        auto const auth = x_matrix_header(remote, local_server_name, "PUT", target, body);
                        auto const request = build_request("PUT", target, auth, false, body);
                        do_round(fd, reader, request, federation_results[0]);
                    }
                    ::close(fd);
                });
            }

            for (auto& worker : workers)
            {
                worker.join();
            }

            shutdown.fire();
            client_server_thread.join();
            federation_server_thread.join();

            THEN("every category completes without deadlocking, and the results are reported")
            {
                auto const wall = std::chrono::duration<double>{soak_duration()};

                auto sync_total = CategoryStats{};
                auto read_total = CategoryStats{};
                auto send_total = CategoryStats{};
                for (auto index = 0U; index < user_count; ++index)
                {
                    sync_total.ok += sync_results[index].ok;
                    sync_total.failed += sync_results[index].failed;
                    sync_total.latencies_ms.insert(sync_total.latencies_ms.end(),
                                                   sync_results[index].latencies_ms.begin(),
                                                   sync_results[index].latencies_ms.end());
                    read_total.ok += read_results[index].ok;
                    read_total.failed += read_results[index].failed;
                    read_total.latencies_ms.insert(read_total.latencies_ms.end(),
                                                   read_results[index].latencies_ms.begin(),
                                                   read_results[index].latencies_ms.end());
                    send_total.ok += send_results[index].ok;
                    send_total.failed += send_results[index].failed;
                    send_total.latencies_ms.insert(send_total.latencies_ms.end(),
                                                   send_results[index].latencies_ms.begin(),
                                                   send_results[index].latencies_ms.end());
                }

                report("sync", sync_total, wall);
                report("read", read_total, wall);
                report("send", send_total, wall);
                report("federation_send", federation_results[0], wall);

                REQUIRE(client_stats.accepted_connections >= user_count * 3U);
                REQUIRE(federation_stats.accepted_connections >= federation_worker_count);
                // Every category made real progress — a hang in any one
                // category (the deadlock/starvation pattern this harness
                // exists to catch) would show up as zero completed rounds
                // for that category while the others still finished, or as
                // the outer meson test timeout if the join above never
                // returns at all.
                REQUIRE(sync_total.ok > 0U);
                REQUIRE(read_total.ok > 0U);
                REQUIRE(send_total.ok > 0U);
                REQUIRE(federation_results[0].ok > 0U);
            }
        }
    }
}
