// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         OUT-OF-PROCESS FEDERATION WORKER INTEGRATION TESTS              |
// |                                                                         |
// |  These tests spawn the real merovingian-fed-worker binary over an       |
// |  encrypted AF_UNIX socketpair and exercise room-based sharding, the     |
// |  no-signing refusal, and in-process fallback when the worker is down.    |
// +-------------------------------------------------------------------------+

#include "../federation_signing_test_support.hpp"
#include "../support/edu_relay_context.hpp"
#include "../support/joining_threads.hpp"
#include "../support/master_key.hpp"
#include "../support/membership_fixture_support.hpp"
#include "../support/remote_room_fixture.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/crypto/master_key.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/federation_request_routing.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/homeserver/worker_pool.hpp"
#include "merovingian/homeserver/worker_supervisor.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/ipc/channel.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/types.h>
#endif

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

// Derives the worker IPC auth key material a test hands directly to a
// WorkerSupervisor it constructs itself (bypassing WorkerPool, which would
// otherwise do this derivation once for every shard — see
// WorkerPool::WorkerPool in src/homeserver/worker_pool.cpp). Mirrors that
// same derivation from the same master key file so the standalone
// WorkerSupervisor scenarios below authenticate against a real worker
// exactly as WorkerPool-driven scenarios do.
[[nodiscard]] auto derive_worker_ipc_auth_key_material(std::string const& master_key_path)
    -> merovingian::core::SecretBuffer
{
    auto material = merovingian::crypto::load_master_key_material(master_key_path);
    REQUIRE(material.has_value());
    auto const key = merovingian::crypto::derive_ipc_auth_key(material->bytes());
    REQUIRE(key.has_value());
    return merovingian::core::SecretBuffer{
        std::span<std::uint8_t const>{key->bytes.data(), key->bytes.size()}
    };
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
    // Use a unique on-disk SQLite file per scenario. This gives the main
    // runtime and its per-statement persistence connections a consistent store
    // that survives connection open/close, and gives each spawned worker process
    // a distinct connection to the same file. The temp directory is unique per
    // scenario, so different scenarios do not share signing keys or rooms.
    database.sqlite_path = (tmp / "merovingian.sqlite3").string();
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
    // ADR-0062 part 3: Landlock is applied unconditionally at worker startup,
    // independent of apply_hardening above, so every scenario here spawns a
    // real worker that attempts it. Setting the opt-out true only changes
    // behaviour when the running kernel actually lacks Landlock (older than
    // 5.13, or disabled at boot) -- on a kernel that has it, Landlock is
    // still applied for real and every scenario below genuinely exercises the
    // allowlist (this is deliberate: a missing CA/resolver/NSS path would
    // surface here as outbound federation failing). Without this, every
    // scenario in this file would refuse to start on any CI/dev kernel that
    // predates Landlock, which is a regression this ADR must not introduce.
    fw.allow_without_landlock = true;

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
    // ADR-0062 part 3: see the comment on make_federation_worker_config's
    // fw.allow_without_landlock above.
    content += "federation.worker.allow_without_landlock=";
    content += config.federation_worker().allow_without_landlock ? "true" : "false";
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

// Format a vector of event IDs as a JSON string array.
[[nodiscard]] auto json_id_array(std::vector<std::string> const& ids) -> std::string
{
    auto out = std::string{"["};
    for (std::size_t i = 0U; i < ids.size(); ++i)
    {
        if (i != 0U)
        {
            out += ',';
        }
        out += "\"" + ids[i] + "\"";
    }
    out += "]";
    return out;
}

// Events relayed by a worker are signed as their sender's server with this
// seed, and relay_key_resolver() gives main that server's matching key: main
// re-verifies every relayed PDU's signature itself (ADR-0071).
constexpr auto relay_key_seed = "federation-worker-flow-relay-seed";
constexpr auto relay_key_id = "ed25519:auto";

[[nodiscard]] auto server_of(std::string_view user_id) -> std::string
{
    auto const colon = user_id.find(':');
    return colon == std::string_view::npos ? std::string{} : std::string{user_id.substr(colon + 1U)};
}

// Hashes and signs `unsigned_event_json` as the server `sender` belongs to.
[[nodiscard]] auto sign_as_sender(std::string_view unsigned_event_json, std::string_view sender) -> std::string
{
    auto signed_json = merovingian::federation::test::make_signed_event_json(unsigned_event_json, server_of(sender),
                                                                             relay_key_id, relay_key_seed, "10");
    REQUIRE(!signed_json.empty());
    return signed_json;
}

// The event ID a signed room-version-10 event hashes to.
[[nodiscard]] auto event_id_of(std::string const& signed_event_json) -> std::string
{
    auto const envelope = merovingian::federation::parse_inbound_pdu_envelope(signed_event_json, "10");
    REQUIRE(envelope.has_value());
    return envelope->event_id;
}

// Main's key resolver in these scenarios: every server's key is the one
// derived from relay_key_seed, valid until 2100-01-01 (from room v5 a key
// must still be valid at each event's origin_server_ts, ADR-0075).
[[nodiscard]] auto relay_key_resolver()
{
    return [](std::string_view server_name,
              std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
        if (key_id != relay_key_id)
        {
            return std::nullopt;
        }
        auto remote = merovingian::federation::FederationRemoteRuntime{};
        remote.server_name = std::string{server_name};
        remote.signing_key = {std::string{server_name}, relay_key_id, 4'102'444'800'000U,
                              merovingian::federation::test::keypair_from_seed(relay_key_seed).public_key};
        remote.discovery.server_name = std::string{server_name};
        return remote;
    };
}

// Build an m.room.member event JSON, hashed and signed as the sender's server,
// so it passes main's signature re-verification and the PDU receipt checks run
// by membership_acceptor.
[[nodiscard]] auto make_membership_event_json(std::string_view room_id, std::string_view sender,
                                              std::string_view state_key, std::string_view membership,
                                              std::vector<std::string> const& prev_events,
                                              std::vector<std::string> const& auth_events, std::int64_t depth,
                                              std::int64_t origin_server_ts) -> std::string
{
    using namespace merovingian;

    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{membership}}));

    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{origin_server_ts}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
    obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{state_key}}));
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.member"}}));

    auto prev_arr = canonicaljson::Array{};
    for (auto const& id : prev_events)
    {
        prev_arr.push_back(canonicaljson::Value{id});
    }
    obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev_arr)}));

    auto auth_arr = canonicaljson::Array{};
    for (auto const& id : auth_events)
    {
        auth_arr.push_back(canonicaljson::Value{id});
    }
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{std::move(auth_arr)}));

    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return sign_as_sender(serialized.output, sender);
}

} // namespace

namespace
{

// The socket client is deliberately independent of the production outbound
// federation transport: that transport rejects cleartext/loopback destinations.
[[nodiscard]] auto fed10_socket_request(std::uint16_t port, std::string const& request) -> LocalHttpResponse
{
    auto socket = merovingian::core::FileDescriptor{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    REQUIRE(socket.valid());
    auto const timeout = timeval{15, 0};
    REQUIRE(::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    REQUIRE(::setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    auto address = sockaddr_in{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    REQUIRE(::connect(socket.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address)) == 0);
    auto sent = std::size_t{};
    while (sent < request.size())
    {
        auto const count = ::send(socket.get(), request.data() + sent, request.size() - sent, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR)
            continue;
        REQUIRE(count > 0);
        sent += static_cast<std::size_t>(count);
    }
    auto response = std::string{};
    auto bytes = std::array<char, 4096>{};
    for (;;)
    {
        auto const count = ::recv(socket.get(), bytes.data(), bytes.size(), 0);
        if (count < 0 && errno == EINTR)
            continue;
        REQUIRE(count >= 0);
        if (count == 0)
            break;
        response.append(bytes.data(), static_cast<std::size_t>(count));
        REQUIRE(response.size() <= 65536U);
    }
    auto const body_offset = response.find("\r\n\r\n");
    REQUIRE(body_offset != std::string::npos);
    REQUIRE(response.starts_with("HTTP/1.1 "));
    auto result = LocalHttpResponse{};
    auto const status = std::from_chars(response.data() + 9, response.data() + 12, result.status);
    REQUIRE(status.ec == std::errc{});
    result.body = response.substr(body_offset + 4U);
    return result;
}

class Fed10TempDirectory final
{
public:
    explicit Fed10TempDirectory(std::filesystem::path path)
        : path_(std::move(path))
    {
    }
    Fed10TempDirectory(Fed10TempDirectory const&) = delete;
    auto operator=(Fed10TempDirectory const&) -> Fed10TempDirectory& = delete;
    ~Fed10TempDirectory() noexcept
    {
        auto error = std::error_code{};
        std::ignore = std::filesystem::remove_all(path_, error);
    }

private:
    std::filesystem::path path_;
};

// Stop the listener and drain request threads even if a REQUIRE unwinds.
class Fed10SocketListener final
{
public:
    explicit Fed10SocketListener(merovingian::homeserver::ClientServerRuntime& runtime)
    {
        REQUIRE(acceptor_.bind("127.0.0.1", 0U).ok);
        REQUIRE(shutdown_.valid());
        thread_ = std::thread{[this, &runtime]() {
            merovingian::homeserver::serve_http(acceptor_, runtime, shutdown_, stats_,
                                                merovingian::homeserver::HttpDispatchMode::federation, pool_);
        }};
    }
    Fed10SocketListener(Fed10SocketListener const&) = delete;
    auto operator=(Fed10SocketListener const&) -> Fed10SocketListener& = delete;
    ~Fed10SocketListener() noexcept
    {
        shutdown_.fire();
        if (thread_.joinable())
            thread_.join();
        pool_.request_stop();
    }
    [[nodiscard]] auto port() const noexcept -> std::uint16_t
    {
        return acceptor_.bound_port();
    }

private:
    merovingian::net::TcpAcceptor acceptor_{};
    merovingian::net::ShutdownSignal shutdown_{};
    merovingian::homeserver::HttpServeStats stats_{};
    merovingian::net::ThreadPool pool_{2U};
    std::thread thread_{};
};

// Stop the worker before the scenario's callback counters leave scope.
class Fed10ProxyLifetime final
{
public:
    explicit Fed10ProxyLifetime(merovingian::homeserver::HomeserverRuntime& runtime)
        : runtime_(runtime)
    {
    }
    Fed10ProxyLifetime(Fed10ProxyLifetime const&) = delete;
    auto operator=(Fed10ProxyLifetime const&) -> Fed10ProxyLifetime& = delete;
    ~Fed10ProxyLifetime() noexcept
    {
        runtime_.federation_proxy.reset();
    }

private:
    merovingian::homeserver::HomeserverRuntime& runtime_;
};

// The shared genesis helper populates mirrors, not the room/event SQL rows.
// Persist every row and graph edge before spawning the independent worker.
auto fed10_persist_remote_room(merovingian::homeserver::HomeserverRuntime& runtime, std::string const& room_id) -> void
{
    using namespace merovingian;
    tests::remote_room::seed_room_with_genesis_state_group(runtime, room_id);
    auto& store = runtime.database.persistent_store;
    auto rooms = std::move(store.rooms);
    auto events = std::move(store.events);
    auto state = std::move(store.state);
    auto memberships = std::move(store.memberships);
    store.rooms.clear();
    store.events.clear();
    store.state.clear();
    store.memberships.clear();
    for (auto& room : rooms)
        REQUIRE(database::store_room(store, std::move(room)));
    for (auto& event : events)
    {
        if (event.depth > 0U)
        {
            event.prev_event_ids = {events[static_cast<std::size_t>(event.depth - 1U)].event_id};
            event.auth_event_ids = {room_id + ":create"};
        }
        // Match the durably stored graph to the event JSON read by the child.
        auto parsed = canonicaljson::parse_lossless(event.json);
        REQUIRE(parsed.error == canonicaljson::ParseError::none);
        auto& object = std::get<canonicaljson::Object>(parsed.value.storage());
        for (auto& member : object)
        {
            if (member.key != "prev_events" && member.key != "auth_events")
                continue;
            auto array = canonicaljson::Array{};
            for (auto const& id : member.key == "prev_events" ? event.prev_event_ids : event.auth_event_ids)
                array.emplace_back(id);
            *member.value = canonicaljson::Value{std::move(array)};
        }
        auto const serialized = canonicaljson::serialize_canonical(parsed.value);
        REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
        event.json = serialized.output;
        REQUIRE(database::store_event(store, event));
    }
    for (auto& entry : state)
        REQUIRE(database::store_state(store, std::move(entry)));
    for (auto& membership : memberships)
        REQUIRE(database::store_membership(store, std::move(membership)) == database::MembershipStoreResult::stored);
    auto const remote = tests::remote_room::remote_runtime();
    REQUIRE(database::store_server_signing_key(
        store, {remote.server_name, remote.signing_key.key_id,
                federation::test::pubkey_b64(federation::test::keypair_from_seed(tests::remote_room::remote_key_seed)),
                remote.signing_key.valid_until_ts}));
}

[[nodiscard]] auto fed10_target_count(merovingian::database::PersistentStore const& store, std::string const& event_id)
    -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(store.events, [&](auto const& event) {
        return event.event_id == event_id;
    }));
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

// Matrix v1.19, server-server API, PUT /send/{txnId}: unsuccessful
// transactions remain retryable; completed transactions must not redeliver EDUs.
SCENARIO("main key-admission overload survives real worker socket HTTP and unchanged transaction retry",
         "[integration][federation][worker][send][fed10][fed10-worker-http]")
{
    using namespace merovingian;
    using namespace merovingian::tests::remote_room;
    GIVEN("a durable resident room and public remote key shared with one actual worker shard")
    {
        WHEN("main's PDU key cache misses while quota or in-flight admission is full")
        {
            THEN("both admission branches return retryable 503 without delivery, then accept and deduplicate the same "
                 "request")
            {
                for (auto const occupied_slot : {false, true})
                {
                    INFO((occupied_slot ? "main slot-full" : "main quota-full"));
                    auto const tmp = unique_temp_dir("merovingian-fed10-worker-http-");
                    auto cleanup = Fed10TempDirectory{tmp};
                    auto config = make_federation_worker_config(tmp);
                    config.server().server_name = local_server;
                    config.federation_worker().shards = 1U;
                    auto const config_path = tmp / "worker.conf";
                    write_worker_config(config_path, config);
                    auto started = homeserver::start_client_server(config);
                    REQUIRE(started.started);
                    auto& client = started.runtime;
                    auto& runtime = client.homeserver;
                    homeserver::wire_federation_callbacks(runtime);
                    REQUIRE(static_cast<bool>(runtime.federation.pdu_sink));
                    REQUIRE(static_cast<bool>(runtime.federation.edu_sink));
                    auto const room_id = std::string{"!fed10-worker-http:"} + local_server;
                    fed10_persist_remote_room(runtime, room_id);
                    // A numeric relay origin plus a durable fresh public key lets
                    // the real child resolve its peer without external DNS/HTTP.
                    // The PDU sender remains a different, cache-known server.
                    auto const relay_server = std::string{"203.0.113.20"};
                    auto const relay_member = std::string{"@relay:"} + relay_server;
                    REQUIRE(database::store_membership(runtime.database.persistent_store,
                                                       {room_id, relay_member, "join"}) ==
                            database::MembershipStoreResult::stored);
                    auto relay = remote_runtime();
                    relay.server_name = relay_server;
                    relay.signing_key.server_name = relay_server;
                    relay.discovery.server_name = relay_server;
                    relay.discovery.resolved_host = relay_server;
                    relay.discovery.resolved_addresses = {relay_server};
                    REQUIRE(database::store_server_signing_key(
                        runtime.database.persistent_store,
                        {relay_server, relay.signing_key.key_id,
                         events::matrix_base64_from_bytes(relay.signing_key.public_key_bytes),
                         relay.signing_key.valid_until_ts}));
                    auto const signed_pdu = make_remote_message_json(
                        room_id, {room_id + ":member"}, {room_id + ":create", room_id + ":pl", room_id + ":member:bob"},
                        4, 50);
                    auto const envelope = federation::parse_inbound_pdu_envelope(signed_pdu, room_version);
                    REQUIRE(envelope.has_value());
                    auto const event_id = envelope->event_id;
                    auto const body = std::string{"{\"origin\":\""} + relay_server +
                                      "\",\"origin_server_ts\":50,\"pdus\":[" + signed_pdu +
                                      "],\"edus\":[{\"edu_type\":\"m.typing\",\"content\":{\"room_id\":\"" + room_id +
                                      "\",\"user_id\":\"" + relay_member + "\",\"typing\":true}}]}";
                    auto const target = std::string{"/_matrix/federation/v1/send/fed10-unchanged"};
                    auto call = federation::OutboundCall{};
                    call.transaction =
                        federation::make_outbound_transaction(local_server, "PUT", target, relay_server, body);
                    call.key_id = remote_key_id;
                    call.secret_key =
                        federation::test::secret_key_buffer(federation::test::keypair_from_seed(remote_key_seed));
                    auto const outbound = federation::build_outbound_request(call);
                    auto const authorization = std::ranges::find_if(outbound.headers, [](auto const& header) {
                        return header.name == "Authorization";
                    });
                    REQUIRE(authorization != outbound.headers.end());
                    auto const credentials = federation::parse_x_matrix_authorization_header(authorization->value);
                    REQUIRE(credentials.has_value());
                    auto authenticated = federation::SignedFederationRequest{};
                    authenticated.method = "PUT";
                    authenticated.target = target;
                    authenticated.origin = relay_server;
                    authenticated.destination = local_server;
                    authenticated.key_id = credentials->key_id;
                    authenticated.signature = credentials->signature;
                    authenticated.body = body;
                    authenticated.canonical_json_verified = true;
                    authenticated.remote_addr = "127.0.0.1";
                    authenticated.now_ts =
                        static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                       std::chrono::system_clock::now().time_since_epoch())
                                                       .count());
                    auto raw_calls = std::atomic<std::size_t>{};
                    auto cache_misses = std::atomic<std::size_t>{};
                    auto edu_deliveries = std::atomic<std::size_t>{};
                    runtime.federation.remotes = {relay};
                    runtime.federation.cached_pdu_key_lookup =
                        [&cache_misses](std::string_view server,
                                        std::string_view id) -> std::optional<federation::FederationKeyRecord> {
                        if (server == remote_server && id == remote_key_id)
                            ++cache_misses;
                        return std::nullopt;
                    };
                    runtime.federation.remote_key_resolver = [&raw_calls](std::string_view server,
                                                                          std::string_view id) {
                        ++raw_calls;
                        return genuine_key_resolver()(server, id);
                    };
                    // Observe, but always execute, the genuine production typing sink.
                    auto real_edu_sink = runtime.federation.edu_sink;
                    runtime.federation.edu_sink = [&edu_deliveries, real_edu_sink](auto const& edu) {
                        ++edu_deliveries;
                        return real_edu_sink(edu);
                    };
                    auto const warm_auth =
                        federation::verify_inbound_federation_signature(runtime.federation, authenticated);
                    REQUIRE(warm_auth.accepted);
                    REQUIRE(raw_calls.load() == 0U);
                    // Read independently using the child's restricted table profile.
                    {
                        auto durable = database::open_sqlite_persistent_store(
                            config.database().sqlite_path, database::TableLoadProfile::federation_worker);
                        REQUIRE(durable.ok);
                        CHECK(durable.store.rooms.size() == 1U);
                        CHECK(durable.store.events.size() == 4U);
                        CHECK(durable.store.state.size() == 4U);
                        CHECK(durable.store.memberships.size() == 3U);
                        CHECK(durable.store.event_edges.size() == 3U);
                        CHECK(durable.store.event_auth.size() == 3U);
                        CHECK(durable.store.event_state_groups.size() == 4U);
                        auto const key = database::find_server_signing_key(durable.store, remote_server, remote_key_id);
                        REQUIRE(key.has_value());
                        CHECK(key->secret_key.empty());
                        CHECK(key->valid_until_ts > authenticated.now_ts);
                    }
                    runtime.federation_proxy = std::make_unique<FederationProxy>(
                        config.federation_worker(), runtime, std::string{worker_binary_path()}, config_path.string());
                    auto const proxy_lifetime = Fed10ProxyLifetime{runtime};
                    std::ignore = proxy_lifetime;
                    REQUIRE(wait_for_healthy(*runtime.federation_proxy, std::chrono::seconds{15}));
                    auto listener = Fed10SocketListener{client};
                    {
                        auto guard = std::lock_guard{*runtime.federation.mutex};
                        runtime.federation.config.key_resolution_max_in_flight = 1U;
                        runtime.federation.config.key_resolution_per_ip_rate = {1U, 3600U};
                        runtime.federation.key_resolution_buckets.clear();
                        runtime.federation.key_resolution_failures.clear();
                        runtime.federation.key_resolutions_in_flight = occupied_slot ? 1U : 0U;
                        if (!occupied_slot)
                            runtime.federation.key_resolution_buckets.push_back(
                                {"<unknown>", 1U, std::chrono::steady_clock::now()});
                    }
                    // Reuse these exact bytes, including txid and signed body, for all three sends.
                    auto const wire =
                        "PUT " + target + " HTTP/1.1\r\nHost: localhost\r\nAuthorization: " + authorization->value +
                        "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
                        "\r\nConnection: close\r\n\r\n" + body;
                    auto const denied = fed10_socket_request(listener.port(), wire);
                    CHECK(denied.status == 503U);
                    auto const denied_json = canonicaljson::parse_lossless(denied.body);
                    REQUIRE(denied_json.error == canonicaljson::ParseError::none);
                    auto const* denied_object = std::get_if<canonicaljson::Object>(&denied_json.value.storage());
                    REQUIRE(denied_object != nullptr);
                    auto const errcode = std::ranges::find_if(*denied_object, [](auto const& member) {
                        return member.key == "errcode";
                    });
                    REQUIRE(errcode != denied_object->end());
                    auto const* code = std::get_if<std::string>(&errcode->value->storage());
                    REQUIRE(code != nullptr);
                    CHECK(*code == "M_UNKNOWN");
                    CHECK(runtime.federation_proxy->healthy());
                    CHECK(cache_misses.load() > 0U);
                    CHECK(raw_calls.load() == 0U);
                    CHECK(edu_deliveries.load() == 0U);
                    {
                        auto guard = std::lock_guard{runtime.mutex};
                        CHECK(fed10_target_count(runtime.database.persistent_store, event_id) == 0U);
                        CHECK(homeserver::current_typing_users_in_room(runtime, room_id).empty());
                        auto durable = database::open_sqlite_persistent_store(config.database().sqlite_path);
                        REQUIRE(durable.ok);
                        CHECK(fed10_target_count(durable.store, event_id) == 0U);
                    }
                    {
                        auto guard = std::lock_guard{*runtime.federation.mutex};
                        CHECK(runtime.federation.key_resolutions_in_flight == (occupied_slot ? 1U : 0U));
                        CHECK(runtime.federation.key_resolution_failures.empty());
                        runtime.federation.key_resolution_buckets.clear();
                        runtime.federation.key_resolutions_in_flight = 0U;
                    }
                    auto const accepted = fed10_socket_request(listener.port(), wire);
                    CHECK(accepted.status == 200U);
                    auto const accepted_json = canonicaljson::parse_lossless(accepted.body);
                    REQUIRE(accepted_json.error == canonicaljson::ParseError::none);
                    auto const* accepted_object = std::get_if<canonicaljson::Object>(&accepted_json.value.storage());
                    REQUIRE(accepted_object != nullptr);
                    auto const pdus = std::ranges::find_if(*accepted_object, [](auto const& member) {
                        return member.key == "pdus";
                    });
                    REQUIRE(pdus != accepted_object->end());
                    auto const* pdu_results = std::get_if<canonicaljson::Object>(&pdus->value->storage());
                    REQUIRE(pdu_results != nullptr);
                    // The production response lists only PDU errors. Prove
                    // acceptance below with the real in-memory and durable event.
                    CHECK(pdu_results->empty());
                    CHECK(runtime.federation_proxy->healthy());
                    CHECK(raw_calls.load() == 1U);
                    CHECK(edu_deliveries.load() == 1U);
                    auto const misses_after_accept = cache_misses.load();
                    {
                        auto guard = std::lock_guard{runtime.mutex};
                        CHECK(fed10_target_count(runtime.database.persistent_store, event_id) == 1U);
                        CHECK(homeserver::current_typing_users_in_room(runtime, room_id) ==
                              std::vector<std::string>{relay_member});
                        auto durable = database::open_sqlite_persistent_store(config.database().sqlite_path);
                        REQUIRE(durable.ok);
                        CHECK(fed10_target_count(durable.store, event_id) == 1U);
                    }
                    auto const duplicate = fed10_socket_request(listener.port(), wire);
                    CHECK(duplicate.status == 200U);
                    CHECK(bool{duplicate.body == accepted.body});
                    CHECK(runtime.federation_proxy->healthy());
                    CHECK(cache_misses.load() == misses_after_accept);
                    CHECK(raw_calls.load() == 1U);
                    CHECK(edu_deliveries.load() == 1U);
                    {
                        auto guard = std::lock_guard{runtime.mutex};
                        CHECK(fed10_target_count(runtime.database.persistent_store, event_id) == 1U);
                        CHECK(homeserver::current_typing_users_in_room(runtime, room_id) ==
                              std::vector<std::string>{relay_member});
                        auto durable = database::open_sqlite_persistent_store(config.database().sqlite_path);
                        REQUIRE(durable.ok);
                        CHECK(fed10_target_count(durable.store, event_id) == 1U);
                    }
                }
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

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        REQUIRE(runtime.federation.membership_acceptor);
        runtime.federation.remote_key_resolver = relay_key_resolver();

        auto const room_id = std::string{"!membership-room:example.com"};
        // membership_acceptor runs the room's authorization rules before it
        // persists anything (M-01), so a bare room row is no longer enough: with
        // no m.room.create and no m.room.join_rules in the store there is nothing
        // for the join to be authorized against, and it is refused. Seed the
        // minimum real room state a public join needs, so this scenario exercises
        // the IPC relay it is actually about rather than an unauthorized join.
        REQUIRE(
            merovingian::database::store_room(runtime.database.persistent_store, {room_id, "@resident:example.com"}));
        {
            auto const creator = std::string{"@resident:example.com"};
            auto const* policy = merovingian::rooms::find_room_version_policy("10");
            REQUIRE(policy != nullptr);

            auto seed_state = [&, policy](std::string_view event_id, std::string_view type, std::string_view state_key,
                                          std::string const& content_json, std::uint64_t ordering) {
                using namespace merovingian;

                auto& store = runtime.database.persistent_store;
                auto const prev_events = tests::fixture_prev_event_ids(store, room_id);
                auto const auth_events = tests::fixture_auth_event_ids(store, room_id, creator, false);

                auto event = database::PersistentEvent{};
                event.event_id = std::string{event_id};
                event.room_id = room_id;
                event.sender_user_id = creator;
                event.depth = ordering;
                event.stream_ordering = ordering;
                event.prev_event_ids = prev_events;
                event.auth_event_ids = auth_events;
                event.json = std::string{R"({"room_id":")"} + room_id + R"(","sender":")" + creator +
                             R"(","origin_server_ts":1000,"type":")" + std::string{type} + R"(","state_key":")" +
                             std::string{state_key} + R"(","content":)" + content_json + R"(,"prev_events":)" +
                             json_id_array(prev_events) + R"(,"auth_events":)" + json_id_array(auth_events) + "}";
                auto state = database::PersistentStateEvent{room_id, std::string{type}, std::string{state_key},
                                                            std::string{event_id}};
                REQUIRE(database::store_event_with_state(store, std::move(event), state));

                auto const state_before = homeserver::compute_state_before(store, room_id, *policy, prev_events);
                REQUIRE(state_before.ok);
                auto const state_after =
                    homeserver::compute_state_after(state_before.state, event_id, type, std::string{state_key});
                auto const group =
                    homeserver::record_event_state(store, room_id, event_id, prev_events, state_after, true);
                REQUIRE(group.has_value());
                REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));
            };
            // room_version must match the "room_version":"10" the ingest request
            // below declares, or the event is judged under the wrong rule set.
            seed_state("$seed-create:example.com", "m.room.create", "",
                       R"({"room_version":"10","creator":"@resident:example.com"})", 1U);
            seed_state("$seed-creator-member:example.com", "m.room.member", creator, R"({"membership":"join"})", 2U);
            seed_state("$seed-power-levels:example.com", "m.room.power_levels", "",
                       R"({"users":{"@resident:example.com":100},"users_default":0,"ban":50,"kick":50,"invite":0})",
                       3U);
            // public: the remote user holds no invite, so the join is authorized
            // by the join rule alone.
            seed_state("$seed-join-rules:example.com", "m.room.join_rules", "", R"({"join_rule":"public"})", 4U);
        }

        WHEN("a membership_ingest request shaped like a real worker's is handled")
        {
            auto const sender = std::string{"@remote:matrix.example.org"};
            auto& store = runtime.database.persistent_store;
            auto const join_auth_events = merovingian::tests::fixture_auth_event_ids(store, room_id, sender, false);
            auto const join_prev_events = merovingian::tests::fixture_prev_event_ids(store, room_id);

            auto const event_json = make_membership_event_json(room_id, sender, sender, "join", join_prev_events,
                                                               join_auth_events, 5, 1234);
            auto const request_json =
                std::string{R"({"type":"membership_ingest","endpoint":"send_join","event_id":")"} +
                event_id_of(event_json) + R"(")" + R"(,"room_id":")" + room_id + R"(","room_version":"10","sender":")" +
                sender + R"(","event_type":"m.room.member","state_key":")" + sender +
                R"(","origin_server_ts":1234,"depth":5,"auth_event_ids":)" + json_id_array(join_auth_events) +
                R"(,"prev_event_ids":)" + json_id_array(join_prev_events) + R"(,"signatures":[],"json":)" +
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
        runtime.federation.remote_key_resolver = relay_key_resolver();

        WHEN("a membership_ingest request targets a room that was never stored")
        {
            auto const room_id = std::string{"!never-stored:example.com"};
            auto const sender = std::string{"@remote:matrix.example.org"};
            auto const event_json = make_membership_event_json(room_id, sender, sender, "join", {}, {}, 0, 1234);
            auto const request_json =
                std::string{R"({"type":"membership_ingest","endpoint":"send_join","event_id":")"} +
                event_id_of(event_json) + R"(")" + R"(,"room_id":")" + room_id + R"(","room_version":"10","sender":")" +
                sender + R"(","event_type":"m.room.member","state_key":")" + sender +
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
            auto const target_user = "@local:" + runtime.config.server().server_name;
            auto const target_device = std::string{"DEVICE1"};
            // to-device messages are only delivered to existing local users and devices (FED-3).
            {
                auto persistent = merovingian::database::PersistentUser{};
                persistent.user_id = target_user;
                runtime.database.persistent_store.users.push_back(std::move(persistent));
            }
            {
                auto device = merovingian::database::PersistentDevice{};
                device.user_id = target_user;
                device.device_id = target_device;
                runtime.database.persistent_store.devices.push_back(std::move(device));
            }
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

            auto const response_json =
                merovingian::tests::ingest_edu_with_live_context(runtime, request_json, "matrix.example.org");

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
            auto const target_user = "@james:" + runtime.config.server().server_name;
            auto const target_device = std::string{"DEVICE1"};
            // to-device messages are only delivered to existing local users and devices (FED-3).
            {
                auto persistent = merovingian::database::PersistentUser{};
                persistent.user_id = target_user;
                runtime.database.persistent_store.users.push_back(std::move(persistent));
            }
            {
                auto device = merovingian::database::PersistentDevice{};
                device.user_id = target_user;
                device.device_id = target_device;
                runtime.database.persistent_store.devices.push_back(std::move(device));
            }
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

            auto const response_json =
                merovingian::tests::ingest_edu_with_live_context(runtime, request_json, "matrix.ping.me.uk");

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

        auto channels = merovingian::tests::make_edu_relay_channels();
        // Mirrors worker_pool.cpp's WorkerSupervisor::set_request_handler's
        // "edu_ingest" branch: dispatch the request body to
        // handle_edu_ingest_request() against main's own runtime and send the
        // result back over the same channel.
        channels.main->set_request_handler([&runtime, &channels](std::uint64_t id, std::string json) {
            auto const response = merovingian::homeserver::handle_edu_ingest_request(runtime, json, *channels.main);
            channels.main->send_response(id, response);
        });
        // Keep a real main-owned parent live while the worker relays the EDU.
        // The trusted origin is chosen by this testcase, not read from JSON.
        auto relay_context = merovingian::tests::EduRelayContext{*channels.main, *channels.worker};
        REQUIRE(relay_context.establish("matrix.ping.me.uk"));

        WHEN("the worker side sends a real edu_ingest wire frame carrying an Olm-encrypted room-key share over the "
             "encrypted channel")
        {
            auto const sender = std::string{"@james:matrix.ping.me.uk"};
            auto const target_user = "@james:" + runtime.config.server().server_name;
            auto const target_device = std::string{"DEVICE1"};
            // to-device messages are only delivered to existing local users and devices (FED-3).
            {
                auto persistent = merovingian::database::PersistentUser{};
                persistent.user_id = target_user;
                runtime.database.persistent_store.users.push_back(std::move(persistent));
            }
            {
                auto device = merovingian::database::PersistentDevice{};
                device.user_id = target_user;
                device.device_id = target_device;
                runtime.database.persistent_store.devices.push_back(std::move(device));
            }
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

            auto const reply =
                channels.worker->send_request(relay_context.wrap(request_json), std::chrono::seconds{10});

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

        REQUIRE(relay_context.finish());
    }
}

SCENARIO("Main refuses a sign_request frame from a worker without signing and without taking the runtime lock",
         "[integration][federation-worker][ipc][security][worker_signing_refused]")
{
    // Security audit 2026-09-29, CRY-1 (ADR-0078). The federation worker is the
    // process most exposed to hostile input and has no production need for a
    // signature, so main no longer answers sign_request: a compromised worker
    // must not be able to mint signatures as this server, and must not be able
    // to park main's global runtime lock behind a signing call either.
    GIVEN("a main runtime that holds a real signing key and a real IpcChannel pair standing in for the worker link")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-sign-refused");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "sign-refused-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // Precondition that gives the test its teeth: main really could sign.
        REQUIRE(runtime.crypto_provider != nullptr);

        auto channels = make_ipc_test_channel_pair();
        // Mirrors WorkerPool's per-shard request handler, which consults
        // refuse_forbidden_worker_request before any other frame type.
        channels.server->set_request_handler([srv = channels.server.get()](std::uint64_t id, std::string json) {
            auto const type = merovingian::ipc::ipc_json_get_str(json, "type");
            if (!merovingian::homeserver::refuse_forbidden_worker_request(*srv, id, type))
            {
                srv->send_response(id, R"({"type":"unexpected_frame_handled"})");
            }
        });
        channels.server->start();
        channels.client->start();

        // Hold main's global runtime lock on this thread for the whole WHEN
        // block. The IPC dispatch thread is a different thread, so a handler
        // that tried to take the lock would block until the request timeout and
        // the reply below would never arrive. That makes "the lock is not
        // taken" observable without any sleep-based synchronisation.
        auto runtime_guard = std::unique_lock<merovingian::homeserver::RuntimeMutex>{runtime.mutex};

        WHEN("the worker sends a sign_request for the active key carrying a serialised PDU")
        {
            auto const pdu =
                std::string{R"({"type":"m.room.message","sender":"@victim:example.org","room_id":"!r:example.org",)"
                            R"("content":{"body":"forged"},"origin_server_ts":1})"};
            auto const request = std::string{R"({"type":"sign_request","key_id":"ed25519:any","canonical_json":)"} +
                                 ipc_escape_json_string(pdu) + "}";
            auto const reply = channels.client->send_request(request, std::chrono::seconds{10});

            THEN("main answers with an error frame and no signature, while the runtime lock was held elsewhere")
            {
                REQUIRE(reply.has_value());
                INFO("reply: " << *reply);
                REQUIRE(merovingian::ipc::ipc_json_get_str(*reply, "type") == "error");
                REQUIRE(merovingian::ipc::ipc_json_get_str(*reply, "reason").empty() == false);
                REQUIRE(reply->find("\"signature\"") == std::string::npos);
                REQUIRE(reply->find("sign_response") == std::string::npos);
            }
        }

        WHEN("the worker sends a sign_request carrying arbitrary non-JSON bytes")
        {
            auto const request = std::string{
                R"({"type":"sign_request","key_id":"ed25519:auto","canonical_json":"\u0000\u0001 not json"})"};
            auto const reply = channels.client->send_request(request, std::chrono::seconds{10});

            THEN("main still answers with an error frame and no signature")
            {
                REQUIRE(reply.has_value());
                INFO("reply: " << *reply);
                REQUIRE(merovingian::ipc::ipc_json_get_str(*reply, "type") == "error");
                REQUIRE(reply->find("\"signature\"") == std::string::npos);
            }
        }

        WHEN("the worker sends a frame type main does accept from workers")
        {
            auto const type = std::string{"edu_ingest"};
            auto const refused = merovingian::homeserver::refuse_forbidden_worker_request(*channels.server, 1U, type);

            THEN("the refusal helper leaves it alone so the normal handler can serve it")
            {
                REQUIRE_FALSE(refused);
            }
        }

        runtime_guard.unlock();
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

            auto const response_json =
                merovingian::tests::ingest_edu_with_live_context(runtime, request_json, "matrix.example.org");

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

            auto const response_json =
                merovingian::tests::ingest_edu_with_live_context(runtime, request_json, "matrix.example.org");

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
        runtime.federation.remote_key_resolver = relay_key_resolver();

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
            auto const event_json = make_membership_event_json(room_id, sender, target_user, "invite", {"$remote-prev"},
                                                               {"$remote-create"}, 5, 1234);

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
                                      R"(,"event_id":)" + escape(event_id_of(event_json)) + R"(,"room_version":"10",)" +
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
        runtime.federation.remote_key_resolver = relay_key_resolver();
        // Deliberately do NOT register target_user in runtime.database.users.

        WHEN("an invite_ingest request targets a user who was never registered locally")
        {
            auto const room_id = std::string{"!invite-room-404:matrix.example.org"};
            auto const sender = std::string{"@remote:matrix.example.org"};
            auto const target_user = std::string{"@nobody:"} + config.server().server_name;
            auto const event_json = make_membership_event_json(room_id, sender, target_user, "invite", {"$remote-prev"},
                                                               {"$remote-create"}, 5, 1234);

            auto const request_json =
                std::string{R"({"type":"invite_ingest","room_id":)"} + ipc_escape_json_string(room_id) +
                R"(,"event_id":)" + ipc_escape_json_string(event_id_of(event_json)) + R"(,"room_version":"10",)" +
                R"("invite_event_json":)" + ipc_escape_json_string(event_json) + R"(,"invite_room_state_json":[]})";

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
        auto const member_id = std::string{"@member:member.example.org"};
        REQUIRE(merovingian::database::store_event(
            runtime.database.persistent_store,
            {event_id, room_id, std::string{"@sender:"} + config.server().server_name,
             R"({"type":"m.room.message","content":{"body":"event-query-relay-marker"}})"}));
        // FED-2: a server may read an event only when it has a joined user in
        // the event's room, so give the room one on member.example.org.
        REQUIRE(merovingian::database::store_event(
            runtime.database.persistent_store,
            {"$member_join", room_id, member_id,
             R"({"type":"m.room.member","state_key":"@member:member.example.org","content":{"membership":"join"}})"}));
        REQUIRE(merovingian::database::store_state(runtime.database.persistent_store,
                                                   {room_id, "m.room.member", member_id, "$member_join"}));

        auto const relay = [&](std::string const& origin) {
            auto const request_json = std::string{R"({"type":"event_query_ingest","event_id":)"} +
                                      ipc_escape_json_string(event_id) + R"(,"origin":)" +
                                      ipc_escape_json_string(origin) + "}";
            return merovingian::homeserver::handle_event_query_ingest_request(runtime, request_json);
        };

        WHEN("an event_query_ingest request shaped like a real worker's is handled for a server in the room")
        {
            auto const response_json = relay("member.example.org");

            THEN("the response reflects main's own store rather than an empty worker-local snapshot")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("status":"ok")") != std::string::npos);
                REQUIRE(response_json.find("event-query-relay-marker") != std::string::npos);
            }
        }

        WHEN("the same request is made on behalf of a server with no user in the room")
        {
            auto const response_json = relay("stranger.example.net");

            THEN("main answers forbidden and the frame carries no event body")
            {
                INFO("response: " << response_json);
                REQUIRE(response_json.find(R"("status":"forbidden")") != std::string::npos);
                REQUIRE(response_json.find("event-query-relay-marker") == std::string::npos);
            }
        }

        WHEN("the request frame carries no origin at all")
        {
            auto const request_json =
                std::string{R"({"type":"event_query_ingest","event_id":)"} + ipc_escape_json_string(event_id) + "}";
            auto const response_json =
                merovingian::homeserver::handle_event_query_ingest_request(runtime, request_json);

            THEN("it fails closed rather than reading unrestricted")
            {
                REQUIRE(response_json.find("event-query-relay-marker") == std::string::npos);
                REQUIRE(response_json.find(R"("status":"forbidden")") != std::string::npos);
            }
        }
    }
}

SCENARIO("The wired federation providers refuse a server outside the room and serve one inside it",
         "[integration][federation-worker][query-relay][fed2][security]")
{
    // The providers wire_federation_callbacks installs are the ones both main and
    // the federation worker (from its room snapshot) run, so this drives the
    // production lambdas end to end for all five room-scoped reads.
    GIVEN("a wired runtime holding a room with one joined user on member.example.org")
    {
        REQUIRE(sodium_init() >= 0);

        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-fed2");
        auto config = make_federation_worker_config(tmp_dir);
        config.database().sqlite_path = (tmp_dir / "fed2-test.sqlite3").string();

        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto& store = runtime.database.persistent_store;
        auto const room_id = std::string{"!private:"} + config.server().server_name;
        auto const member_id = std::string{"@member:member.example.org"};
        REQUIRE(merovingian::database::store_event(
            store, {"$create", room_id, member_id, R"({"type":"m.room.create","state_key":"","content":{}})", 1U, 1U}));
        REQUIRE(merovingian::database::store_event(
            store,
            {"$join", room_id, member_id,
             R"({"type":"m.room.member","state_key":"@member:member.example.org","content":{"membership":"join"}})", 2U,
             2U, std::vector<std::string>{"$create"}}));
        REQUIRE(merovingian::database::store_event(
            store, {"$msg", room_id, member_id, R"({"type":"m.room.message","content":{"body":"secret-body"}})", 3U, 3U,
                    std::vector<std::string>{"$join"}}));
        REQUIRE(merovingian::database::store_state(store, {room_id, "m.room.create", "", "$create"}));
        REQUIRE(merovingian::database::store_state(store, {room_id, "m.room.member", member_id, "$join"}));

        auto const stranger = std::string{"stranger.example.net"};
        auto const member = std::string{"member.example.org"};
        auto& fed = runtime.federation;
        REQUIRE(fed.event_query_provider);
        REQUIRE(fed.state_query_provider);
        REQUIRE(fed.state_ids_query_provider);
        REQUIRE(fed.missing_events_query_provider);
        REQUIRE(fed.backfill_provider);
        auto const missing_body = std::string{R"({"latest_events":["$msg"],"earliest_events":[],"limit":10})"};
        auto const backfill = [&](std::string const& origin) {
            auto request = merovingian::federation::BackfillRequest{};
            request.room_id = room_id;
            request.event_ids = {"$msg"};
            request.limit = 10U;
            request.origin = origin;
            return fed.backfill_provider(request);
        };
        using merovingian::federation::RoomReadStatus;

        WHEN("a server with no user in the room calls each of the five reads")
        {
            auto const event = fed.event_query_provider("$msg", stranger);
            auto const state = fed.state_query_provider(room_id, "$msg", stranger);
            auto const state_ids = fed.state_ids_query_provider(room_id, "$msg", stranger);
            auto const missing = fed.missing_events_query_provider(room_id, missing_body, stranger);
            auto const backfilled = backfill(stranger);

            THEN("each is refused and none returns room data")
            {
                REQUIRE(event.status == RoomReadStatus::forbidden);
                REQUIRE(state.status == RoomReadStatus::forbidden);
                REQUIRE(state_ids.status == RoomReadStatus::forbidden);
                REQUIRE(missing.status == RoomReadStatus::forbidden);
                REQUIRE_FALSE(backfilled.accepted);
                REQUIRE(backfilled.status == 403U);
                REQUIRE(event.body.empty());
                REQUIRE(state.body.empty());
                REQUIRE(state_ids.body.empty());
                REQUIRE(missing.body.empty());
                REQUIRE(backfilled.pdus_json.empty());
            }
        }

        WHEN("the server with a joined user calls each of the five reads")
        {
            auto const event = fed.event_query_provider("$msg", member);
            auto const state = fed.state_query_provider(room_id, "$msg", member);
            auto const state_ids = fed.state_ids_query_provider(room_id, "$msg", member);
            auto const missing = fed.missing_events_query_provider(room_id, missing_body, member);
            auto const backfilled = backfill(member);

            THEN("each succeeds")
            {
                REQUIRE(event.status == RoomReadStatus::ok);
                REQUIRE(event.body.find("secret-body") != std::string::npos);
                REQUIRE(state.status == RoomReadStatus::ok);
                REQUIRE(state_ids.status == RoomReadStatus::ok);
                REQUIRE(missing.status == RoomReadStatus::ok);
                REQUIRE(backfilled.accepted);
                REQUIRE_FALSE(backfilled.pdus_json.empty());
            }
        }

        WHEN("the room is then made world readable")
        {
            REQUIRE(merovingian::database::store_event(
                store,
                {"$hv", room_id, member_id,
                 R"({"type":"m.room.history_visibility","state_key":"","content":{"history_visibility":"world_readable"}})",
                 4U, 4U, std::vector<std::string>{"$msg"}}));
            REQUIRE(merovingian::database::store_state(store, {room_id, "m.room.history_visibility", "", "$hv"}));

            THEN("a server with no user in the room can read it")
            {
                REQUIRE(fed.event_query_provider("$msg", stranger).status == RoomReadStatus::ok);
                REQUIRE(fed.state_ids_query_provider(room_id, "$msg", stranger).status == RoomReadStatus::ok);
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

SCENARIO("FederationProxy serves version discovery locally without authentication",
         "[integration][federation-proxy][version][authentication]")
{
    GIVEN("a FederationProxy wrapping a healthy worker pool")
    {
        if (worker_binary_path().empty())
        {
            SKIP("MEROVINGIAN_TEST_FEDERATION_WORKER is not defined");
        }

        REQUIRE(sodium_init() >= 0);
        auto const tmp_dir = unique_temp_dir("merovingian-fed-proxy-version");
        auto config = make_federation_worker_config(tmp_dir);
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);
        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto proxy = FederationProxy{config.federation_worker(), started.runtime, std::string{worker_binary_path()},
                                     config_path.string()};
        REQUIRE(wait_for_healthy(proxy, std::chrono::seconds{15}));

        WHEN("an unsigned GET version request passes through the proxy")
        {
            auto const response = proxy.handle(make_fed_request("GET", "/_matrix/federation/v1/version"));

            THEN("the main process returns the version response without consulting federation authorization")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"name\":\"Merovingian\"") != std::string::npos);
                REQUIRE(response.body.find("\"version\":\"" MEROVINGIAN_VERSION "\"") != std::string::npos);
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
#ifndef __linux__
        // seccomp-bpf and the sibling controls apply_worker_hardening() installs
        // are Linux-only. apply_worker_hardening() now fails closed on other
        // platforms instead of silently accepting (see runtime_hardening.cpp) --
        // with apply_hardening=true below, the worker process now correctly
        // refuses to start here, so this scenario's "reaches healthy" assertion
        // no longer applies on non-Linux. The fail-closed behaviour itself is
        // covered by tests/unit/test_runtime_hardening.cpp.
        SKIP("worker seccomp scenario is Linux-only; other platforms fail closed by design when "
             "federation.worker.apply_hardening=true because there is no in-process worker sandbox there");
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
            // The worker seccomp scenario must run as an unprivileged user.
            // CI containers run as root, and a root worker hits two unrelated
            // seccomp failures: SQLite's robustFchown() issues fchown(), and the
            // worker hardening sequence cannot drop the capability bounding set
            // without CAP_SETPCAP. Production workers are spawned by a non-root
            // service user, so the real filter behaviour is covered by the unit
            // seccomp tests and by manual integration runs as a non-root user.
            if (::geteuid() == 0)
            {
                SKIP("worker seccomp scenario skipped under root; run as a non-root user to exercise the filter");
            }

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

        auto supervisor = WorkerSupervisor{
            std::string{worker_binary_path()}, config_path.string(), config.federation_worker().request_timeout_seconds,
            0U, derive_worker_ipc_auth_key_material(config.security().secrets.master_key_file)};
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

        auto supervisor = WorkerSupervisor{
            std::string{worker_binary_path()}, config_path.string(), config.federation_worker().request_timeout_seconds,
            0U, derive_worker_ipc_auth_key_material(config.security().secrets.master_key_file)};
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

SCENARIO("WorkerSupervisor retries a transient spawn failure without losing supervision",
         "[iso-3][integration][federation-worker][supervisor]")
{
    GIVEN("a supervised real worker whose executable temporarily disappears")
    {
        REQUIRE_FALSE(worker_binary_path().empty());
        REQUIRE(sodium_init() >= 0);
        auto const tmp_dir = unique_temp_dir("merovingian-fed-worker-spawn-retry");
        auto config = make_federation_worker_config(tmp_dir);
        config.federation_worker().request_timeout_seconds = 2U;
        auto const config_path = tmp_dir / "merovingian.conf";
        write_worker_config(config_path, config);
        auto started = start_runtime(config);
        REQUIRE(started.started);
        auto const executable = tmp_dir / "worker-link";
        auto const real_binary = std::filesystem::absolute(std::string{worker_binary_path()});
        std::filesystem::create_symlink(real_binary, executable);
        auto supervisor =
            WorkerSupervisor{executable.string(), config_path.string(), 2U, 0U,
                             derive_worker_ipc_auth_key_material(config.security().secrets.master_key_file)};
        supervisor.start();
        auto const original_pid = supervisor.worker_pid();
        REQUIRE(original_pid > 0);
        std::filesystem::remove(executable);
        REQUIRE(::kill(original_pid, SIGKILL) == 0);
        auto const reap_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (supervisor.worker_pid() == original_pid && std::chrono::steady_clock::now() < reap_deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        REQUIRE(supervisor.worker_pid() == -1);
        // The first retry has a one-second backoff. Keep the path absent through
        // that attempt so this exercises posix_spawn failure, not just a crash.
        std::this_thread::sleep_for(std::chrono::milliseconds{1500});
        REQUIRE_FALSE(supervisor.healthy());
        WHEN("the executable becomes available again")
        {
            std::filesystem::create_symlink(real_binary, executable);
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{8};
            while ((supervisor.worker_pid() <= 0 || !supervisor.healthy()) &&
                   std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{20});
            }
            THEN("a new owned child is started and the supervisor becomes healthy")
            {
                CHECK(supervisor.worker_pid() > 0);
                CHECK(supervisor.worker_pid() != original_pid);
                CHECK(supervisor.healthy());
            }
            supervisor.stop();
            CHECK(supervisor.worker_pid() == -1);
            CHECK_FALSE(supervisor.healthy());
        }
        WHEN("shutdown is requested during retry backoff")
        {
            auto const began = std::chrono::steady_clock::now();
            supervisor.stop();
            THEN("shutdown interrupts the backoff promptly")
            {
                CHECK(std::chrono::steady_clock::now() - began < std::chrono::milliseconds{500});
                CHECK(supervisor.worker_pid() == -1);
                CHECK_FALSE(supervisor.healthy());
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

        auto supervisor = WorkerSupervisor{
            std::string{worker_binary_path()}, config_path.string(), config.federation_worker().request_timeout_seconds,
            0U, derive_worker_ipc_auth_key_material(config.security().secrets.master_key_file)};
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

// FED-12 exercises the public relay handler with real pending channel requests.
// This deliberately mirrors only WorkerPool's EDU dispatch branch: it does not
// prove production handler registration, restart wiring, or signed-body binding.
#include <condition_variable>
#include <future>
#include <limits>
#include <optional>
#include <utility>
#include <variant>

namespace
{

[[nodiscard]] auto fed12_json(merovingian::canonicaljson::Object object) -> std::string
{
    auto const encoded =
        merovingian::canonicaljson::serialize_canonical_strict(merovingian::canonicaljson::Value{std::move(object)});
    REQUIRE(encoded.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return encoded.output;
}

[[nodiscard]] auto fed12_text(std::string_view text) -> merovingian::canonicaljson::Value
{
    return merovingian::canonicaljson::Value{std::string{text}};
}

[[nodiscard]] auto fed12_random_credential() -> std::string
{
    auto bytes = merovingian::core::SecretBuffer{32U};
    randombytes_buf(bytes.bytes().data(), bytes.bytes().size());
    auto const alphabet = std::string_view{"0123456789abcdef"};
    auto result = std::string{};
    for (auto const byte : bytes.bytes())
    {
        result += alphabet[byte >> 4U];
        result += alphabet[byte & 15U];
    }
    return result;
}

[[nodiscard]] auto fed12_authenticated_channels() -> IpcTestChannelPair
{
    auto [server_fd, client_fd] = make_ipc_test_socketpair();
    auto material = merovingian::core::SecretBuffer{32U};
    randombytes_buf(material.bytes().data(), material.bytes().size());
    auto const authentication = merovingian::crypto::derive_ipc_auth_key(material.bytes());
    REQUIRE(authentication.has_value());
    auto channels = IpcTestChannelPair{};
    auto server_error = std::exception_ptr{};
    auto client_error = std::exception_ptr{};
    // JoiningThreads, not std::jthread: FreeBSD and OpenBSD libc++ lack jthread.
    auto handshakes = merovingian::tests::JoiningThreads{};
    handshakes.emplace_back([&] {
        try
        {
            channels.server = std::make_unique<merovingian::ipc::IpcChannel>(
                std::move(server_fd), merovingian::ipc::IpcChannel::Role::server, *authentication);
        }
        catch (...)
        {
            server_error = std::current_exception();
        }
    });
    handshakes.emplace_back([&] {
        try
        {
            channels.client = std::make_unique<merovingian::ipc::IpcChannel>(
                std::move(client_fd), merovingian::ipc::IpcChannel::Role::client, *authentication);
        }
        catch (...)
        {
            client_error = std::current_exception();
        }
    });
    handshakes.join();
    REQUIRE(!server_error);
    REQUIRE(!client_error);
    return channels;
}

struct Fed12ReceivedParent final
{
    std::uint64_t id{};
    merovingian::homeserver::LocalHttpRequest request{};
};

class Fed12PendingRelay final
{
public:
    explicit Fed12PendingRelay(merovingian::homeserver::HomeserverRuntime& runtime)
        : runtime_(runtime)
        , channels_(fed12_authenticated_channels())
    {
        channels_.server->set_request_handler([this](std::uint64_t id, std::string frame) {
            // Validate against this exact receiving main channel's live parent.
            auto const response =
                merovingian::homeserver::handle_edu_ingest_request(runtime_, frame, *channels_.server);
            channels_.server->send_response(id, response);
        });
        channels_.client->set_request_handler([this](std::uint64_t id, std::string frame) {
            auto const request = merovingian::ipc::deserialize_fed_request(frame);
            auto guard = std::lock_guard{mutex_};
            if (releasing_)
            {
                channels_.client->send_response(id, completion_);
                return;
            }
            parents_.push_back({id, request});
            received_.notify_all();
            // The dispatch thread returns without replying. A separate test
            // future sends EDU RPCs while this real main->worker call is pending.
        });
        channels_.server->start();
        channels_.client->start();
    }
    Fed12PendingRelay(Fed12PendingRelay const&) = delete;
    auto operator=(Fed12PendingRelay const&) -> Fed12PendingRelay& = delete;
    ~Fed12PendingRelay() noexcept
    {
        std::ignore = finish();
        channels_.server->stop();
        channels_.client->stop();
    }

    [[nodiscard]] auto send_parent(merovingian::homeserver::LocalHttpRequest const& request)
        -> std::optional<Fed12ReceivedParent>
    {
        auto index = std::size_t{};
        {
            auto guard = std::lock_guard{mutex_};
            index = parents_.size();
        }
        auto frame = merovingian::ipc::serialize_fed_request(request);
        pending_.push_back(
            std::async(std::launch::async, [this, frame = std::move(frame), origin = request.verified_origin] {
                return channels_.server->send_request(frame, std::chrono::seconds{60}, origin);
            }));
        auto guard = std::unique_lock{mutex_};
        if (!received_.wait_for(guard, std::chrono::seconds{10}, [&] {
                return parents_.size() > index;
            }))
            return std::nullopt;
        return parents_[index];
    }

    [[nodiscard]] auto parent_is_pending(std::size_t index) -> bool
    {
        return pending_.at(index).wait_for(std::chrono::seconds{0}) == std::future_status::timeout;
    }

    [[nodiscard]] auto relay(std::string frame) -> std::optional<std::string>
    {
        auto response = std::async(std::launch::async, [this, frame = std::move(frame)] {
            return channels_.client->send_request(frame, std::chrono::seconds{10});
        });
        return response.get();
    }

    // Also called on unwinding: release the held responses before joining any
    // callers or destroying either channel. Never wait with a runtime/list lock.
    [[nodiscard]] auto finish() noexcept -> bool
    {
        if (finished_)
            return completion_ok_;
        try
        {
            {
                auto guard = std::lock_guard{mutex_};
                releasing_ = true;
                for (auto const& parent : parents_)
                    channels_.client->send_response(parent.id, completion_);
            }
            for (auto& pending : pending_)
            {
                if (pending.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
                {
                    completion_ok_ = false;
                    channels_.server->stop();
                    channels_.client->stop();
                }
                auto const response = pending.get();
                if (!response.has_value() || merovingian::ipc::deserialize_fed_response(*response).status != 200U)
                    completion_ok_ = false;
            }
        }
        catch (...)
        {
            completion_ok_ = false;
            channels_.server->stop();
            channels_.client->stop();
            for (auto& pending : pending_)
                if (pending.valid())
                    pending.wait();
        }
        finished_ = true;
        return completion_ok_;
    }

private:
    merovingian::homeserver::HomeserverRuntime& runtime_;
    IpcTestChannelPair channels_;
    std::mutex mutex_{};
    std::condition_variable received_{};
    std::vector<Fed12ReceivedParent> parents_{};
    std::vector<std::future<std::optional<std::string>>> pending_{};
    std::string completion_{merovingian::ipc::serialize_fed_response({200U, "{}"})};
    bool releasing_{false};
    bool finished_{false};
    bool completion_ok_{true};
};

} // namespace

SCENARIO("Main binds worker EDU origins to genuinely verified pending federation requests",
         "[integration][federation][federation-worker][fed-12-origin-binding]")
{
    using namespace merovingian;
    using canonicaljson::make_member;
    using canonicaljson::Value;

    GIVEN("a SQLite client runtime, a publicly registered device, and two genuine federation signing identities")
    {
        REQUIRE(sodium_init() >= 0);
        auto const directory = unique_temp_dir("fed12-origin-binding");
        auto cleanup = Fed10TempDirectory{directory};
        auto config = make_federation_worker_config(directory);
        config.security().registration.enabled = true;
        config.security().registration.require_token = true;
        auto const registration_token = fed12_random_credential();
        auto const registration_token_path = directory / "registration.allow";
        write_file(registration_token_path, registration_token + "\n");
        std::filesystem::permissions(registration_token_path, std::filesystem::perms::owner_read);
        config.security().registration.token_file = registration_token_path.string();
        auto started = homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& client = started.runtime;
        auto& runtime = client.homeserver;
        homeserver::wire_federation_callbacks(runtime);
        REQUIRE(static_cast<bool>(runtime.federation.edu_sink));
        REQUIRE(static_cast<bool>(client.sync_notifier));

        // Public registration creates both the durable account/device and the
        // separate client device read model. No fixture-only vector insertion.
        auto password = fed12_random_credential();
        // Keep the generated password random while satisfying the real policy.
        password[0] = static_cast<char>(65U + static_cast<unsigned char>(password[0]) % 26U);
        password[1] = static_cast<char>(97U + static_cast<unsigned char>(password[1]) % 26U);
        password[2] = static_cast<char>(48U + static_cast<unsigned char>(password[2]) % 10U);
        password[3] = static_cast<char>(33U + static_cast<unsigned char>(password[3]) % 15U);
        auto const registration_body = fed12_json({
            make_member("username", fed12_text("fed12recipient")),
            make_member("password", fed12_text(password)),
            make_member("device_id", fed12_text("FED12DEVICE")),
            make_member("auth", Value{canonicaljson::Object{
                                    make_member("type", fed12_text("m.login.registration_token")),
                                    make_member("token", fed12_text(registration_token)),
                                }}
             ),
        });
        auto const registration = homeserver::handle_client_server_request(
            client, {"POST", "/_matrix/client/v3/register", {}, registration_body});
        REQUIRE(registration.response.status == 200U);
        auto const recipient = ipc::ipc_json_get_str(registration.response.body, "user_id");
        auto const device = ipc::ipc_json_get_str(registration.response.body, "device_id");
        auto const access = ipc::ipc_json_get_str(registration.response.body, "access_token");
        REQUIRE(!recipient.empty());
        REQUIRE(!device.empty());
        REQUIRE(!access.empty());
        REQUIRE(homeserver::device_count(client, recipient) == 1U);
        auto const listed =
            homeserver::handle_client_server_request(client, {"GET", "/_matrix/client/v3/devices", access, {}});
        REQUIRE(listed.response.status == 200U);

        auto key_a = crypto::generate_ed25519_keypair();
        auto key_b = crypto::generate_ed25519_keypair();
        REQUIRE(key_a.has_value());
        REQUIRE(key_b.has_value());
        auto const origin_a = std::string{"fed12-a.example"};
        auto const origin_b = std::string{"fed12-b.example"};
        auto const id_a = std::string{"ed25519:"} + fed12_random_credential().substr(0U, 12U);
        auto const id_b = std::string{"ed25519:"} + fed12_random_credential().substr(0U, 12U);
        auto const now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        auto const remote_record = [&](std::string const& origin, std::string const& id,
                                       crypto::Ed25519Keypair const& key) {
            auto remote = federation::FederationRemoteRuntime{};
            remote.server_name = origin;
            remote.discovery.server_name = origin;
            remote.discovery.resolved_host = origin;
            remote.discovery.resolved_addresses = {"1.1.1.1"};
            remote.signing_key = {
                origin, id, now + 3600000U, std::string{key.public_key.begin(), key.public_key.end()}
            };
            return remote;
        };
        auto const remote_a = remote_record(origin_a, id_a, *key_a);
        auto const remote_b = remote_record(origin_b, id_b, *key_b);
        // This provider returns published key data only for the exact generated
        // identities. The production verifier still performs Ed25519 verification.
        runtime.federation.remote_key_resolver =
            [remote_a, remote_b](std::string_view origin,
                                 std::string_view id) -> std::optional<federation::FederationRemoteRuntime> {
            if (origin == remote_a.server_name && id == remote_a.signing_key.key_id)
                return remote_a;
            if (origin == remote_b.server_name && id == remote_b.signing_key.key_id)
                return remote_b;
            return std::nullopt;
        };

        auto const message_type = std::string{"org.merovingian.fed12.origin_binding"};
        auto const marker_a = fed12_json({make_member("marker", fed12_text("same-origin-control"))});
        auto const marker_b = fed12_json({make_member("marker", fed12_text("foreign-origin-retry"))});
        auto const content = [&](std::string const& origin, std::string_view message_id, std::string const& marker) {
            auto parsed_marker = canonicaljson::parse_lossless(marker);
            REQUIRE(parsed_marker.error == canonicaljson::ParseError::none);
            return fed12_json({
                make_member("sender", fed12_text("@sender:" + origin)),
                make_member("type", fed12_text(message_type)),
                make_member("message_id", fed12_text(message_id)),
                make_member("messages", Value{canonicaljson::Object{
                                            make_member(recipient, Value{canonicaljson::Object{make_member(
                                                                       device, std::move(parsed_marker.value))}})}}),
            });
        };
        auto const content_a = content(origin_a, "fed12-control", marker_a);
        auto const content_b = content(origin_b, "fed12-unchanged-retry", marker_b);
        auto const verified_parent = [&](std::string const& origin, std::string const& id,
                                         crypto::Ed25519Keypair const& key, std::string const& edu_content,
                                         std::string_view transaction_id) {
            auto const body = federation::build_edu_transaction_body(origin, "m.direct_to_device", edu_content);
            REQUIRE(body.has_value());
            auto const target = std::string{"/_matrix/federation/v1/send/"} + std::string{transaction_id};
            auto call = federation::OutboundCall{};
            call.transaction = federation::make_outbound_transaction(runtime.config.server().server_name, "PUT", target,
                                                                     origin, *body);
            call.key_id = id;
            call.secret_key = core::SecretBuffer{key.secret_key.bytes()};
            auto const signed_http = federation::build_outbound_request(call);
            auto const authorization = std::ranges::find_if(signed_http.headers, [](auto const& header) {
                return header.name == "Authorization";
            });
            REQUIRE(bool{authorization != signed_http.headers.end()});
            auto const credentials = federation::parse_x_matrix_authorization_header(authorization->value);
            REQUIRE(credentials.has_value());
            auto signed_request = federation::SignedFederationRequest{};
            signed_request.method = "PUT";
            signed_request.target = target;
            signed_request.origin = credentials->origin;
            signed_request.destination = credentials->destination;
            signed_request.key_id = credentials->key_id;
            signed_request.signature = credentials->signature;
            signed_request.body = *body;
            signed_request.now_ts = now;
            signed_request.remote_addr = "203.0.113.12";
            signed_request.canonical_json_verified =
                canonicaljson::parse_lossless(*body).error == canonicaljson::ParseError::none;
            auto const verification =
                federation::verify_inbound_federation_signature(runtime.federation, signed_request);
            REQUIRE(verification.accepted);
            REQUIRE(bool{verification.identity.origin == origin});
            REQUIRE(bool{verification.identity.key_id == id});
            auto request = make_fed_request("PUT", target, *body);
            request.sig_verified = true;
            request.verified_origin = verification.identity.origin;
            request.verified_key_id = verification.identity.key_id;
            return request;
        };

        auto const request_a = verified_parent(origin_a, id_a, *key_a, content_a, "fed12-parent-a");
        auto relay = Fed12PendingRelay{runtime};
        auto const parent_a = relay.send_parent(request_a);
        REQUIRE(parent_a.has_value());
        REQUIRE(parent_a->id > 0U);
        REQUIRE(parent_a->request.sig_verified);
        REQUIRE(bool{parent_a->request.verified_origin == origin_a});
        REQUIRE(bool{parent_a->request.verified_key_id == request_a.verified_key_id});
        REQUIRE(bool{parent_a->request.body == request_a.body});
        REQUIRE(parent_a->request.access_token.empty());
        REQUIRE(relay.parent_is_pending(0U));

        auto const frame = [&](std::uint64_t parent_id, std::string const& origin, std::string const& edu_content) {
            // IDs come from the receiving channel, never a guessed counter.
            // canonicaljson stores integers as int64; check before conversion.
            REQUIRE(parent_id <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));
            return fed12_json({
                make_member("type", fed12_text("edu_ingest")),
                make_member("parent_request_id", Value{static_cast<std::int64_t>(parent_id)}),
                make_member("origin", fed12_text(origin)),
                make_member("edu_type", fed12_text("m.direct_to_device")),
                make_member("content_json", fed12_text(edu_content)),
            });
        };
        auto const same_rows = [](auto const& left, auto const& right) {
            return std::ranges::equal(left, right, [](auto const& a, auto const& b) {
                return a.stream_id == b.stream_id && a.sender_user_id == b.sender_user_id &&
                       a.target_user_id == b.target_user_id && a.target_device_id == b.target_device_id &&
                       a.message_type == b.message_type && a.content_json == b.content_json;
            });
        };
        struct Snapshot final
        {
            std::vector<database::PersistentToDeviceMessage> rows{};
            std::uint64_t watermark{};
            std::uint64_t notified{};
        };
        auto const snapshot = [&] {
            auto guard = std::lock_guard{runtime.mutex};
            auto durable = database::open_sqlite_persistent_store(config.database().sqlite_path);
            REQUIRE(durable.ok);
            auto const addressed = [&](auto const& store) {
                auto rows = std::vector<database::PersistentToDeviceMessage>{};
                for (auto const& row : store.to_device_messages)
                    if (row.target_user_id == recipient && row.target_device_id == device)
                        rows.push_back(row);
                return rows;
            };
            auto rows = addressed(durable.store);
            REQUIRE(same_rows(rows, addressed(runtime.database.persistent_store)));
            REQUIRE(durable.store.next_sync_stream_id == runtime.database.persistent_store.next_sync_stream_id);
            return Snapshot{std::move(rows), durable.store.next_sync_stream_id,
                            client.sync_notifier->current_sync_stream_id()};
        };
        auto const marker_count = [&](Snapshot const& state, std::string const& origin, std::string const& marker) {
            return std::ranges::count_if(state.rows, [&](auto const& row) {
                return row.sender_user_id == "@sender:" + origin && row.message_type == message_type &&
                       row.content_json == marker;
            });
        };

        WHEN("the worker relays B's valid sender and EDU under A's still-pending authenticated parent")
        {
            THEN("the origin mismatch has no durable or sync effects and does not poison B's unchanged retry")
            {
                auto const before_control = snapshot();
                REQUIRE(before_control.rows.empty());
                auto const control = relay.relay(frame(parent_a->id, origin_a, content_a));
                REQUIRE(control.has_value());
                REQUIRE(bool{ipc::ipc_json_get_str(*control, "status") == "accepted"});
                auto const before_forgery = snapshot();
                REQUIRE(before_forgery.rows.size() == 1U);
                REQUIRE(marker_count(before_forgery, origin_a, marker_a) == 1);
                REQUIRE(marker_count(before_forgery, origin_b, marker_b) == 0);
                REQUIRE(before_forgery.watermark > before_control.watermark);
                REQUIRE(before_forgery.notified > before_control.notified);
                REQUIRE(relay.parent_is_pending(0U));

                auto const forged = relay.relay(frame(parent_a->id, origin_b, content_b));
                REQUIRE(forged.has_value());
                // Nonfatal behavioral RED checks: cleanup and the dedup control
                // must still execute against the currently vulnerable handler.
                CHECK(bool{ipc::ipc_json_get_str(*forged, "status") == "rejected_invalid"});
                auto const after_forgery = snapshot();
                CHECK(same_rows(after_forgery.rows, before_forgery.rows));
                CHECK(marker_count(after_forgery, origin_b, marker_b) == 0);
                CHECK(after_forgery.watermark == before_forgery.watermark);
                CHECK(after_forgery.notified == before_forgery.notified);
                REQUIRE(relay.parent_is_pending(0U));

                auto const request_b = verified_parent(origin_b, id_b, *key_b, content_b, "fed12-parent-b");
                auto const parent_b = relay.send_parent(request_b);
                REQUIRE(parent_b.has_value());
                REQUIRE(parent_b->id != parent_a->id);
                REQUIRE(parent_b->request.sig_verified);
                REQUIRE(bool{parent_b->request.verified_origin == origin_b});
                REQUIRE(bool{parent_b->request.verified_key_id == request_b.verified_key_id});
                REQUIRE(bool{parent_b->request.body == request_b.body});
                REQUIRE(relay.parent_is_pending(0U));
                REQUIRE(relay.parent_is_pending(1U));
                // Identical B content, sender, marker and message_id. Only the
                // parent correlation changes to B's genuinely verified call.
                auto const retried = relay.relay(frame(parent_b->id, origin_b, content_b));
                REQUIRE(retried.has_value());
                CHECK(bool{ipc::ipc_json_get_str(*retried, "status") == "accepted"});
                auto const after_retry = snapshot();
                CHECK(after_retry.rows.size() == before_forgery.rows.size() + 1U);
                CHECK(marker_count(after_retry, origin_a, marker_a) == 1);
                CHECK(marker_count(after_retry, origin_b, marker_b) == 1);
                CHECK(after_retry.watermark > after_forgery.watermark);
                CHECK(after_retry.notified > after_forgery.notified);
                auto const fresh_b = std::ranges::any_of(after_retry.rows, [&](auto const& row) {
                    return row.sender_user_id == "@sender:" + origin_b && row.message_type == message_type &&
                           row.content_json == marker_b && row.stream_id > after_forgery.watermark;
                });
                CHECK(fresh_b);
                REQUIRE(relay.parent_is_pending(0U));
                REQUIRE(relay.parent_is_pending(1U));
                REQUIRE(relay.finish());
                // Both real parent futures have consumed their fed_response;
                // their channel pending entries are gone before the stale RPC.
                auto const stale_content = content(origin_b, "fed12-after-completion", marker_b);
                auto const stale = relay.relay(frame(parent_b->id, origin_b, stale_content));
                REQUIRE(stale.has_value());
                CHECK(bool{ipc::ipc_json_get_str(*stale, "status") == "rejected_invalid"});
                auto const after_completion = snapshot();
                CHECK(same_rows(after_completion.rows, after_retry.rows));
                CHECK(after_completion.watermark == after_retry.watermark);
                CHECK(after_completion.notified == after_retry.notified);
            }
        }
    }
}
