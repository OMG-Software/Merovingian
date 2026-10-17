// SPDX-License-Identifier: GPL-3.0-or-later

// DB-6: exercise the public federation dispatcher through an actual TCP
// listener, not LocalHttpRequest::sig_verified or a replacement resolver/sink.
// Matrix v1.19 Server-Server API: request authentication, GET /make_join and
// GET /event. A decoded NUL must be a controlled refusal, not a decoder
// exception, an ordinary lookup miss, or a dropped keep-alive connection.

#include "../federation_signing_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/temp_directory.hpp"
#include "bounded_connect.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sodium.h>
#include <sys/socket.h>
#include <sys/time.h>

#ifndef MEROVINGIAN_TEST_FEDERATION_WORKER
#define MEROVINGIAN_TEST_FEDERATION_WORKER ""
#endif

namespace
{
namespace hs = merovingian::homeserver;
namespace fed = merovingian::federation;
namespace db = merovingian::database;

class PrivateSqliteDirectory final
{
public:
    PrivateSqliteDirectory()
    {
        // Honour the native test process's TMPDIR; mkdtemp creates mode 0700.
        auto name = (merovingian::tests::temporary_directory() / "merovingian-db6-transport-XXXXXX").string();
        auto buffer = std::vector<char>{name.begin(), name.end()};
        buffer.push_back('\0');
        REQUIRE(::mkdtemp(buffer.data()) != nullptr);
        directory_ = buffer.data();
    }
    ~PrivateSqliteDirectory() noexcept
    {
        auto ignored = std::error_code{};
        std::ignore = std::filesystem::remove_all(directory_, ignored);
    }
    PrivateSqliteDirectory(PrivateSqliteDirectory const&) = delete;
    auto operator=(PrivateSqliteDirectory const&) -> PrivateSqliteDirectory& = delete;

    [[nodiscard]] auto database_path() const -> std::string
    {
        return (directory_ / "store.sqlite3").string();
    }

    [[nodiscard]] auto worker_config_path() const -> std::filesystem::path
    {
        return directory_ / "federation-worker.conf";
    }

private:
    std::filesystem::path directory_{};
};

// The worker reads the same durable SQLite fixture as main, but starts its
// own runtime and loads its own room snapshot. Only the existing shared
// master-key file's path is placed in this private config, never key material.
auto write_proxy_worker_config(std::filesystem::path const& path, merovingian::config::Config const& config) -> void
{
    auto stream = std::ofstream{path, std::ios::binary};
    REQUIRE(stream.is_open());
    stream << "server.name=" << config.server().server_name << '\n'
           << "server.public_baseurl=" << config.server().public_baseurl << '\n'
           << "database.backend=sqlite\n"
           << "database.sqlite_path=" << config.database().sqlite_path << '\n'
           << "database.role=runtime\n"
           << "security.federation.enabled=true\n"
           << "security.federation.default_policy=allow\n"
           << "security.secrets.master_key_file=" << config.security().secrets.master_key_file << '\n'
           << "federation.worker.shards=" << config.federation_worker().shards << '\n'
           << "federation.worker.threads=" << config.federation_worker().threads << '\n'
           << "federation.worker.relay_threads=" << config.federation_worker().relay_threads << '\n'
           << "federation.worker.request_timeout_seconds=" << config.federation_worker().request_timeout_seconds << '\n'
           << "federation.worker.apply_hardening=false\n"
           << "federation.worker.allow_without_landlock=true\n";
    stream.close();
    auto const config_written = !stream.fail();
    REQUIRE(config_written);
}

[[nodiscard]] auto wait_for_proxy_worker(hs::FederationProxy const& proxy) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (!proxy.healthy() && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    return proxy.healthy();
}

// Declare before ListenerGuard: assertion unwinding first drains the TCP
// listener and request pool, then stops the worker while its runtime and
// private config/database directory still exist.
class ProxyWorkerGuard final
{
public:
    explicit ProxyWorkerGuard(hs::HomeserverRuntime& runtime)
        : runtime_{runtime}
    {
    }
    ~ProxyWorkerGuard()
    {
        stop();
    }
    ProxyWorkerGuard(ProxyWorkerGuard const&) = delete;
    auto operator=(ProxyWorkerGuard const&) -> ProxyWorkerGuard& = delete;

    auto stop() -> void
    {
        runtime_.federation_proxy.reset();
    }

private:
    hs::HomeserverRuntime& runtime_;
};

// Compare row contents, not merely counts: an overwrite must also be visible.
// Audit/rate-limit bookkeeping is intentionally outside this room-data snapshot.
struct RoomRows final
{
    std::vector<std::tuple<std::string, std::string, bool>> rooms{};
    std::vector<std::tuple<std::string, std::string, std::string, std::string, std::uint64_t>> events{};
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> state{};
    std::vector<std::tuple<std::string, std::string, std::string, std::uint64_t>> memberships{};
    std::uint64_t sync_watermark{};
    std::uint64_t event_watermark{};

    auto operator==(RoomRows const&) const -> bool = default;
};

[[nodiscard]] auto room_rows(db::PersistentStore const& store) -> RoomRows
{
    auto rows = RoomRows{};
    for (auto const& room : store.rooms)
    {
        rows.rooms.emplace_back(room.room_id, room.creator_user_id, room.directory_public);
    }
    for (auto const& event : store.events)
    {
        rows.events.emplace_back(event.event_id, event.room_id, event.json, event.status, event.stream_ordering);
    }
    for (auto const& state : store.state)
    {
        rows.state.emplace_back(state.room_id, state.event_type, state.state_key, state.event_id);
    }
    for (auto const& member : store.memberships)
    {
        rows.memberships.emplace_back(member.room_id, member.user_id, member.membership, member.stream_ordering);
    }
    rows.sync_watermark = store.next_sync_stream_id;
    rows.event_watermark = store.event_stream_watermark;
    // The loader's SQL order differs from insertion order for current state.
    std::ranges::sort(rows.rooms);
    std::ranges::sort(rows.events);
    std::ranges::sort(rows.state);
    std::ranges::sort(rows.memberships);
    return rows;
}

class ListenerGuard final
{
public:
    ListenerGuard(merovingian::net::ShutdownSignal& shutdown, std::thread& listener, merovingian::net::ThreadPool& pool)
        : shutdown_{shutdown}
        , listener_{listener}
        , pool_{pool}
    {
    }
    ~ListenerGuard()
    {
        stop();
    }
    ListenerGuard(ListenerGuard const&) = delete;
    auto operator=(ListenerGuard const&) -> ListenerGuard& = delete;

    auto stop() -> void
    {
        shutdown_.fire();
        if (listener_.joinable())
        {
            listener_.join();
        }
        // serve_http stops its dispatcher before returning; now join workers
        // before any referenced runtime/stats/acceptor can be destroyed.
        pool_.request_stop();
    }

private:
    merovingian::net::ShutdownSignal& shutdown_;
    std::thread& listener_;
    merovingian::net::ThreadPool& pool_;
};

[[nodiscard]] auto connect_loopback(std::uint16_t port) -> merovingian::core::FileDescriptor
{
    auto socket = merovingian::core::FileDescriptor{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    REQUIRE(socket.valid());
    auto timeout = timeval{};
    timeout.tv_sec = 5;
    REQUIRE(::setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    auto address = sockaddr_in{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    // Bounded: a blocking connect() to this listener never returned on OpenBSD.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    REQUIRE(merovingian::tests::connect_within(socket.get(), *reinterpret_cast<sockaddr const*>(&address),
                                               sizeof(address)));
    return socket;
}

[[nodiscard]] auto wait_socket(int fd, short events, std::chrono::steady_clock::time_point deadline) -> bool
{
    while (std::chrono::steady_clock::now() < deadline)
    {
        auto entry = pollfd{fd, events, 0};
        auto const result = ::poll(&entry, 1U, 100);
        if (result > 0)
        {
            return (entry.revents & events) != 0;
        }
        if (result < 0 && errno != EINTR)
        {
            return false;
        }
    }
    return false;
}

[[nodiscard]] auto send_bounded(int fd, std::string_view wire) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!wire.empty() && wait_socket(fd, POLLOUT, deadline))
    {
        auto const sent = ::send(fd, wire.data(), wire.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent > 0)
        {
            wire.remove_prefix(static_cast<std::size_t>(sent));
        }
        else if (sent == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK))
        {
            return false;
        }
    }
    return wire.empty();
}

struct WireReply final
{
    unsigned status{};
    bool keep_alive{};
    std::string body{};
};

// One Content-Length-framed response, never read-until-close. Both bytes and
// elapsed time are capped so missing responses and decoder-driven disconnects
// fail this case instead of hanging the integration binary.
[[nodiscard]] auto receive_bounded(int fd) -> std::optional<WireReply>
{
    auto wire = std::string{};
    auto buffer = std::array<char, 4096U>{};
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    constexpr auto cap = std::size_t{65536U};
    while (wire.size() <= cap)
    {
        auto const head_end = wire.find("\r\n\r\n");
        if (head_end != std::string::npos)
        {
            constexpr auto prefix = std::string_view{"\r\nContent-Length: "};
            auto const length_at = wire.find(prefix);
            if (!wire.starts_with("HTTP/1.1 ") || head_end < 12U || length_at == std::string::npos ||
                length_at >= head_end)
            {
                return std::nullopt;
            }
            auto const begin = length_at + prefix.size();
            auto const end = wire.find("\r\n", begin);
            if (end == std::string::npos || end > head_end)
            {
                return std::nullopt;
            }
            auto length = std::size_t{};
            auto const parsed = std::from_chars(wire.data() + begin, wire.data() + end, length);
            if (parsed.ec != std::errc{} || parsed.ptr != wire.data() + end || length > cap)
            {
                return std::nullopt;
            }
            if (wire.size() >= head_end + 4U + length)
            {
                auto reply = WireReply{};
                auto const status = std::from_chars(wire.data() + 9U, wire.data() + 12U, reply.status);
                if (status.ec != std::errc{} || status.ptr != wire.data() + 12U)
                {
                    return std::nullopt;
                }
                reply.keep_alive = wire.substr(0U, head_end).find("\r\nConnection: keep-alive") != std::string::npos;
                reply.body = wire.substr(head_end + 4U, length);
                return reply;
            }
        }
        if (!wait_socket(fd, POLLIN, deadline))
        {
            return std::nullopt;
        }
        auto const received = ::recv(fd, buffer.data(), buffer.size(), MSG_DONTWAIT);
        if (received > 0)
        {
            wire.append(buffer.data(), static_cast<std::size_t>(received));
        }
        else if (received == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK))
        {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

[[nodiscard]] auto signed_get(int fd, std::string const& target, fed::test::SigningKeypair const& keypair)
    -> std::optional<WireReply>
{
    auto constexpr origin = std::string_view{"db6-peer.example.org"};
    auto const signature =
        fed::make_federation_signature(origin, "example.org", "GET", target, "", fed::test::secret_key_span(keypair));
    REQUIRE_FALSE(signature.empty());
    auto const wire = "GET " + target + " HTTP/1.1\r\nHost: example.org\r\nAuthorization: X-Matrix origin=\"" +
                      std::string{origin} + "\",destination=\"example.org\",key=\"ed25519:db6\",sig=\"" + signature +
                      "\"\r\n\r\n";
    // Never CAPTURE/INFO the signed request, keypair, or response body.
    if (!send_bounded(fd, wire))
    {
        return std::nullopt;
    }
    return receive_bounded(fd);
}
} // namespace

SCENARIO("Federation socket HTTP refuses NUL path components without disconnecting or changing room data",
         "[db6][db6-transport][integration]")
{
    GIVEN("a real SQLite runtime, a known peer's durable verification key, and a readable public room")
    {
        REQUIRE(sodium_init() >= 0);
        auto const directory = PrivateSqliteDirectory{};
        auto const path = directory.database_path();
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = path;
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        security.federation.enabled = true;
        security.federation.default_policy = "allow";
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{}, database, security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
        auto started = hs::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(runtime.homeserver.federation_proxy == nullptr);

        auto const owner = hs::register_appservice_user(runtime.homeserver, "db6_transport_owner");
        REQUIRE(owner.ok);
        auto const login = hs::login_local_user_by_id(runtime.homeserver, owner.value, "DB6-TRANSPORT");
        REQUIRE(login.ok);
        auto options = hs::CreateRoomOptions{};
        options.preset = "public_chat";
        auto const room = hs::create_room(runtime.homeserver, login.value, options);
        REQUIRE(room.ok);
        auto const readable = hs::send_event(
            runtime.homeserver, login.value, room.value,
            R"({"type":"m.room.history_visibility","state_key":"","content":{"history_visibility":"world_readable"}})");
        REQUIRE(readable.ok);

        auto seed = std::string(32U, '\0');
        randombytes_buf(seed.data(), seed.size());
        auto const keypair = fed::test::keypair_from_seed(seed);
        sodium_memzero(seed.data(), seed.size());
        auto const now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        auto const key_response = fed::RemoteKeyResponse{
            "db6-peer.example.org", now + 3600000U, {{"ed25519:db6", fed::test::pubkey_b64(keypair)}}};
        REQUIRE(fed::cache_remote_server_keys(runtime.homeserver.database.persistent_store, key_response, now));
        auto durable = db::open_sqlite_persistent_store(path);
        REQUIRE(durable.ok);
        auto const peer_key = fed::find_cached_remote_key(durable.store, "db6-peer.example.org", "ed25519:db6");
        REQUIRE(peer_key.has_value());
        auto const key_matches = peer_key->public_key_bytes == keypair.public_key;
        REQUIRE(key_matches);
        auto peer = fed::FederationRemoteRuntime{};
        peer.server_name = "db6-peer.example.org";
        peer.signing_key = *peer_key;
        // A known-peer record, as in the existing inbound signing fixture.
        // This is policy metadata only: no resolver or outbound call is used.
        peer.discovery.server_name = peer.server_name;
        peer.discovery.well_known_host = peer.server_name;
        peer.discovery.resolved_host = peer.server_name;
        peer.discovery.resolved_addresses = {"203.0.113.10"};
        peer.discovery.tls_required = true;
        peer.trust.reputation_score = 100U;
        fed::upsert_remote(runtime.homeserver.federation, std::move(peer));
        auto const before = room_rows(runtime.homeserver.database.persistent_store);
        auto const durable_before = room_rows(durable.store);
        auto const baseline_matches = before == durable_before;
        REQUIRE(baseline_matches);
        auto const stream_before = runtime.homeserver.database.next_stream_ordering;

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = hs::HttpServeStats{};
        auto pool = merovingian::net::ThreadPool{2U};
        auto listener_error = std::exception_ptr{};

        WHEN("signed room-ID, event-ID and membership-subject requests cross the no-proxy federation listener")
        {
            auto listener = std::thread{[&] {
                try
                {
                    hs::serve_http(acceptor, runtime, shutdown, stats, hs::HttpDispatchMode::federation, pool);
                }
                catch (...)
                {
                    listener_error = std::current_exception();
                }
            }};
            auto guard = ListenerGuard{shutdown, listener, pool};

            THEN("NUL receives 400 between successful authenticated controls on the same socket, with no persistence")
            {
                auto const encoded_room = merovingian::core::percent_encode_path_component(room.value);
                auto const subject =
                    merovingian::core::percent_encode_path_component("@db6member:db6-peer.example.org");
                auto const encoded_event = merovingian::core::percent_encode_path_component(readable.value);
                auto const join_prefix = std::string{"/_matrix/federation/v1/make_join/"};
                auto const event_prefix = std::string{"/_matrix/federation/v1/event/"};
                auto const join_control = join_prefix + encoded_room + "/" + subject + "?ver=12";
                auto const event_control = event_prefix + encoded_event;
                struct Component final
                {
                    std::string_view name;
                    std::string encoded;
                    std::string prefix;
                    std::string suffix;
                    std::string control;
                    std::string marker;
                };
                auto const room_component = Component{
                    "room ID", encoded_room, join_prefix, "/" + subject + "?ver=12", join_control, "\"event\""};
                auto const subject_component = Component{"membership subject/state key",
                                                         subject,
                                                         join_prefix + encoded_room + "/",
                                                         "?ver=12",
                                                         join_control,
                                                         "\"event\""};
                auto const event_component =
                    Component{"event ID", encoded_event, event_prefix, "", event_control, "\"pdus\""};
                auto const components = std::array{room_component, subject_component, event_component};
                for (auto const& component : components)
                {
                    for (auto const position :
                         {std::string_view{"leading"}, std::string_view{"interior"}, std::string_view{"trailing"}})
                    {
                        INFO(component.name);
                        INFO(position);
                        // The initial '!', '@', '$' is encoded as a whole %HH
                        // triplet. Insert after it, never inside the triplet.
                        auto const at = position == "leading"    ? 0U
                                        : position == "interior" ? 3U
                                                                 : component.encoded.size();
                        auto bad = component.encoded;
                        bad.insert(at, "%00");
                        auto client = connect_loopback(port);
                        auto const control = signed_get(client.get(), component.control, keypair);
                        REQUIRE(control.has_value());
                        REQUIRE(control->status == 200U);
                        REQUIRE(control->keep_alive);
                        auto const reached_handler = control->body.find(component.marker) != std::string::npos;
                        REQUIRE(reached_handler);
                        auto const refused =
                            signed_get(client.get(), component.prefix + bad + component.suffix, keypair);
                        CHECK(refused.has_value());
                        if (refused.has_value())
                        {
                            CHECK(refused->status == 400U);
                            CHECK(refused->keep_alive);
                            CHECK_FALSE(refused->body.empty());
                        }
                        auto const follow = signed_get(client.get(), component.control, keypair);
                        CHECK(follow.has_value());
                        if (follow.has_value())
                        {
                            CHECK(follow->status == 200U);
                            auto const handler_still_reached = follow->body.find(component.marker) != std::string::npos;
                            CHECK(handler_still_reached);
                        }
                        {
                            auto lock = std::unique_lock{runtime.homeserver.mutex};
                            auto const unchanged = room_rows(runtime.homeserver.database.persistent_store) == before;
                            CHECK(unchanged);
                            CHECK(runtime.homeserver.database.next_stream_ordering == stream_before);
                        }
                        auto reloaded = db::open_sqlite_persistent_store(path);
                        REQUIRE(reloaded.ok);
                        auto const durably_unchanged = room_rows(reloaded.store) == durable_before;
                        CHECK(durably_unchanged);
                    }
                }

                // Exactly one decoding pass: %2500 is the literal text %00.
                // Unknown literal room/event IDs reach the ordinary lookup
                // (404 M_NOT_FOUND), while a valid literal-percent localpart
                // is returned in the successful make_join state_key.
                for (auto const& component : components)
                {
                    auto literal = component.encoded;
                    literal.insert(3U, "%2500");
                    INFO(component.name);
                    auto client = connect_loopback(port);
                    auto const compatible =
                        signed_get(client.get(), component.prefix + literal + component.suffix, keypair);
                    REQUIRE(compatible.has_value());
                    auto const membership = component.name == "membership subject/state key";
                    CHECK(compatible->status == (membership ? 200U : 404U));
                    CHECK(compatible->keep_alive);
                    auto const literal_handled = compatible->body.find(membership ? "@%00db6member:db6-peer.example.org"
                                                                                  : "M_NOT_FOUND") != std::string::npos;
                    CHECK(literal_handled);
                    auto const follow = signed_get(client.get(), component.control, keypair);
                    REQUIRE(follow.has_value());
                    CHECK(follow->status == 200U);
                }
                guard.stop();
                CHECK(listener_error == nullptr);
                auto const unchanged = room_rows(runtime.homeserver.database.persistent_store) == before;
                CHECK(unchanged);
                CHECK(runtime.homeserver.database.next_stream_ordering == stream_before);
                auto reloaded = db::open_sqlite_persistent_store(path);
                REQUIRE(reloaded.ok);
                auto const durably_unchanged = room_rows(reloaded.store) == durable_before;
                CHECK(durably_unchanged);
                CHECK(stats.accepted_connections == 12U);
                // Count only complete wire responses, not auth denial or a
                // worker-unavailable reply masquerading as NUL admission.
                CHECK(stats.completed_requests == 33U);
                CHECK(runtime.homeserver.federation.key_resolution_buckets.empty());
                CHECK(runtime.homeserver.federation.key_resolution_failures.empty());
            }
        }
    }
}

SCENARIO("Federation proxy socket HTTP refuses NUL components with a healthy separate worker",
         "[db6][db6-transport][db6-proxy-transport][integration]")
{
    GIVEN("durable room fixtures and peer keys seeded before a real federation worker starts")
    {
        REQUIRE(sodium_init() >= 0);
        auto const worker_path = std::string{MEROVINGIAN_TEST_FEDERATION_WORKER};
        auto const worker_configured = !worker_path.empty();
        REQUIRE(worker_configured);
        auto const worker_exists = std::filesystem::is_regular_file(worker_path);
        REQUIRE(worker_exists);
        auto const directory = PrivateSqliteDirectory{};
        auto const path = directory.database_path();
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = path;
        database.role = merovingian::config::DatabaseRole::runtime;
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        security.federation.enabled = true;
        security.federation.default_policy = "allow";
        auto worker = merovingian::config::FederationWorkerConfig{};
        worker.shards = 1U;
        worker.threads = 1U;
        worker.request_timeout_seconds = 5U;
        // Follow the real worker-flow fixture: this test targets decoding,
        // not the separately tested seccomp/platform availability policies.
        worker.apply_hardening = false;
        worker.allow_without_landlock = true;
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}, worker};
        auto started = hs::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(runtime.homeserver.federation_proxy == nullptr);

        auto const owner = hs::register_appservice_user(runtime.homeserver, "db6_proxy_transport_owner");
        REQUIRE(owner.ok);
        auto const login = hs::login_local_user_by_id(runtime.homeserver, owner.value, "DB6-PROXY-TRANSPORT");
        REQUIRE(login.ok);
        auto options = hs::CreateRoomOptions{};
        options.preset = "public_chat";
        auto const room = hs::create_room(runtime.homeserver, login.value, options);
        REQUIRE(room.ok);
        auto const readable = hs::send_event(
            runtime.homeserver, login.value, room.value,
            R"({"type":"m.room.history_visibility","state_key":"","content":{"history_visibility":"world_readable"}})");
        REQUIRE(readable.ok);

        auto seed = std::string(32U, '\0');
        randombytes_buf(seed.data(), seed.size());
        auto const keypair = fed::test::keypair_from_seed(seed);
        sodium_memzero(seed.data(), seed.size());
        auto const now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        auto const key_response = fed::RemoteKeyResponse{
            "db6-peer.example.org", now + 3600000U, {{"ed25519:db6", fed::test::pubkey_b64(keypair)}}};
        REQUIRE(fed::cache_remote_server_keys(runtime.homeserver.database.persistent_store, key_response, now));
        auto durable = db::open_sqlite_persistent_store(path);
        REQUIRE(durable.ok);
        auto const peer_key = fed::find_cached_remote_key(durable.store, "db6-peer.example.org", "ed25519:db6");
        REQUIRE(peer_key.has_value());
        auto const key_matches = peer_key->public_key_bytes == keypair.public_key;
        REQUIRE(key_matches);
        auto peer = fed::FederationRemoteRuntime{};
        peer.server_name = "db6-peer.example.org";
        peer.signing_key = *peer_key;
        peer.discovery.server_name = peer.server_name;
        peer.discovery.well_known_host = peer.server_name;
        peer.discovery.resolved_host = peer.server_name;
        peer.discovery.resolved_addresses = {"203.0.113.10"};
        peer.discovery.tls_required = true;
        peer.trust.reputation_score = 100U;
        fed::upsert_remote(runtime.homeserver.federation, std::move(peer));
        auto const before = room_rows(runtime.homeserver.database.persistent_store);
        auto const durable_before = room_rows(durable.store);
        auto const baseline_matches = before == durable_before;
        REQUIRE(baseline_matches);
        auto const stream_before = runtime.homeserver.database.next_stream_ordering;

        // No fixture changes after spawning: the worker must read the room,
        // current state, membership, history event and cached public key from
        // SQLite at startup, not from main's in-memory data or fake callbacks.
        auto const config_path = directory.worker_config_path();
        write_proxy_worker_config(config_path, config);
        runtime.homeserver.federation_proxy = std::make_unique<hs::FederationProxy>(
            config.federation_worker(), runtime.homeserver, worker_path, config_path.string());
        auto proxy_guard = ProxyWorkerGuard{runtime.homeserver};
        REQUIRE(wait_for_proxy_worker(*runtime.homeserver.federation_proxy));
        // A failed room-sync status would route make_join back to main. With
        // startup fixtures there is no notification or fallback to hide a
        // worker that cannot actually serve the authenticated 200 controls.
        REQUIRE(runtime.homeserver.federation_proxy->room_sync_status(room.value).state == "ok");
        REQUIRE(runtime.homeserver.federation_proxy->room_sync_status(room.value).generation == 0U);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = hs::HttpServeStats{};
        auto pool = merovingian::net::ThreadPool{2U};
        auto listener_error = std::exception_ptr{};

        WHEN("signed HTTP crosses the main proxy's room-key decoder and the real worker IPC boundary")
        {
            auto listener = std::thread{[&] {
                try
                {
                    hs::serve_http(acceptor, runtime, shutdown, stats, hs::HttpDispatchMode::federation, pool);
                }
                catch (...)
                {
                    listener_error = std::current_exception();
                }
            }};
            auto guard = ListenerGuard{shutdown, listener, pool};

            THEN("each NUL is a controlled 400 between worker-served 200 controls without room writes or disconnects")
            {
                auto const encoded_room = merovingian::core::percent_encode_path_component(room.value);
                auto const subject =
                    merovingian::core::percent_encode_path_component("@db6member:db6-peer.example.org");
                auto const encoded_event = merovingian::core::percent_encode_path_component(readable.value);
                auto const join_prefix = std::string{"/_matrix/federation/v1/make_join/"};
                auto const event_prefix = std::string{"/_matrix/federation/v1/event/"};
                auto const join_control = join_prefix + encoded_room + "/" + subject + "?ver=12";
                auto const event_control = event_prefix + encoded_event;
                struct Component final
                {
                    std::string_view name;
                    std::string encoded;
                    std::string prefix;
                    std::string suffix;
                    std::string control;
                    std::string marker;
                };
                auto const room_component = Component{
                    "room ID", encoded_room, join_prefix, "/" + subject + "?ver=12", join_control, "\"event\""};
                auto const subject_component = Component{"membership subject/state key",
                                                         subject,
                                                         join_prefix + encoded_room + "/",
                                                         "?ver=12",
                                                         join_control,
                                                         "\"event\""};
                auto const event_component =
                    Component{"event ID", encoded_event, event_prefix, "", event_control, "\"pdus\""};
                auto const components = std::array{room_component, subject_component, event_component};
                for (auto const& component : components)
                {
                    for (auto const position :
                         {std::string_view{"leading"}, std::string_view{"interior"}, std::string_view{"trailing"}})
                    {
                        INFO(component.name);
                        INFO(position);
                        auto const at = position == "leading"    ? 0U
                                        : position == "interior" ? 3U
                                                                 : component.encoded.size();
                        auto bad = component.encoded;
                        bad.insert(at, "%00");
                        REQUIRE(runtime.homeserver.federation_proxy->healthy());
                        auto client = connect_loopback(port);
                        auto const control = signed_get(client.get(), component.control, keypair);
                        REQUIRE(control.has_value());
                        REQUIRE(control->status == 200U);
                        REQUIRE(control->keep_alive);
                        auto const reached_worker_handler = control->body.find(component.marker) != std::string::npos;
                        REQUIRE(reached_worker_handler);
                        auto const refused =
                            signed_get(client.get(), component.prefix + bad + component.suffix, keypair);
                        CHECK(refused.has_value());
                        if (refused.has_value())
                        {
                            CHECK(refused->status == 400U);
                            CHECK(refused->keep_alive);
                            auto const invalid_parameter = refused->body.find("M_INVALID_PARAM") != std::string::npos;
                            CHECK(invalid_parameter);
                        }
                        auto const follow = signed_get(client.get(), component.control, keypair);
                        CHECK(follow.has_value());
                        if (follow.has_value())
                        {
                            CHECK(follow->status == 200U);
                            CHECK(follow->keep_alive);
                            auto const worker_still_reached = follow->body.find(component.marker) != std::string::npos;
                            CHECK(worker_still_reached);
                        }
                        CHECK(runtime.homeserver.federation_proxy->healthy());
                        CHECK(runtime.homeserver.federation_proxy->room_sync_status(room.value).state == "ok");
                        CHECK(runtime.homeserver.federation_proxy->room_sync_status(room.value).generation == 0U);
                        {
                            auto lock = std::unique_lock{runtime.homeserver.mutex};
                            auto const unchanged = room_rows(runtime.homeserver.database.persistent_store) == before;
                            CHECK(unchanged);
                            CHECK(runtime.homeserver.database.next_stream_ordering == stream_before);
                        }
                        auto reloaded = db::open_sqlite_persistent_store(path);
                        REQUIRE(reloaded.ok);
                        auto const durably_unchanged = room_rows(reloaded.store) == durable_before;
                        CHECK(durably_unchanged);
                    }
                }

                // Preserve the same single-decode %2500 positives across the
                // proxy: ordinary literal-percent lookup misses and a valid
                // make_join subject must not be treated as decoded NUL.
                for (auto const& component : components)
                {
                    auto literal = component.encoded;
                    literal.insert(3U, "%2500");
                    INFO(component.name);
                    REQUIRE(runtime.homeserver.federation_proxy->healthy());
                    auto client = connect_loopback(port);
                    auto const compatible =
                        signed_get(client.get(), component.prefix + literal + component.suffix, keypair);
                    REQUIRE(compatible.has_value());
                    auto const membership = component.name == "membership subject/state key";
                    CHECK(compatible->status == (membership ? 200U : 404U));
                    CHECK(compatible->keep_alive);
                    auto const literal_handled = compatible->body.find(membership ? "@%00db6member:db6-peer.example.org"
                                                                                  : "M_NOT_FOUND") != std::string::npos;
                    CHECK(literal_handled);
                    auto const follow = signed_get(client.get(), component.control, keypair);
                    REQUIRE(follow.has_value());
                    CHECK(follow->status == 200U);
                    CHECK(follow->keep_alive);
                    auto const worker_still_reached = follow->body.find(component.marker) != std::string::npos;
                    CHECK(worker_still_reached);
                }
                guard.stop();
                CHECK(listener_error == nullptr);
                CHECK(runtime.homeserver.federation_proxy->healthy());
                CHECK(runtime.homeserver.federation_proxy->room_sync_status(room.value).state == "ok");
                CHECK(runtime.homeserver.federation_proxy->room_sync_status(room.value).generation == 0U);
                proxy_guard.stop();
                CHECK(runtime.homeserver.federation_proxy == nullptr);
                auto const unchanged = room_rows(runtime.homeserver.database.persistent_store) == before;
                CHECK(unchanged);
                CHECK(runtime.homeserver.database.next_stream_ordering == stream_before);
                auto reloaded = db::open_sqlite_persistent_store(path);
                REQUIRE(reloaded.ok);
                auto const durably_unchanged = room_rows(reloaded.store) == durable_before;
                CHECK(durably_unchanged);
                CHECK(stats.accepted_connections == 12U);
                CHECK(stats.completed_requests == 33U);
                CHECK(runtime.homeserver.federation.key_resolution_buckets.empty());
                CHECK(runtime.homeserver.federation.key_resolution_failures.empty());
            }
        }
    }
}
