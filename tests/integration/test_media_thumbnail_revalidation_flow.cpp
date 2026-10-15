// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// MED-4, bounded local-source slice: the record authorising an already-started
// decode must still be servable after the worker finishes. No remote fetch,
// cache eviction, trust-policy override or replacement decoder is involved.
#include <catch2/catch_test_macros.hpp>

#if defined(MEROVINGIAN_TEST_THUMBNAIL_WORKER) && defined(MEROVINGIAN_TEST_THUMBNAIL_GATE) && !defined(_WIN32)

#include "../support/joining_threads.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/temp_directory.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
using Clock = std::chrono::steady_clock;
using merovingian::core::FileDescriptor;

[[nodiscard]] auto sample_png() -> std::string
{
    // Complete 8x8 RGBA PNG, also used by the remote-media pool flow fixture.
    constexpr std::array<unsigned char, 81U> bytes{
        137, 80,  78,  71,  13,  10, 26, 10,  0,   0,   0,   13,  73, 72,  68,  82,  0,  0,  0,  8,   0,
        0,   0,   8,   8,   6,   0,  0,  0,   196, 15,  190, 139, 0,  0,   0,   24,  73, 68, 65, 84,  120,
        156, 99,  248, 207, 192, 0,  66, 255, 113, 209, 12,  248, 36, 193, 244, 176, 48, 1,  0,  131, 23,
        127, 129, 6,   228, 109, 45, 0,  0,   0,   0,   73,  69,  78, 68,  174, 66,  96, 130};
    return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
}

class PrivateDirectory final
{
public:
    PrivateDirectory()
        : m_path{(std::filesystem::absolute(merovingian::tests::temporary_directory()) / "merovingian-med4-XXXXXX")
                     .string()}
    {
        // mkdtemp creates mode 0700 atomically, including the database and the
        // copied gate in its lifetime. No predictable shared control files.
        REQUIRE(::mkdtemp(m_path.data()) != nullptr);
    }
    PrivateDirectory(PrivateDirectory const&) = delete;
    auto operator=(PrivateDirectory const&) -> PrivateDirectory& = delete;
    PrivateDirectory(PrivateDirectory&&) = delete;
    auto operator=(PrivateDirectory&&) -> PrivateDirectory& = delete;
    ~PrivateDirectory() noexcept
    {
        auto error = std::error_code{};
        std::ignore = std::filesystem::remove_all(m_path, error);
    }
    [[nodiscard]] auto path() const -> std::filesystem::path
    {
        return m_path;
    }

private:
    std::string m_path;
};

[[nodiscard]] auto wait_readable(int fd, Clock::time_point deadline) noexcept -> bool
{
    while (true)
    {
        auto const remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
        if (remaining.count() <= 0)
        {
            return false;
        }
        auto entry = ::pollfd{fd, POLLIN, 0};
        auto const ready = ::poll(&entry, 1U, static_cast<int>(remaining.count()));
        if (ready < 0 && errno == EINTR)
        {
            continue;
        }
        return ready > 0 && (entry.revents & POLLIN) != 0;
    }
}

class ChildGate final
{
public:
    explicit ChildGate(std::filesystem::path const& directory)
        : m_executable{directory / "thumbnail-gate"}
    {
        std::filesystem::copy_file(MEROVINGIAN_TEST_THUMBNAIL_GATE, m_executable);
        std::filesystem::permissions(m_executable, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace);
        auto const ack = directory / "thumbnail-gate.ack";
        auto const release = directory / "thumbnail-gate.release";
        REQUIRE(::mkfifo(ack.c_str(), 0600) == 0);
        REQUIRE(::mkfifo(release.c_str(), 0600) == 0);
        m_ack.reset(::open(ack.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC));
        m_release.reset(::open(release.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC));
        REQUIRE(m_ack.valid());
        REQUIRE(m_release.valid());
    }
    ChildGate(ChildGate const&) = delete;
    auto operator=(ChildGate const&) -> ChildGate& = delete;
    ChildGate(ChildGate&&) = delete;
    auto operator=(ChildGate&&) -> ChildGate& = delete;
    ~ChildGate() noexcept
    {
        std::ignore = release();
    }
    [[nodiscard]] auto executable() const -> std::string
    {
        return m_executable.string();
    }
    auto arm() -> void
    {
        // Only called after the previous request has been collected. Clear
        // stale bytes so ACK always proves entry by THIS child.
        auto byte = char{};
        while (::read(m_ack.get(), &byte, 1U) == 1)
        {
        }
        while (::read(m_release.get(), &byte, 1U) == 1)
        {
        }
        m_released = false;
    }
    [[nodiscard]] auto entered() const noexcept -> bool
    {
        auto const deadline = Clock::now() + std::chrono::seconds{15};
        while (wait_readable(m_ack.get(), deadline))
        {
            auto byte = char{};
            auto const count = ::read(m_ack.get(), &byte, 1U);
            if (count < 0 && (errno == EINTR || errno == EAGAIN))
            {
                continue;
            }
            return count == 1 && byte == 'A';
        }
        return false;
    }
    // One more release byte, for when several gated children are waiting.
    [[nodiscard]] auto release_one() noexcept -> bool
    {
        auto const byte = 'R';
        auto written = ssize_t{-1};
        do
        {
            written = ::write(m_release.get(), &byte, 1U);
        } while (written < 0 && errno == EINTR);
        return written == 1;
    }
    [[nodiscard]] auto release() noexcept -> bool
    {
        if (m_released)
        {
            return true;
        }
        auto const byte = 'R';
        auto written = ssize_t{-1};
        do
        {
            written = ::write(m_release.get(), &byte, 1U);
        } while (written < 0 && errno == EINTR);
        m_released = written == 1;
        return m_released;
    }

private:
    std::filesystem::path m_executable;
    FileDescriptor m_ack{};
    FileDescriptor m_release{};
    bool m_released{true};
};

// The production TCP listener and HTTP connection dispatcher, not a socketpair
// or a direct router call. Eight workers give one loopback address two active
// slots, allowing /versions and moderation while one thumbnail is gated.
class DispatchedListener final
{
public:
    explicit DispatchedListener(merovingian::homeserver::ClientServerRuntime& runtime)
        : m_dispatcher{runtime, m_stats, m_pool}
    {
        REQUIRE(m_acceptor.bind("127.0.0.1", 0U).ok);
        REQUIRE(m_dispatcher.start());
        m_threads.emplace_back([this] {
            merovingian::homeserver::serve_http(m_acceptor, m_dispatcher, m_shutdown,
                                                merovingian::homeserver::HttpDispatchMode::client_server);
        });
    }
    DispatchedListener(DispatchedListener const&) = delete;
    auto operator=(DispatchedListener const&) -> DispatchedListener& = delete;
    DispatchedListener(DispatchedListener&&) = delete;
    auto operator=(DispatchedListener&&) -> DispatchedListener& = delete;
    ~DispatchedListener() noexcept
    {
        m_shutdown.fire();
        m_threads.join();
        m_dispatcher.request_stop();
        m_pool.request_stop();
    }
    [[nodiscard]] auto port() const noexcept -> std::uint16_t
    {
        return m_acceptor.bound_port();
    }

private:
    merovingian::net::TcpAcceptor m_acceptor{};
    merovingian::net::ShutdownSignal m_shutdown{};
    merovingian::homeserver::HttpServeStats m_stats{};
    merovingian::net::ThreadPool m_pool{8U};
    merovingian::homeserver::HttpConnectionDispatcher m_dispatcher;
    merovingian::tests::JoiningThreads m_threads{};
};

struct Response final
{
    bool complete{false};
    unsigned status{0U};
    std::string content_type{};
    std::string body{};
};

[[nodiscard]] auto request(std::string_view method, std::string_view target, std::string_view token = {},
                           std::string_view body = {}, std::string_view type = "application/json") -> std::string
{
    auto result =
        std::string{method} + " " + std::string{target} + " HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n";
    if (!token.empty())
    {
        result += "Authorization: Bearer " + std::string{token} + "\r\n";
    }
    result += "Content-Type: " + std::string{type} + "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" +
              std::string{body};
    return result;
}

// No Catch assertions on this path: it also runs on an async client thread,
// and neither request bodies nor authentication responses enter diagnostics.
[[nodiscard]] auto transact(std::uint16_t port, std::string const& wire,
                            std::chrono::seconds timeout = std::chrono::seconds{15}) -> Response
{
    auto socket = FileDescriptor{::socket(AF_INET, SOCK_STREAM, 0)};
    if (!socket.valid() || !socket.set_cloexec())
    {
        return {};
    }
#ifdef SO_NOSIGPIPE
    auto const no_sigpipe = 1;
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) != 0)
    {
        return {};
    }
#endif
    auto remote = ::sockaddr_in{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(socket.get(), reinterpret_cast<::sockaddr const*>(&remote), sizeof(remote)) != 0)
    {
        return {};
    }
    auto const flags = ::fcntl(socket.get(), F_GETFL, 0);
    if (flags < 0 || ::fcntl(socket.get(), F_SETFL, flags | O_NONBLOCK) != 0)
    {
        return {};
    }
    auto const deadline = Clock::now() + timeout;
    auto remaining = std::string_view{wire};
    while (!remaining.empty())
    {
        auto const left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
        auto entry = ::pollfd{socket.get(), POLLOUT, 0};
        if (left.count() <= 0)
        {
            return {};
        }
        auto const ready = ::poll(&entry, 1U, static_cast<int>(left.count()));
        if (ready < 0 && errno == EINTR)
        {
            continue;
        }
        if (ready <= 0 || (entry.revents & POLLOUT) == 0)
        {
            return {};
        }
#ifdef MSG_NOSIGNAL
        auto const sent = ::send(socket.get(), remaining.data(), remaining.size(), MSG_NOSIGNAL);
#else
        auto const sent = ::send(socket.get(), remaining.data(), remaining.size(), 0);
#endif
        if (sent < 0 && (errno == EINTR || errno == EAGAIN))
        {
            continue;
        }
        if (sent <= 0)
        {
            return {};
        }
        remaining.remove_prefix(static_cast<std::size_t>(sent));
    }
    auto received = std::string{};
    auto buffer = std::array<char, 4096U>{};
    while (received.size() <= 1024U * 1024U && wait_readable(socket.get(), deadline))
    {
        auto const count = ::recv(socket.get(), buffer.data(), buffer.size(), 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
        {
            continue;
        }
        if (count <= 0)
        {
            break;
        }
        received.append(buffer.data(), static_cast<std::size_t>(count));
        auto const head_end = received.find("\r\n\r\n");
        auto const length_at = received.find("\r\nContent-Length: ");
        if (head_end == std::string::npos || length_at == std::string::npos || length_at >= head_end)
        {
            continue;
        }
        auto length = std::size_t{};
        auto const start = length_at + std::string_view{"\r\nContent-Length: "}.size();
        auto const end = received.find("\r\n", start);
        auto const parsed = std::from_chars(received.data() + start, received.data() + end, length);
        if (parsed.ec != std::errc{} || parsed.ptr != received.data() + end || length > 1024U * 1024U)
        {
            return {};
        }
        if (received.size() < head_end + 4U + length)
        {
            continue;
        }
        auto result = Response{};
        auto const status_at = received.find(' ');
        if (!received.starts_with("HTTP/1.1 ") || status_at == std::string::npos)
        {
            return {};
        }
        auto const status =
            std::from_chars(received.data() + status_at + 1U, received.data() + status_at + 4U, result.status);
        if (status.ec != std::errc{})
        {
            return {};
        }
        auto const type_at = received.find("\r\nContent-Type: ");
        if (type_at != std::string::npos && type_at < head_end)
        {
            auto const type_start = type_at + std::string_view{"\r\nContent-Type: "}.size();
            result.content_type = received.substr(type_start, received.find("\r\n", type_start) - type_start);
        }
        result.body = received.substr(head_end + 4U, length);
        result.complete = true;
        return result;
    }
    return {};
}

// Destructor BODY releases the child before waiting on the future. Merely
// declaring a gate before a future would deadlock during REQUIRE unwinding:
// the future's destructor waits before the gate's destructor can release it.
class PendingThumbnail final
{
public:
    PendingThumbnail(ChildGate& gate, std::uint16_t port, std::string wire)
        : m_gate{gate}
        , m_response{std::async(std::launch::async, [port, wire = std::move(wire)] {
            return transact(port, wire, std::chrono::seconds{120});
        })}
    {
    }
    PendingThumbnail(PendingThumbnail const&) = delete;
    auto operator=(PendingThumbnail const&) -> PendingThumbnail& = delete;
    PendingThumbnail(PendingThumbnail&&) = delete;
    auto operator=(PendingThumbnail&&) -> PendingThumbnail& = delete;
    ~PendingThumbnail() noexcept
    {
        std::ignore = m_gate.release();
        if (m_response.valid())
        {
            m_response.wait();
        }
    }
    [[nodiscard]] auto pending() -> bool
    {
        return m_response.wait_for(std::chrono::seconds{0}) == std::future_status::timeout;
    }
    [[nodiscard]] auto collect() -> Response
    {
        REQUIRE(m_gate.release());
        REQUIRE(m_response.wait_for(std::chrono::seconds{120}) == std::future_status::ready);
        return m_response.get();
    }

private:
    ChildGate& m_gate;
    std::future<Response> m_response;
};

[[nodiscard]] auto sqlite_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    auto server = merovingian::config::ServerConfig{};
    server.http.request_threads = 8U;
    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto json_string(std::string const& body, std::string_view key) -> std::optional<std::string>
{
    auto const object = merovingian::tests::parse_object_json(body);
    auto const* value = merovingian::tests::string_member(object, key);
    return value == nullptr ? std::nullopt : std::optional<std::string>{*value};
}

[[nodiscard]] auto login_admin(merovingian::homeserver::ClientServerRuntime& runtime, std::uint16_t port) -> std::string
{
    auto const localpart = merovingian::crypto::secure_random_hex(12U);
    auto password = merovingian::crypto::secure_random_hex(24U);
    REQUIRE(localpart.has_value());
    REQUIRE(password.has_value());
    // Preserve random entropy while satisfying the real password policy.
    (*password)[0] = 'A';
    (*password)[1] = 'a';
    (*password)[2] = '7';
    (*password)[3] = '!';
    auto const registration = [&] {
        auto const lock = std::lock_guard{runtime.homeserver.mutex};
        return merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, *localpart, *password);
    }();
    REQUIRE(registration.ok);
    // Hex localpart and generated policy-safe password need no JSON escaping.
    auto const body = std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\""} +
                      registration.value + "\"},\"password\":\"" + *password + "\",\"device_id\":\"MED4\"}";
    auto const login = transact(port, request("POST", "/_matrix/client/v3/login", {}, body));
    REQUIRE(login.complete);
    REQUIRE(login.status == 200U);
    auto const token = json_string(login.body, "access_token");
    REQUIRE(token.has_value());
    REQUIRE_FALSE(token->empty());
    return *token;
}

[[nodiscard]] auto upload(std::uint16_t port, std::string const& token, std::string const& image) -> std::string
{
    auto const result = transact(port, request("POST", "/_matrix/client/v1/media/upload", token, image, "image/png"));
    REQUIRE(result.complete);
    REQUIRE(result.status == 200U);
    auto const uri = json_string(result.body, "content_uri");
    REQUIRE(uri.has_value());
    auto constexpr prefix = std::string_view{"mxc://example.org/"};
    REQUIRE(uri->starts_with(prefix));
    return uri->substr(prefix.size());
}

[[nodiscard]] auto thumbnail_target(std::string const& id, unsigned dimension) -> std::string
{
    return "/_matrix/client/v1/media/thumbnail/example.org/" + id + "?width=" + std::to_string(dimension) +
           "&height=" + std::to_string(dimension) + "&method=scale";
}

auto use_worker(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& path) -> void
{
    auto const lock = std::lock_guard{runtime.homeserver.mutex};
    auto& config = runtime.homeserver.media_repository.config;
    config.thumbnail_worker_path = path;
    config.thumbnail_timeout_seconds = 90U;
}

[[nodiscard]] auto png_signature(std::string const& body) -> bool
{
    auto constexpr signature = std::string_view{"\x89PNG\r\n\x1a\n", 8U};
    return body.starts_with(signature);
}

[[nodiscard]] auto png_dimension(std::string const& body, std::size_t offset) -> std::uint32_t
{
    auto result = std::uint32_t{};
    for (auto index = offset; index < offset + 4U; ++index)
    {
        result = (result << 8U) | static_cast<unsigned char>(body[index]);
    }
    return result;
}

auto require_thumbnail(Response const& response, unsigned dimension) -> void
{
    REQUIRE(response.complete);
    REQUIRE(response.status == 200U);
    REQUIRE(response.content_type == "image/png");
    REQUIRE(png_signature(response.body));
    REQUIRE(response.body.size() >= 33U);
    REQUIRE(response.body.substr(8U, 8U) == std::string{"\0\0\0\rIHDR", 8U});
    REQUIRE(png_dimension(response.body, 16U) == dimension);
    REQUIRE(png_dimension(response.body, 20U) == dimension);
}

[[nodiscard]] auto durable_record(std::filesystem::path const& path, std::string const& id)
    -> merovingian::database::PersistentLocalMedia
{
    // Reopen SQLite through its actual factory; inspect result.store, not a
    // stale runtime vector and not an invented optional/connection API.
    auto const snapshot = merovingian::database::open_sqlite_persistent_store(path.string());
    REQUIRE(snapshot.ok);
    auto const row =
        std::ranges::find(snapshot.store.local_media, id, &merovingian::database::PersistentLocalMedia::media_id);
    REQUIRE(row != snapshot.store.local_media.end());
    return *row;
}

auto check_not_served(Response const& response, std::string const& original) -> void
{
    CHECK(response.complete);
    CHECK(response.status == 404U);
    CHECK(response.content_type != "image/png");
    CHECK_FALSE(png_signature(response.body));
    auto const contains_original = response.body.find(original) != std::string::npos;
    CHECK_FALSE(contains_original);
}
[[nodiscard]] auto remote_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto config = sqlite_config(path);
    auto security = config.security();
    security.media.remote_fetch_enabled = true;
    security.media.remote_fetch_media_policy = "allow";
    return {config.server(), config.listeners(),          config.database(),
            security,        config.client_rate_limits(), config.log_modules()};
}

[[nodiscard]] auto router_get(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& target,
                              std::string const& token) -> Response
{
    auto const result = merovingian::homeserver::handle_client_server_request(runtime, {"GET", target, token, {}});
    auto content_type = std::string{};
    for (auto const& [name, value] : result.response.headers)
    {
        if (name == "Content-Type")
        {
            content_type = value;
        }
    }
    return {result.status == merovingian::homeserver::DispatchResult::Status::complete, result.response.status,
            std::move(content_type), result.response.body};
}
} // namespace

SCENARIO("Local thumbnail decoding revalidates the moderated record rather than its shared blob",
         "[med-4-revalidation][media][database][http][concurrency]")
{
    GIVEN("authenticated local uploads in SQLite and the production loopback HTTP dispatcher")
    {
        WHEN("an administrator moderates one record after its decoder child has entered")
        {
            THEN("completion withholds that record while its deduplicated alias remains independently servable")
            {
                // One complete BDD leaf: a nonfatal expected RED for quarantine
                // must not conceal the removal input on Catch section replay.
                for (auto const remove : {false, true})
                {
                    INFO((remove ? "permanent removal" : "quarantine followed by release"));
                    auto const directory = PrivateDirectory{};
                    auto const path = directory.path() / "media.sqlite3";
                    auto gate = ChildGate{directory.path()};
                    auto started = merovingian::homeserver::start_client_server(sqlite_config(path));
                    REQUIRE(started.started);
                    auto& runtime = started.runtime;
                    use_worker(runtime, MEROVINGIAN_TEST_THUMBNAIL_WORKER);
                    auto listener = DispatchedListener{runtime};
                    auto const port = listener.port();
                    auto const token = login_admin(runtime, port);
                    auto const image = sample_png();
                    auto const original = upload(port, token, image);
                    auto const alias = upload(port, token, image);
                    REQUIRE(original != alias);
                    auto const initial = merovingian::database::open_sqlite_persistent_store(path.string());
                    REQUIRE(initial.ok);
                    REQUIRE(initial.store.local_media.size() == 2U);
                    REQUIRE(initial.store.media_blobs.size() == 1U);
                    REQUIRE(initial.store.media_blobs.front().ref_count == 2U);
                    auto const first = durable_record(path, original);
                    auto const second = durable_record(path, alias);
                    REQUIRE(first.digest == second.digest);
                    REQUIRE(first.hash_algorithm == second.hash_algorithm);
                    REQUIRE_FALSE(first.quarantined);
                    REQUIRE_FALSE(first.removed);
                    REQUIRE_FALSE(second.quarantined);
                    REQUIRE_FALSE(second.removed);

                    // Ungated, real-worker controls through the SAME TCP route.
                    // IHDR geometry distinguishes real resampling from fallback
                    // to the valid but 8x8 uploaded original; no parent decoder.
                    require_thumbnail(transact(port, request("GET", thumbnail_target(original, 4U), token)), 4U);
                    require_thumbnail(transact(port, request("GET", thumbnail_target(alias, 4U), token)), 4U);
                    use_worker(runtime, gate.executable());
                    {
                        // Prove the gate also successfully execs the actual
                        // worker before using it to make a moderation claim.
                        gate.arm();
                        auto control =
                            PendingThumbnail{gate, port, request("GET", thumbnail_target(original, 3U), token)};
                        REQUIRE(gate.entered());
                        REQUIRE(control.pending());
                        require_thumbnail(control.collect(), 3U);
                    }
                    {
                        gate.arm();
                        auto pending =
                            PendingThumbnail{gate, port, request("GET", thumbnail_target(original, 2U), token)};
                        REQUIRE(gate.entered());
                        REQUIRE(pending.pending());
                        auto const versions = transact(port, request("GET", "/_matrix/client/versions"));
                        REQUIRE(versions.complete);
                        REQUIRE(versions.status == 200U);
                        REQUIRE(pending.pending());
                        auto const action = remove ? "remove/" : "quarantine/";
                        auto const moderated = transact(
                            port, request("POST", std::string{"/_merovingian/admin/media/"} + action + original, token,
                                          "MED-4 regression"));
                        REQUIRE(moderated.complete);
                        REQUIRE(moderated.status == 200U);
                        REQUIRE(pending.pending());
                        auto const persisted = durable_record(path, original);
                        if (remove)
                        {
                            REQUIRE(persisted.removed);
                        }
                        else
                        {
                            REQUIRE(persisted.quarantined);
                            REQUIRE_FALSE(persisted.removed);
                        }
                        REQUIRE(pending.pending());
                        // Expected behavioral RED: pre-repair code publishes
                        // decoded bytes after the record ceased to be servable.
                        auto const completed = pending.collect();
                        check_not_served(completed, image);
                    }
                    use_worker(runtime, MEROVINGIAN_TEST_THUMBNAIL_WORKER);
                    require_thumbnail(transact(port, request("GET", thumbnail_target(alias, 2U), token)), 2U);
                    check_not_served(transact(port, request("GET", thumbnail_target(original, 2U), token)), image);
                    if (!remove)
                    {
                        auto const released =
                            transact(port, request("POST", "/_merovingian/admin/media/release/" + original, token));
                        REQUIRE(released.complete);
                        REQUIRE(released.status == 200U);
                        auto const persisted = durable_record(path, original);
                        REQUIRE_FALSE(persisted.quarantined);
                        REQUIRE_FALSE(persisted.removed);
                        require_thumbnail(transact(port, request("GET", thumbnail_target(original, 2U), token)), 2U);
                    }
                    else
                    {
                        // Removal has no restoration step: the old identity
                        // stays unavailable even though the shared bytes live.
                        auto const persisted = durable_record(path, original);
                        CHECK(persisted.removed);
                        check_not_served(
                            transact(port, request("GET", "/_matrix/client/v1/media/download/example.org/" + original,
                                                   token)),
                            image);
                    }
                    auto const surviving = durable_record(path, alias);
                    CHECK_FALSE(surviving.quarantined);
                    CHECK_FALSE(surviving.removed);
                    require_thumbnail(transact(port, request("GET", thumbnail_target(alias, 4U), token)), 4U);
                    // PendingThumbnail scopes have released and waited before
                    // listener/pools join, runtime destruction and file cleanup.
                }
            }
        }
    }
}

SCENARIO("MED-4 a generated thumbnail is served from the cache only while its record is servable",
         "[med-4-cache][media][database][http]")
{
    GIVEN("an uploaded image whose 4x4 thumbnail was generated once by the real worker")
    {
        auto const directory = PrivateDirectory{};
        auto const path = directory.path() / "media.sqlite3";
        auto started = merovingian::homeserver::start_client_server(sqlite_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        use_worker(runtime, MEROVINGIAN_TEST_THUMBNAIL_WORKER);
        auto listener = DispatchedListener{runtime};
        auto const port = listener.port();
        auto const token = login_admin(runtime, port);
        auto const image = sample_png();
        auto const id = upload(port, token, image);
        require_thumbnail(transact(port, request("GET", thumbnail_target(id, 4U), token)), 4U);

        WHEN("the worker becomes unavailable")
        {
            use_worker(runtime, (directory.path() / "no-such-worker").string());

            THEN("the same thumbnail is still served, a new size is not, and moderation withholds the cached one")
            {
                require_thumbnail(transact(port, request("GET", thumbnail_target(id, 4U), token)), 4U);
                check_not_served(transact(port, request("GET", thumbnail_target(id, 3U), token)), image);
                auto const quarantined =
                    transact(port, request("POST", "/_merovingian/admin/media/quarantine/" + id, token, "MED-4"));
                REQUIRE(quarantined.status == 200U);
                check_not_served(transact(port, request("GET", thumbnail_target(id, 4U), token)), image);
                auto const released = transact(port, request("POST", "/_merovingian/admin/media/release/" + id, token));
                REQUIRE(released.status == 200U);
                require_thumbnail(transact(port, request("GET", thumbnail_target(id, 4U), token)), 4U);
            }
        }
    }
}

SCENARIO("MED-4 one requester cannot run more thumbnail decodes at once than the per-user cap",
         "[med-4-concurrency][media][database][concurrency]")
{
    GIVEN("an uploaded image and two decodes for one user held at the gate")
    {
        auto const directory = PrivateDirectory{};
        auto const path = directory.path() / "media.sqlite3";
        auto gate = ChildGate{directory.path()};
        auto started = merovingian::homeserver::start_client_server(sqlite_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        use_worker(runtime, MEROVINGIAN_TEST_THUMBNAIL_WORKER);
        auto listener = DispatchedListener{runtime};
        auto const port = listener.port();
        auto const token = login_admin(runtime, port);
        auto const image = sample_png();
        auto const id = upload(port, token, image);
        use_worker(runtime, gate.executable());
        gate.arm();
        auto first = std::async(std::launch::async, [&] {
            return router_get(runtime, thumbnail_target(id, 2U), token);
        });
        REQUIRE(gate.entered());
        auto second = std::async(std::launch::async, [&] {
            return router_get(runtime, thumbnail_target(id, 3U), token);
        });
        REQUIRE(gate.entered());

        WHEN("the same user asks for a third thumbnail")
        {
            auto third = std::async(std::launch::async, [&] {
                return router_get(runtime, thumbnail_target(id, 4U), token);
            });
            auto const answered = third.wait_for(std::chrono::seconds{10}) == std::future_status::ready;
            // Release every gated child, including a third one if the cap failed.
            for (auto i = 0; i < 3; ++i)
            {
                std::ignore = gate.release_one();
            }
            auto const first_result = first.get();
            auto const second_result = second.get();

            THEN("it is refused at once with 429, and the two held decodes still complete")
            {
                REQUIRE(answered);
                auto const third_result = third.get();
                CHECK(third_result.status == 429U);
                CHECK(third_result.body.find("M_LIMIT_EXCEEDED") != std::string::npos);
                require_thumbnail(first_result, 2U);
                require_thumbnail(second_result, 3U);
            }
        }
    }
}

SCENARIO("MED-4 a remote thumbnail decoded while its cached record is quarantined is not served",
         "[med-4-remote][media][remote][concurrency]")
{
    GIVEN("a remote image admitted into the cache and its thumbnail decode held at the gate")
    {
        auto const directory = PrivateDirectory{};
        auto const path = directory.path() / "media.sqlite3";
        auto gate = ChildGate{directory.path()};
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto started = merovingian::homeserver::start_client_server(remote_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        {
            auto const lock = std::lock_guard{runtime.homeserver.mutex};
            runtime.homeserver.media_repository.config.private_address_fetches_blocked = false;
            runtime.homeserver.test_forced_outbound_resolution["peer.example.org"] = {
                "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};
        }
        runtime.rate_limit_engine.reset();
        auto listener = DispatchedListener{runtime};
        auto const port = listener.port();
        auto const token = login_admin(runtime, port);
        auto const image = sample_png();
        auto const multipart = std::string{"--med4\r\nContent-Type: application/json\r\n\r\n{}\r\n"
                                           "--med4\r\nContent-Type: image/png\r\n\r\n"} +
                               image + "\r\n--med4--\r\n";
        auto const peer_response =
            std::string{"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=med4\r\nConnection: "
                        "close\r\nContent-Length: "} +
            std::to_string(multipart.size()) + "\r\n\r\n" + multipart;
        auto peer = std::thread{[&] {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, *tls.context,
                                                                       {
                                                                           {"/media/download/remote", peer_response}
            });
        }};
        auto const peer_join = merovingian::tests::tls_mock::ScopedThreadJoin{peer};
        use_worker(runtime, gate.executable());
        gate.arm();
        auto const remote_target =
            std::string{"/_matrix/client/v1/media/thumbnail/peer.example.org/remote?width=2&height=2&method=scale"};
        auto pending = PendingThumbnail{gate, port, request("GET", remote_target, token)};
        REQUIRE(gate.entered());
        if (peer.joinable())
        {
            peer.join();
        }
        auto const local_id = [&] {
            auto const lock = std::lock_guard{runtime.homeserver.mutex};
            auto const& cache = runtime.homeserver.media_repository.remote_media_cache;
            return cache.empty() ? std::string{} : cache.front().local_media_id;
        }();
        REQUIRE_FALSE(local_id.empty());

        WHEN("an administrator quarantines the cached record before the decode finishes")
        {
            auto const quarantined =
                transact(port, request("POST", "/_merovingian/admin/media/quarantine/" + local_id, token, "MED-4"));
            auto const completed = pending.collect();

            THEN("the thumbnail is not served")
            {
                REQUIRE(quarantined.status == 200U);
                CHECK(completed.status != 200U);
                CHECK_FALSE(png_signature(completed.body));
            }
        }
    }
}

#endif // Real worker AND real child gate available; no fake passing fallback.
