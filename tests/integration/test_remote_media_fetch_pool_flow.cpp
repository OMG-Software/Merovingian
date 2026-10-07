// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0121: a remote media download or thumbnail that has to fetch from the
// origin is handed to a dedicated media fetch pool, as a waiting /sync is handed
// to the sync pool. Element Web loads an image and its thumbnail at the same
// time, and every remote image on screen at once; the one-per-client budget
// that protected the main request pool (ADR-0079) refused all but the first
// with 429, and Element does not retry, so the attachment stayed broken.

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/remote_media_fetch_coalescer.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <sys/socket.h>
#include <sys/time.h>

namespace
{
[[nodiscard]] auto sample_png() -> std::string
{
    constexpr std::array<unsigned char, 81U> bytes{
        137, 80,  78,  71,  13,  10, 26, 10,  0,   0,   0,   13,  73, 72,  68,  82,  0,  0,  0,  8,   0,
        0,   0,   8,   8,   6,   0,  0,  0,   196, 15,  190, 139, 0,  0,   0,   24,  73, 68, 65, 84,  120,
        156, 99,  248, 207, 192, 0,  66, 255, 113, 209, 12,  248, 36, 193, 244, 176, 48, 1,  0,  131, 23,
        127, 129, 6,   228, 109, 45, 0,  0,   0,   0,   73,  69,  78, 68,  174, 66,  96, 130};
    return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
}

[[nodiscard]] auto multipart_png_response(std::string const& image) -> std::string
{
    auto const multipart = std::string{"--pool-boundary\r\nContent-Type: application/json\r\n\r\n{}\r\n"
                                       "--pool-boundary\r\nContent-Type: image/png\r\n\r\n"} +
                           image + "\r\n--pool-boundary--\r\n";
    return std::string{"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; "
                       "boundary=pool-boundary\r\nConnection: close\r\nContent-Length: "} +
           std::to_string(multipart.size()) + "\r\n\r\n" + multipart;
}

auto send_all(int fd, std::string_view data) -> bool
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

// Reads until the server closes. Bounded by a receive timeout, so a response
// that never comes fails the scenario instead of hanging the suite.
[[nodiscard]] auto receive_until_close(int fd) -> std::string
{
    auto timeout = ::timeval{};
    timeout.tv_sec = 30;
    std::ignore = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    auto output = std::string{};
    auto buffer = std::array<char, 4096U>{};
    while (true)
    {
        auto const received = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (received <= 0)
        {
            break;
        }
        output.append(buffer.data(), static_cast<std::size_t>(received));
    }
    return output;
}

[[nodiscard]] auto get_request(std::string_view target, std::string_view token) -> std::string
{
    return "GET " + std::string{target} + " HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " +
           std::string{token} + "\r\nConnection: close\r\n\r\n";
}

// One request served on a socketpair, as a request-pool worker serves it. When
// the request was handed to another pool, the server end now belongs to that
// pool's task and the response arrives on `client` later.
struct ServedRequest final
{
    bool transferred{false};
    merovingian::core::FileDescriptor client{-1};
};

[[nodiscard]] auto serve(merovingian::homeserver::ClientServerRuntime& runtime,
                         merovingian::homeserver::HttpServeStats& stats, std::string const& request,
                         std::string_view peer, merovingian::net::ThreadPool* media_fetch_pool) -> ServedRequest
{
    auto sockets = std::array<int, 2>{-1, -1};
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
    auto server = merovingian::core::FileDescriptor{sockets[0]};
    auto client = merovingian::core::FileDescriptor{sockets[1]};
    REQUIRE(send_all(client.get(), request));
    auto const transferred = merovingian::homeserver::serve_one_http_connection(
        server.get(), runtime, stats, merovingian::homeserver::HttpDispatchMode::client_server, nullptr, peer,
        media_fetch_pool);
    if (transferred)
    {
        std::ignore = server.release();
    }
    return {transferred, std::move(client)};
}

[[nodiscard]] auto media_config(merovingian::config::ServerConfig server = {},
                                merovingian::config::ClientRateLimitsConfig rate_limits = {})
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.media.remote_fetch_enabled = true;
    security.media.remote_fetch_media_policy = "allow";
    return merovingian::config::Config{std::move(server),
                                       merovingian::config::ListenersConfig{},
                                       merovingian::tests::in_memory_database_config(),
                                       security,
                                       std::move(rate_limits),
                                       merovingian::config::LogModulesConfig{}};
}

// A logged-in user and an HTTPS origin for peer.example.org. The runtime is
// used in place: its callbacks capture its address, so it must not be moved.
[[nodiscard]] auto login_media_user(merovingian::homeserver::ClientServerRuntime& runtime, std::uint16_t origin_port,
                                    std::string const& certificate_pem) -> std::string
{
    runtime.homeserver.media_repository.config.private_address_fetches_blocked = false;
    auto const user = merovingian::homeserver::register_local_user(runtime.homeserver, "pool_user", "CorrectHorse7!",
                                                                   merovingian::tests::registration_token);
    REQUIRE(user.ok);
    auto const login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, user.value, "POOL");
    REQUIRE(login.ok);
    runtime.homeserver.test_forced_outbound_resolution["peer.example.org"] = {
        "localhost", origin_port, {"127.0.0.1"}, certificate_pem};
    return login.value;
}

constexpr auto client_peer = std::string_view{"203.0.113.7"};
} // namespace

SCENARIO("A remote media download that is still being fetched does not hold a request thread",
         "[media-fetch-pool][media][remote][http]")
{
    GIVEN("a remote origin that is reachable but slow to answer, and a media fetch pool")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto started = merovingian::homeserver::start_client_server(media_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();
        auto const token = login_media_user(runtime, acceptor.bound_port(), certificate.certificate_pem);
        auto const image = sample_png();
        auto state = merovingian::tests::tls_mock::StallingTlsServerState{};
        auto origin = std::thread{[&]() {
            merovingian::tests::tls_mock::run_stalling_tls_server(
                acceptor, *tls.context, state, multipart_png_response(image), std::chrono::seconds{20});
        }};
        auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{origin};
        auto media_pool = merovingian::net::ThreadPool{2U};
        auto stats = merovingian::homeserver::HttpServeStats{};

        WHEN("a client downloads the remote file and then makes an unrelated request")
        {
            auto const began = std::chrono::steady_clock::now();
            auto download =
                serve(runtime, stats, get_request("/_matrix/client/v1/media/download/peer.example.org/slow", token),
                      client_peer, &media_pool);
            auto const handed_off_after = std::chrono::steady_clock::now() - began;
            REQUIRE(merovingian::tests::tls_mock::wait_for_flag(state.request_received, std::chrono::seconds{10}));
            auto versions =
                serve(runtime, stats, get_request("/_matrix/client/versions", token), client_peer, &media_pool);
            auto const versions_response = receive_until_close(versions.client.get());
            auto const origin_answered_before_versions = state.released.load();
            state.released.store(true);
            auto const download_response = receive_until_close(download.client.get());
            media_pool.request_stop();

            THEN("the request thread was released at once and served the next request while the origin stalled")
            {
                REQUIRE(download.transferred);
                REQUIRE(handed_off_after < std::chrono::seconds{2});
                REQUIRE_FALSE(versions.transferred);
                REQUIRE(versions_response.starts_with("HTTP/1.1 200"));
                REQUIRE_FALSE(origin_answered_before_versions);
            }

            THEN("the download completes with the remote image once the origin answers")
            {
                REQUIRE(download_response.starts_with("HTTP/1.1 200"));
                REQUIRE(download_response.ends_with(image));
            }

            THEN("the media fetch admission is released when the fetch ends")
            {
                REQUIRE(runtime.media_fetch_budget->active() == 0U);
            }
        }
    }
}

SCENARIO("A client loading several remote files at once is served every one", "[media-fetch-pool][media][remote][http]")
{
    GIVEN("a remote origin serving three different images and a media fetch pool")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto started = merovingian::homeserver::start_client_server(media_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();
        auto const token = login_media_user(runtime, acceptor.bound_port(), certificate.certificate_pem);
        auto const image = sample_png();
        auto const response = multipart_png_response(image);
        auto origin = std::thread{[&]() {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, *tls.context,
                                                                       {
                                                                           {"/media/download/one",   response},
                                                                           {"/media/download/two",   response},
                                                                           {"/media/download/three", response}
            });
        }};
        auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{origin};
        auto media_pool = merovingian::net::ThreadPool{3U};
        auto stats = merovingian::homeserver::HttpServeStats{};

        WHEN("one client address requests all three before any has been answered")
        {
            auto requests = std::vector<ServedRequest>{};
            for (auto const* media_id : {"one", "two", "three"})
            {
                requests.push_back(serve(
                    runtime, stats,
                    get_request(std::string{"/_matrix/client/v1/media/download/peer.example.org/"} + media_id, token),
                    client_peer, &media_pool));
            }
            auto responses = std::vector<std::string>{};
            for (auto& request : requests)
            {
                responses.push_back(receive_until_close(request.client.get()));
            }
            media_pool.request_stop();

            THEN("every download was handed off and answered with the image, none refused with 429")
            {
                for (auto const& request : requests)
                {
                    REQUIRE(request.transferred);
                }
                for (auto const& body : responses)
                {
                    INFO(body.substr(0U, 200U));
                    REQUIRE(body.starts_with("HTTP/1.1 200"));
                    REQUIRE(body.ends_with(image));
                }
            }
        }
    }
}

SCENARIO("Concurrent requests for the same remote file reach the origin once",
         "[media-fetch-pool][media][remote][http][concurrency]")
{
    GIVEN("a remote origin that answers a single request, slowly, and a media fetch pool")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto started = merovingian::homeserver::start_client_server(media_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();
        auto const token = login_media_user(runtime, acceptor.bound_port(), certificate.certificate_pem);
        auto const image = sample_png();
        auto state = merovingian::tests::tls_mock::StallingTlsServerState{};
        auto origin = std::thread{[&]() {
            merovingian::tests::tls_mock::run_stalling_tls_server(
                acceptor, *tls.context, state, multipart_png_response(image), std::chrono::seconds{20});
        }};
        auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{origin};
        auto media_pool = merovingian::net::ThreadPool{2U};
        auto stats = merovingian::homeserver::HttpServeStats{};

        WHEN("the file is downloaded and its thumbnail requested while the first fetch is in flight")
        {
            auto download =
                serve(runtime, stats, get_request("/_matrix/client/v1/media/download/peer.example.org/shared", token),
                      client_peer, &media_pool);
            REQUIRE(merovingian::tests::tls_mock::wait_for_flag(state.request_received, std::chrono::seconds{10}));
            auto thumbnail =
                serve(runtime, stats,
                      get_request("/_matrix/client/v1/media/thumbnail/peer.example.org/shared?width=8&height=8", token),
                      client_peer, &media_pool);
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
            while (runtime.homeserver.remote_media_fetch_coalescer->waiting() == 0U &&
                   std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{5});
            }
            auto const second_request_waited = runtime.homeserver.remote_media_fetch_coalescer->waiting() == 1U;
            state.released.store(true);
            auto const download_response = receive_until_close(download.client.get());
            auto const thumbnail_response = receive_until_close(thumbnail.client.get());
            media_pool.request_stop();

            THEN("the second request waited for the first fetch instead of starting its own")
            {
                REQUIRE(download.transferred);
                REQUIRE(thumbnail.transferred);
                REQUIRE(second_request_waited);
            }

            THEN("both are answered from the one fetch, and one local copy holds the file")
            {
                REQUIRE(download_response.starts_with("HTTP/1.1 200"));
                REQUIRE(download_response.ends_with(image));
                INFO(thumbnail_response.substr(0U, 200U));
                REQUIRE_FALSE(thumbnail_response.starts_with("HTTP/1.1 429"));
                REQUIRE_FALSE(thumbnail_response.starts_with("HTTP/1.1 502"));
                REQUIRE(runtime.homeserver.media_repository.remote_media_cache.size() == 1U);
            }
        }
    }
}

SCENARIO("Remote media fetches beyond the media pool's admission get immediate backpressure",
         "[media-fetch-pool][media][remote][http][admission]")
{
    GIVEN("a media fetch pool that admits one fetch per client, and a slow origin")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto server = merovingian::config::ServerConfig{};
        server.http.media_fetch_max_per_client = 1U;
        auto started = merovingian::homeserver::start_client_server(media_config(server));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();
        auto const token = login_media_user(runtime, acceptor.bound_port(), certificate.certificate_pem);
        auto const image = sample_png();
        auto stats = merovingian::homeserver::HttpServeStats{};

        WHEN("one client starts a second fetch while its first is still in flight")
        {
            auto state = merovingian::tests::tls_mock::StallingTlsServerState{};
            auto origin = std::thread{[&]() {
                merovingian::tests::tls_mock::run_stalling_tls_server(
                    acceptor, *tls.context, state, multipart_png_response(image), std::chrono::seconds{20});
            }};
            auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{origin};
            auto media_pool = merovingian::net::ThreadPool{2U};
            auto first =
                serve(runtime, stats, get_request("/_matrix/client/v1/media/download/peer.example.org/first", token),
                      client_peer, &media_pool);
            REQUIRE(merovingian::tests::tls_mock::wait_for_flag(state.request_received, std::chrono::seconds{10}));
            auto const began = std::chrono::steady_clock::now();
            auto second =
                serve(runtime, stats, get_request("/_matrix/client/v1/media/download/peer.example.org/second", token),
                      client_peer, &media_pool);
            auto const refused_after = std::chrono::steady_clock::now() - began;
            auto const second_response = receive_until_close(second.client.get());
            auto other =
                serve(runtime, stats, get_request("/_matrix/client/v1/media/download/peer.example.org/first", token),
                      "198.51.100.9", &media_pool);
            state.released.store(true);
            auto const first_response = receive_until_close(first.client.get());
            auto const other_response = receive_until_close(other.client.get());
            media_pool.request_stop();

            THEN("the second is refused at once with 429 and a retry delay, without holding a thread")
            {
                REQUIRE_FALSE(second.transferred);
                REQUIRE(refused_after < std::chrono::milliseconds{500});
                REQUIRE(second_response.starts_with("HTTP/1.1 429"));
                REQUIRE(second_response.find("M_LIMIT_EXCEEDED") != std::string::npos);
                REQUIRE(second_response.find("retry_after_ms") != std::string::npos);
            }

            THEN("the first fetch and another client's request are unaffected")
            {
                REQUIRE(first_response.starts_with("HTTP/1.1 200"));
                REQUIRE(other.transferred);
                REQUIRE(other_response.starts_with("HTTP/1.1 200"));
                REQUIRE(runtime.media_fetch_budget->active() == 0U);
            }
        }

        WHEN("the media fetch pool cannot take the handoff")
        {
            auto media_pool = merovingian::net::ThreadPool{2U};
            media_pool.request_stop();
            auto const began = std::chrono::steady_clock::now();
            auto refused =
                serve(runtime, stats, get_request("/_matrix/client/v1/media/download/peer.example.org/stopped", token),
                      client_peer, &media_pool);
            auto const elapsed = std::chrono::steady_clock::now() - began;
            auto const response = receive_until_close(refused.client.get());

            THEN("the client gets immediate backpressure and the admission is released")
            {
                REQUIRE_FALSE(refused.transferred);
                REQUIRE(elapsed < std::chrono::milliseconds{500});
                REQUIRE(response.starts_with("HTTP/1.1 429"));
                REQUIRE(runtime.media_fetch_budget->active() == 0U);
            }
        }
    }
}

SCENARIO("A remote media download handed to the media pool is counted against the rate limit once",
         "[media-fetch-pool][media][remote][http][rate-limit]")
{
    GIVEN("a media rate limit of one request per minute for each client, and a media fetch pool")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto rate_limits = merovingian::config::ClientRateLimitsConfig{};
        rate_limits.tier["media"] = merovingian::http::RateLimitPolicy{1U, 60U};
        auto started = merovingian::homeserver::start_client_server(media_config({}, rate_limits));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = login_media_user(runtime, acceptor.bound_port(), certificate.certificate_pem);
        auto const image = sample_png();
        auto origin = std::thread{[&]() {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                acceptor, *tls.context,
                {
                    {"/media/download/limited", multipart_png_response(image)}
            });
        }};
        auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{origin};
        auto media_pool = merovingian::net::ThreadPool{2U};
        auto stats = merovingian::homeserver::HttpServeStats{};

        WHEN("the client downloads one remote file")
        {
            auto download =
                serve(runtime, stats, get_request("/_matrix/client/v1/media/download/peer.example.org/limited", token),
                      client_peer, &media_pool);
            auto const response = receive_until_close(download.client.get());
            media_pool.request_stop();

            THEN("the media pool's pass over the request is not refused as a second request")
            {
                REQUIRE(download.transferred);
                INFO(response.substr(0U, 200U));
                REQUIRE(response.starts_with("HTTP/1.1 200"));
                REQUIRE(response.ends_with(image));
            }
        }
    }
}
