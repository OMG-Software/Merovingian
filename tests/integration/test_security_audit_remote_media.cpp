// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/media/repository.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

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
    auto const multipart = std::string{"--audit-boundary\r\nContent-Type: application/json\r\n\r\n{}\r\n"
                                       "--audit-boundary\r\nContent-Type: image/png\r\n\r\n"} +
                           image + "\r\n--audit-boundary--\r\n";
    return std::string{"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; "
                       "boundary=audit-boundary\r\nConnection: close\r\nContent-Length: "} +
           std::to_string(multipart.size()) + "\r\n\r\n" + multipart;
}

// Connects to `port` and closes at once, so a mock server still waiting in
// accept() for a request that never comes finishes its loop promptly.
auto release_waiting_acceptor(std::uint16_t port) -> void
{
    auto const fd = merovingian::core::SocketHandle{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (!fd.valid())
    {
        return;
    }
    auto address = ::sockaddr_in{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    std::ignore = ::connect(fd.native_handle(), reinterpret_cast<::sockaddr const*>(&address), sizeof(address));
}
} // namespace

// OUT-4 (security-audit-report-2026-09-29.md): every request for a remote
// mxc:// URI went back to the origin, so one client could make this server
// repeat the same outbound fetch indefinitely. The peer below is ready to
// answer twice; a working cache means it is asked once.
SCENARIO("A repeated remote media download is served from the cache without contacting the origin again",
         "[out-4][media][remote][security]")
{
    GIVEN("a real HTTPS peer able to serve the same remote image twice, and remote media admitted without quarantine")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        security.media.remote_fetch_enabled = true;
        security.media.remote_fetch_media_policy = "allow";
        auto const config = merovingian::config::Config{merovingian::config::ServerConfig{},
                                                        merovingian::config::ListenersConfig{},
                                                        merovingian::tests::in_memory_database_config(),
                                                        security,
                                                        merovingian::config::ClientRateLimitsConfig{},
                                                        merovingian::config::LogModulesConfig{}};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.media_repository.config.private_address_fetches_blocked = false;
        runtime.rate_limit_engine.reset();
        auto const user = merovingian::homeserver::register_local_user(
            runtime.homeserver, "media_cache", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, user.value, "MEDIA");
        REQUIRE(login.ok);
        runtime.homeserver.test_forced_outbound_resolution["peer.example.org"] = {
            "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};
        auto const image = sample_png();
        auto const response = multipart_png_response(image);

        WHEN("the same remote image is downloaded twice")
        {
            auto captured = std::vector<std::string>{};
            auto thread = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                    acceptor, *tls.context,
                    {
                        {"/media/download/cached", response},
                        {"/media/download/cached", response}
                },
                    &captured);
            }};
            auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{thread};
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/peer.example.org/cached", login.value, {}});
            auto const second = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/peer.example.org/cached", login.value, {}});
            release_waiting_acceptor(acceptor.bound_port());
            thread.join();

            THEN("both downloads succeed with the image")
            {
                REQUIRE(first.response.status == 200U);
                REQUIRE(second.response.status == 200U);
                REQUIRE(second.response.body == first.response.body);
            }

            THEN("the origin received exactly one request and one local record holds the media")
            {
                REQUIRE(captured.size() == 1U);
                REQUIRE(runtime.homeserver.media_repository.records.size() == 1U);
            }

            THEN("the fetched media is stored in the database, not only in memory (ADR-0119)")
            {
                auto const& store = runtime.homeserver.database.persistent_store;
                REQUIRE(store.local_media.size() == 1U);
                REQUIRE(store.local_media.front().owner_user_id == "@remote-media:peer.example.org");
                auto const& record = runtime.homeserver.media_repository.records.front();
                REQUIRE(merovingian::database::read_media_blob(merovingian::database::prepare_media_blob_read(
                            store, record.storage_id)) == std::optional<std::string>{image});
            }
        }
    }
}

SCENARIO("Remote quarantine refuses image downloads and thumbnails without leaking held bytes",
         "[med-2][media][remote][security]")
{
    GIVEN("a real HTTPS peer supplying a valid PNG and the default remote quarantine policy")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        security.media.remote_fetch_enabled = true;
        auto const config = merovingian::config::Config{merovingian::config::ServerConfig{},
                                                        merovingian::config::ListenersConfig{},
                                                        merovingian::tests::in_memory_database_config(),
                                                        security,
                                                        merovingian::config::ClientRateLimitsConfig{},
                                                        merovingian::config::LogModulesConfig{}};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // The forced test resolution names a known loopback peer. Keep the
        // deployable config secure, then permit that peer in the isolated store.
        runtime.homeserver.media_repository.config.private_address_fetches_blocked = false;
        runtime.rate_limit_engine.reset();
        auto const user = merovingian::homeserver::register_local_user(
            runtime.homeserver, "media_peer", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, user.value, "MEDIA");
        REQUIRE(login.ok);
        runtime.homeserver.test_forced_outbound_resolution["peer.example.org"] = {
            "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};
        auto const image = sample_png();
        auto const multipart = std::string{"--audit-boundary\r\nContent-Type: application/json\r\n\r\n{}\r\n"
                                           "--audit-boundary\r\nContent-Type: image/png\r\n\r\n"} +
                               image + "\r\n--audit-boundary--\r\n";
        auto const response = std::string{"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; "
                                          "boundary=audit-boundary\r\nConnection: close\r\nContent-Length: "} +
                              std::to_string(multipart.size()) + "\r\n\r\n" + multipart;
        WHEN("authenticated download and thumbnail requests fetch the quarantined remote image")
        {
            auto captured = std::vector<std::string>{};
            auto thread = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                    acceptor, *tls.context,
                    {
                        {"/media/download/download",  response},
                        {"/media/download/thumbnail", response}
                },
                    &captured);
            }};
            auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{thread};
            auto const download = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/peer.example.org/download", login.value, {}});
            auto const thumbnail = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v1/media/thumbnail/peer.example.org/thumbnail?width=4&height=4&method=scale",
                          login.value,
                          {}});
            thread.join();
            THEN("both requests fail without serving or embedding payload bytes")
            {
                REQUIRE(captured.size() == 2U);
                REQUIRE(runtime.homeserver.media_repository.records.size() == 2U);
                for (auto const& record : runtime.homeserver.media_repository.records)
                {
                    REQUIRE(record.state == merovingian::media::LocalMediaState::quarantined);
                }
                CHECK(download.response.status == 451U);
                CHECK(thumbnail.response.status == 451U);
                CHECK(download.response.body.find("image/png|") == std::string::npos);
                CHECK(download.response.body.find("PNG") == std::string::npos);
                CHECK(thumbnail.response.body.find("PNG") == std::string::npos);
                CHECK(runtime.homeserver.media_repository.metrics.thumbnails_generated == 0U);
            }
        }
    }
}
