// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/media/repository.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <thread>
#include <vector>

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
} // namespace

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
