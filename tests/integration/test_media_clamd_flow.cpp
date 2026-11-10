// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Media uploads with the optional clamd malware scanner (G15, ADR-0565), end to end through the client-server
// dispatcher against a fake clamd on an AF_UNIX socket. The fake records data on its own thread; assertions run on
// the test thread.

#include "../support/FakeClamdServer.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/ClamdMediaScan.hpp"
#include "merovingian/media/MediaAcceptancePolicy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <unistd.h>

#include <optional>
#include <string>
#include <string_view>

namespace
{

using namespace merovingian::tests;

auto const png_bytes = std::string{"\x89PNG\r\n\x1a\nclamd-flow-image"};

[[nodiscard]] auto clamd_config(std::string const& socket, std::string const& remote_policy = "quarantine")
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.media.clamd_socket_path = socket;
    security.media.clamd_timeout_ms = 1500U;
    security.media.remote_fetch_media_policy = remote_policy;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto socket_path(std::string const& name) -> std::string
{
    return (merovingian::tests::temporary_directory() / ("mvg-clamdflow-" + name + "-" + std::to_string(::getpid())))
        .string();
}

[[nodiscard]] auto nul_terminated(std::string text) -> std::string
{
    text.push_back('\0');
    return text;
}

[[nodiscard]] auto login(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                .response.status == 200U);
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
                  R"("password":"CorrectHorse7!","device_id":"ALICE_DEV"})"});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// Uploads PNG bytes and returns the media ID from the content_uri.
[[nodiscard]] auto upload(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/media/v3/upload",
                  token,
                  png_bytes,
                  {merovingian::http::Header{"Content-Type", "image/png"}}});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* content_uri = string_member(body, "content_uri");
    REQUIRE(content_uri != nullptr);
    return content_uri->substr(std::string_view{"mxc://example.org/"}.size());
}

[[nodiscard]] auto download(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                            std::string const& media_id) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, token, {}});
}

} // namespace

SCENARIO("an upload clamd finds infected stays quarantined and is not served",
         "[g15][integration][media][clamd][security]")
{
    GIVEN("a server with clamd on, and a clamd that reports a signature")
    {
        auto const path = socket_path("found");
        auto const clamd = FakeClamdServer{path, nul_terminated("stream: Win.Test.EICAR_HDB-1 FOUND")};
        REQUIRE(clamd.ok());
        auto started = merovingian::homeserver::start_client_server(clamd_config(path));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("an image is uploaded and then downloaded")
        {
            auto const media_id = upload(started.runtime, token);
            auto const served = download(started.runtime, token, media_id);

            THEN("clamd received the bytes and the media is refused, not served")
            {
                auto const streams = clamd.received_streams();
                REQUIRE(streams.size() == 1U);
                REQUIRE(streams.front() == png_bytes);
                REQUIRE(served.response.status != 200U);
                REQUIRE(served.response.body.find(png_bytes) == std::string::npos);
            }
        }
    }
}

SCENARIO("an upload clamd clears is served", "[g15][integration][media][clamd]")
{
    GIVEN("a server with clamd on, and a clamd that answers OK")
    {
        auto const path = socket_path("ok");
        auto const clamd = FakeClamdServer{path, nul_terminated("stream: OK")};
        REQUIRE(clamd.ok());
        auto started = merovingian::homeserver::start_client_server(clamd_config(path));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("an image is uploaded and downloaded")
        {
            auto const media_id = upload(started.runtime, token);
            auto const served = download(started.runtime, token, media_id);

            THEN("it is served in full")
            {
                REQUIRE(clamd.received_streams().size() == 1U);
                REQUIRE(served.response.status == 200U);
                REQUIRE(served.response.body == png_bytes);
            }
        }
    }
}

SCENARIO("an upload while clamd is down stays quarantined", "[g15][integration][media][clamd][security]")
{
    GIVEN("a server with clamd on and nothing listening on its socket")
    {
        auto started = merovingian::homeserver::start_client_server(clamd_config(socket_path("down")));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("an image is uploaded and downloaded")
        {
            auto const media_id = upload(started.runtime, token);
            auto const served = download(started.runtime, token, media_id);

            THEN("the upload is accepted for the client but the media is not served")
            {
                REQUIRE(served.response.status != 200U);
                REQUIRE(served.response.body.find(png_bytes) == std::string::npos);
            }
        }
    }
}

SCENARIO("with clamd off an upload is served as before", "[g15][integration][media][clamd]")
{
    GIVEN("a server with no clamd socket configured")
    {
        auto started = merovingian::homeserver::start_client_server(clamd_config(""));
        REQUIRE(started.started);
        REQUIRE(started.runtime.homeserver.clamd_scanner == nullptr);
        auto const token = login(started.runtime);

        WHEN("an image is uploaded and downloaded")
        {
            auto const media_id = upload(started.runtime, token);
            auto const served = download(started.runtime, token, media_id);

            THEN("it is served")
            {
                REQUIRE(served.response.status == 200U);
                REQUIRE(served.response.body == png_bytes);
            }
        }
    }
}

SCENARIO("remote media is scanned only when its policy is allow-after-scan", "[g15][integration][media][clamd]")
{
    GIVEN("a server with clamd on, and a clamd that finds a signature")
    {
        auto const path = socket_path("remote");
        auto const clamd = FakeClamdServer{path, nul_terminated("stream: Some.Signature FOUND")};
        REQUIRE(clamd.ok());
        auto started = merovingian::homeserver::start_client_server(clamd_config(path, "allow-after-scan"));
        REQUIRE(started.started);

        WHEN("remote bytes are put to the scanner under each policy")
        {
            auto const scanned = merovingian::homeserver::clamd_media_cleared(started.runtime.homeserver, true,
                                                                              "server", "other.example/abc", png_bytes);
            started.runtime.homeserver.media_repository.config.remote_fetch_media_policy =
                merovingian::media::MediaAcceptancePolicy::quarantine;
            auto const skipped = merovingian::homeserver::clamd_media_cleared(started.runtime.homeserver, true,
                                                                              "server", "other.example/abc", png_bytes);

            THEN("allow-after-scan gets a not-cleared verdict, while quarantine never asks clamd")
            {
                REQUIRE(scanned.has_value());
                REQUIRE_FALSE(*scanned);
                REQUIRE_FALSE(skipped.has_value());
                REQUIRE(clamd.connections() == 1U);
            }
        }
    }
}
