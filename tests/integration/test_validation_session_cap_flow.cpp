// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"

// C10 (ADR-0684): the cap on open identity validation sessions is counted per client address as the rate limiter
// resolves it (trusted proxies, IPv6 prefix grouping), not per TCP peer, so behind a reverse proxy one client cannot
// use up the cap for every other client.
//
// Spec: Matrix Client-Server API v1.19, "POST /register/email/requestToken" (a server may refuse with 429
// M_LIMIT_EXCEEDED). ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/MockIdentityServer.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <string>
#include <utility>

namespace
{

namespace hs = merovingian::homeserver;
using merovingian::tests::tls_mock::MockIdentityServer;

[[nodiscard]] auto make_config(bool behind_proxy) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "example.org";
    server.client_api.max_registration_validation_sessions_per_remote = 4U;
    if (behind_proxy)
    {
        server.trusted_proxies = {"10.0.0.1"};
    }
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

// One registration email requestToken, as `peer` with the given forwarded client (empty for none).
[[nodiscard]] auto request_token(hs::ClientServerRuntime& runtime, MockIdentityServer& identity_server, int number,
                                 std::string const& peer, std::string const& forwarded) -> hs::LocalHttpResponse
{
    auto body = std::string{R"({"client_secret":"secret-)"} + std::to_string(number) + R"(","email":"user)" +
                std::to_string(number) + R"(@example.org","send_attempt":1})";
    auto request = hs::LocalHttpRequest{
        "POST", "/_matrix/client/v3/register/email/requestToken", {}, identity_server.with_identity_server(body)};
    request.remote_addr = peer;
    if (!forwarded.empty())
    {
        request.headers = {
            {"X-Forwarded-For", forwarded}
        };
    }
    return hs::handle_client_server_request(runtime, request).response;
}

} // namespace

SCENARIO("Behind a trusted proxy each client has its own validation session cap", "[validation][c10][integration]")
{
    GIVEN("a runtime behind a proxy with a cap of four sessions per client")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_client_server(make_config(true));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto identity_server = MockIdentityServer{MockIdentityServer::cooperative_responses({})};
        identity_server.install(runtime);

        WHEN("one client fills its cap and another client asks through the same proxy")
        {
            auto fifth = hs::LocalHttpResponse{};
            for (auto number = 0; number < 5; ++number)
            {
                fifth = request_token(runtime, identity_server, number, "10.0.0.1", "203.0.113.10");
            }
            auto const other = request_token(runtime, identity_server, 10, "10.0.0.1", "203.0.113.20");

            THEN("the first client is refused at its cap and the other client is served")
            {
                REQUIRE(fifth.status == 429U);
                REQUIRE(other.status != 429U);
            }
        }
    }
}

SCENARIO("Without a proxy addresses of one IPv6 prefix share a validation session cap",
         "[validation][c10][integration]")
{
    GIVEN("a runtime with no proxy and a cap of four sessions per client")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_client_server(make_config(false));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto identity_server = MockIdentityServer{MockIdentityServer::cooperative_responses({})};
        identity_server.install(runtime);

        WHEN("five requests come from different addresses in one /64")
        {
            auto last = hs::LocalHttpResponse{};
            for (auto number = 0; number < 5; ++number)
            {
                last =
                    request_token(runtime, identity_server, number, "2001:db8:1:2::" + std::to_string(number + 1), {});
            }

            THEN("the fifth is refused as one client's")
            {
                REQUIRE(last.status == 429U);
            }
        }

        WHEN("a client in another prefix asks after the cap was filled")
        {
            for (auto number = 0; number < 4; ++number)
            {
                REQUIRE(request_token(runtime, identity_server, number, "203.0.113.5", {}).status != 429U);
            }
            auto const other = request_token(runtime, identity_server, 20, "203.0.113.6", {});

            THEN("a different IPv4 address is served")
            {
                REQUIRE(other.status != 429U);
            }
        }
    }
}
