// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// The query of an OAuth 2.0 page or endpoint is never logged (ADR-0786): every log line that names a request target
// goes through observability::sanitized_http_target, which keeps only the path of /_merovingian/oauth2/* and
// /_merovingian/account/*. These scenarios drive the client-server dispatcher with the console log captured at debug
// level, so the per-request lines (request.received, request.route_not_found, request.rejected) are seen.

#include "../support/ConsoleLogCapture.hpp"
#include "../support/ModuleLogLevel.hpp"
#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/OAuthTokenSupport.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/observability/LogLevel.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{

namespace hs = merovingian::homeserver;

auto send(hs::ClientServerRuntime& runtime, std::string method, std::string target, std::string body = {}) -> void
{
    auto request = hs::LocalHttpRequest{std::move(method), std::move(target), {}, std::move(body)};
    request.headers.push_back({"Content-Type", "application/json"});
    std::ignore = hs::handle_client_server_request(runtime, request, /*can_wait=*/false);
}

} // namespace

SCENARIO("The query of an OAuth 2.0 request is never logged", "[integration][oauth][oauth-log][logging][security]")
{
    GIVEN("a homeserver with the OAuth 2.0 API on, and the console log captured at debug level")
    {
        auto started = hs::start_client_server(merovingian::tests::oauth_registration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("OAuth 2.0 requests carry a state, a code, a login hint and a session in their query")
        {
            auto const debug_module =
                merovingian::tests::ModuleLogLevel{"client_server", merovingian::observability::LogLevel::debug};
            auto const capture = merovingian::tests::ConsoleLogCapture{merovingian::observability::LogLevel::debug};
            send(runtime, "GET", "/_merovingian/oauth2/authorize?state=SECRETSTATE&login_hint=SECRETHINT");
            send(runtime, "POST", "/_merovingian/oauth2/register?code=SECRETCODE", "{}");
            send(runtime, "GET", "/_merovingian/account?session=SECRETSESSION");
            send(runtime, "GET", "/_merovingian/oauth2/authorize/../x?id=SECRETNESTED");
            // A control request on a Matrix path, so a pass cannot come from lines that were never written.
            send(runtime, "GET", "/_matrix/client/v3/not_a_route?probe=VISIBLEPROBE");
            auto const text = capture.text();

            THEN("the request lines name the OAuth paths, and none holds a query value")
            {
                REQUIRE(text.find("VISIBLEPROBE") != std::string::npos);
                REQUIRE(text.find("/_merovingian/oauth2/authorize") != std::string::npos);
                REQUIRE(text.find("/_merovingian/oauth2/register") != std::string::npos);
                REQUIRE(text.find("/_merovingian/account") != std::string::npos);
                for (auto const secret : std::array{std::string_view{"SECRETSTATE"}, std::string_view{"SECRETHINT"},
                                                    std::string_view{"SECRETCODE"}, std::string_view{"SECRETSESSION"},
                                                    std::string_view{"SECRETNESTED"}})
                {
                    REQUIRE(text.find(secret) == std::string::npos);
                }
            }
        }
    }
}

SCENARIO("A refused token or device request logs the client ID only when it names a registered client",
         "[integration][oauth][oauth-log][logging][security]")
{
    GIVEN("a homeserver with the device grant on, a client registered for the code grant only, and the oauth log at "
          "debug level")
    {
        auto config = merovingian::tests::oauth_registration_config();
        config.server().oauth.device_grant_enabled = true;
        auto started = hs::start_client_server(std::move(config));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const code_only =
            merovingian::tests::register_oauth_web_client(runtime, R"(,"grant_types":["authorization_code"])");
        REQUIRE_FALSE(code_only.empty());

        WHEN("an unregistered client ID is sent to every token grant and to the device endpoint, and the registered "
             "client asks for a grant it does not hold")
        {
            auto const debug_module =
                merovingian::tests::ModuleLogLevel{"oauth", merovingian::observability::LogLevel::debug};
            auto const capture = merovingian::tests::ConsoleLogCapture{merovingian::observability::LogLevel::debug};
            constexpr auto probe = std::string_view{"UNREGISTEREDPROBE"};
            auto const refresh = merovingian::tests::post_oauth_form(
                runtime, merovingian::tests::oauth_token_path,
                merovingian::tests::refresh_grant_fields(probe, std::string(64U, 'a')));
            auto const code = merovingian::tests::post_oauth_form(
                runtime, merovingian::tests::oauth_token_path,
                merovingian::tests::code_grant_fields(probe, std::string(64U, 'f')));
            auto const device_grant =
                merovingian::tests::post_oauth_form(runtime, merovingian::tests::oauth_token_path,
                                                    {
                                                        {"grant_type", "urn:ietf:params:oauth:grant-type:device_code"},
                                                        {"client_id", std::string{probe}},
                                                        {"device_code", std::string(64U, 'd')},
            });
            auto const device = merovingian::tests::post_oauth_form(runtime, "/_merovingian/oauth2/device",
                                                                    {
                                                                        {"client_id", std::string{probe}},
                                                                        {"scope",     "openid"          },
            });
            auto const registered = merovingian::tests::post_oauth_form(
                runtime, merovingian::tests::oauth_token_path,
                merovingian::tests::refresh_grant_fields(code_only, std::string(64U, 'a')));
            auto const text = capture.text();

            THEN("every refusal is logged, the unregistered ID never, and the registered one is")
            {
                for (auto const* response : {&refresh, &code, &device_grant, &device})
                {
                    CHECK(response->status == 400U);
                }
                CHECK(registered.status == 400U);
                CHECK(text.find("oauth.token.refused") != std::string::npos);
                CHECK(text.find("oauth.device.refused") != std::string::npos);
                CHECK(text.find(code_only) != std::string::npos);
                CHECK(text.find(probe) == std::string::npos);
            }
        }
    }
}
