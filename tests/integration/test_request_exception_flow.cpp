// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The client-server dispatch boundary answers an exception a handler lets escape (ADR-0803): a 500 M_UNKNOWN with a
// fixed body, one error line naming the route and the exception's type but never its message, and the runtime lock
// free afterwards. `HomeserverRuntime::test_client_request_hook` makes one request throw.
#include "../support/ConsoleLogCapture.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <future>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>

namespace
{

constexpr auto throwing_path = std::string_view{"/_matrix/client/v3/account/whoami"};
constexpr auto secret_text = std::string_view{"secret-request-data-7f3a"};

[[nodiscard]] auto test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

// Whether another thread can take the runtime lock now: a lock leaked by the unwinding would refuse it.
[[nodiscard]] auto lock_is_free_for_another_thread(merovingian::homeserver::ClientServerRuntime const& runtime) -> bool
{
    return std::async(std::launch::async,
                      [&runtime] {
                          auto const& mutex = runtime.homeserver.mutex;
                          if (!mutex.try_lock())
                          {
                              return false;
                          }
                          mutex.unlock();
                          return true;
                      })
        .get();
}

[[nodiscard]] auto contains(std::string_view text, std::string_view part) -> bool
{
    return text.find(part) != std::string_view::npos;
}

} // namespace

SCENARIO("An exception a client-server handler lets escape is answered with a 500", "[homeserver][request-exception]")
{
    GIVEN("a runtime whose whoami request throws a standard exception carrying request data")
    {
        // The hook runs after the rate limit and before authentication, so a request with no token reaches it. The
        // limiter is removed so the repeated requests of this scenario are never answered 429 before the hook.
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();
        // The message stands for request data a real exception may quote (a parser quoting its input, a path), so
        // it must reach neither the client nor the log.
        runtime.homeserver.test_client_request_hook = [](std::string_view path) {
            if (path == throwing_path)
            {
                throw std::runtime_error{std::string{secret_text}};
            }
        };

        WHEN("the request is made")
        {
            // Captured around the request only, so the log checks below see this request's lines and no start-up.
            auto const capture = merovingian::tests::ConsoleLogCapture{};
            auto const answered =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", std::string{throwing_path}});
            auto const log = capture.text();

            THEN("the client gets 500 M_UNKNOWN with the fixed text and nothing of the message")
            {
                REQUIRE(answered.response.status == 500U);
                REQUIRE(contains(answered.response.body, R"("errcode":"M_UNKNOWN")"));
                REQUIRE(contains(answered.response.body, "internal server error"));
                REQUIRE_FALSE(contains(answered.response.body, secret_text));
            }
            THEN("one error line names the route and the type, never the message")
            {
                REQUIRE(capture.has_line("ERROR", "request.exception"));
                // The route and the type are enough to find the handler; the message is what must not be there.
                REQUIRE(contains(log, throwing_path));
                REQUIRE(contains(log, "runtime_error"));
                REQUIRE_FALSE(contains(log, secret_text));
            }
            THEN("the runtime lock is released")
            {
                // Both checks: the runtime mutex records recursion per thread, so this thread holding it at any depth
                // and another thread being unable to take it are separate ways the unwinding could leak it.
                REQUIRE_FALSE(runtime.homeserver.mutex.held_by_current_thread());
                REQUIRE(lock_is_free_for_another_thread(runtime));
            }
        }

        WHEN("the request throws and then a request that does not throw is made")
        {
            std::ignore =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", std::string{throwing_path}});
            // The first answer is ignored; what matters is that the runtime still serves after the unwinding. A lock
            // leaked by the first request would make this one block or fail.
            auto const versions =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/versions"});

            THEN("the second request is answered as usual")
            {
                REQUIRE(versions.response.status == 200U);
                REQUIRE(contains(versions.response.body, "\"versions\""));
            }
        }
    }

    GIVEN("a runtime whose whoami request throws something that is not a standard exception")
    {
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();
        runtime.homeserver.test_client_request_hook = [](std::string_view path) {
            // Not derived from std::exception: the boundary catches everything, not only what has a what().
            if (path == throwing_path)
            {
                throw 42;
            }
        };

        WHEN("the request is made")
        {
            auto const answered =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", std::string{throwing_path}});

            THEN("it is answered with the same 500 and the lock is released")
            {
                REQUIRE(answered.response.status == 500U);
                REQUIRE(contains(answered.response.body, R"("errcode":"M_UNKNOWN")"));
                REQUIRE(lock_is_free_for_another_thread(runtime));
            }
        }
    }

    GIVEN("a runtime whose whoami request throws std::overflow_error")
    {
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();
        runtime.homeserver.test_client_request_hook = [](std::string_view path) {
            if (path == throwing_path)
            {
                throw std::overflow_error{"counter"};
            }
        };

        WHEN("the request is made")
        {
            auto const answered =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", std::string{throwing_path}});

            THEN("the existing sync stream counter answer is kept")
            {
                // std::overflow_error has its own earlier catch (ADR-0315), which the catch-all must not take over.
                REQUIRE(answered.response.status == 500U);
                REQUIRE(contains(answered.response.body, "sync stream counter exhausted"));
            }
        }
    }

    GIVEN("a runtime with no hook")
    {
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();

        WHEN("the same request is made without a token")
        {
            // The control: without the hook the same request is the handler's 401, so the 500s above came from the
            // hook's exception and not from the request itself.
            auto const answered =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", std::string{throwing_path}});

            THEN("it gets the handler's own answer")
            {
                REQUIRE(answered.response.status == 401U);
                REQUIRE(contains(answered.response.body, "M_MISSING_TOKEN"));
            }
        }
    }
}

SCENARIO("An exception escaping one of the server's own pages is answered with a page",
         "[homeserver][request-exception][oauth][oauth-page]")
{
    GIVEN("a runtime with the OAuth 2.0 API and the device grant on, whose every request throws")
    {
        auto config = merovingian::tests::oauth_registration_config();
        config.server().oauth.device_grant_enabled = true;
        auto started = merovingian::homeserver::start_client_server(std::move(config));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.rate_limit_engine.reset();
        runtime.homeserver.test_client_request_hook = [](std::string_view) {
            throw std::runtime_error{std::string{secret_text}};
        };

        WHEN("a browser opens each page: authorisation, device link, account, and the SSO redirects")
        {
            auto const targets = std::array{
                std::string_view{"/_merovingian/oauth2/authorize?client_id=x"},
                std::string_view{"/_merovingian/oauth2/link"},
                std::string_view{"/_merovingian/account?action=org.matrix.profile"},
                std::string_view{"/_matrix/client/v3/login/sso/redirect?redirectUrl=https%3A%2F%2Fapp.example.com%2F"},
                std::string_view{
                    "/_matrix/client/v3/login/sso/redirect/oidc?redirectUrl=https%3A%2F%2Fapp.example.com%2F"},
            };
            THEN("each answer is a 500 HTML page with the pages' headers, no CORS header and nothing of the message")
            {
                for (auto const target : targets)
                {
                    INFO(target);
                    auto const answered =
                        merovingian::homeserver::handle_client_server_request(runtime, {"GET", std::string{target}});
                    REQUIRE(answered.response.status == 500U);
                    CHECK(answered.response.page);
                    CHECK(merovingian::tests::response_header(answered.response, "Content-Type")
                              .starts_with("text/html"));
                    CHECK_FALSE(
                        merovingian::tests::response_header(answered.response, "Content-Security-Policy").empty());
                    CHECK(
                        merovingian::tests::response_header(answered.response, "Access-Control-Allow-Origin").empty());
                    CHECK_FALSE(contains(answered.response.body, "M_UNKNOWN"));
                    CHECK_FALSE(contains(answered.response.body, secret_text));
                }
                REQUIRE(lock_is_free_for_another_thread(runtime));
            }
        }
        WHEN("an OAuth API endpoint that answers JSON throws")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{"POST", "/_merovingian/oauth2/token"};
            request.headers.push_back({"Content-Type", "application/x-www-form-urlencoded"});
            auto const answered = merovingian::homeserver::handle_client_server_request(runtime, request);
            THEN("it keeps the JSON 500 M_UNKNOWN")
            {
                REQUIRE(answered.response.status == 500U);
                CHECK_FALSE(answered.response.page);
                CHECK(contains(answered.response.body, R"("errcode":"M_UNKNOWN")"));
            }
        }
    }
}
