// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |                 OAUTH 2.0 AWARE CLIENTS CONFORMANCE                     |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 — "OAuth 2.0 aware clients",      |
// |        "GET /login", "GET /login/sso/redirect", "Client login via SSO"  |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// +-------------------------------------------------------------------------+
//
// What a server with the OAuth 2.0 API and the legacy API both on offers clients that know only the legacy API (plan
// P10, ADR-0802).

#include "../support/JsonTestSupport.hpp"
#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/oauth/AuthorizationRedirect.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};

[[nodiscard]] auto start_with_hand_off() -> hs::ClientServerStartResult
{
    auto config = oauth_registration_config();
    config.server().server_name = "example.org";
    enable_token_registration(config.security());
    auto started = hs::start_client_server(std::move(config));
    REQUIRE(started.started);
    started.runtime.rate_limit_engine.reset();
    REQUIRE(
        hs::register_local_user(started.runtime.homeserver, "alice", alice_password, std::string{registration_token})
            .ok);
    return started;
}

[[nodiscard]] auto get(hs::ClientServerRuntime& rt, std::string target, BrowserContext const& browser = {})
    -> hs::LocalHttpResponse
{
    return authorize_request(rt, "GET", std::move(target), {}, browser);
}

[[nodiscard]] auto contains(std::string_view text, std::string_view part) -> bool
{
    return text.find(part) != std::string_view::npos;
}

[[nodiscard]] auto count_occurrences(std::string_view text, std::string_view part) -> std::size_t
{
    auto found = std::size_t{0U};
    for (auto at = text.find(part); at != std::string_view::npos; at = text.find(part, at + 1U))
    {
        ++found;
    }
    return found;
}

} // namespace

// Spec: CS API v1.19 "OAuth 2.0 aware clients", Server behaviour: the homeserver MUST "Provide an implementation of the
// m.login.sso authentication flow", "If password authentication was previously enabled on the homeserver then provide
// an implementation of the m.login.password authentication flow", and "Indicate that the m.login.sso flow is preferred
// by setting oauth_aware_preferred to true."
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#oauth-20-aware-clients
SCENARIO("GET /login offers m.login.sso with oauth_aware_preferred and keeps m.login.password",
         "[oauth][hand-off][conformance]")
{
    GIVEN("a server with the OAuth 2.0 API and the legacy API on")
    {
        auto started = start_with_hand_off();

        WHEN("GET /login is read")
        {
            auto const response = get(started.runtime, "/_matrix/client/v3/login");

            THEN("m.login.sso is preferred, and m.login.password and m.login.token are offered")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(contains(response.body, R"("type":"m.login.sso")"));
                REQUIRE(contains(response.body, R"("oauth_aware_preferred":true)"));
                REQUIRE(contains(response.body, R"("type":"m.login.password")"));
                REQUIRE(contains(response.body, R"("type":"m.login.token")"));
            }
        }
    }
}

// Spec: CS API v1.19 "OAuth 2.0 aware clients", Server behaviour: the homeserver MUST "Support a value for the action
// param on the SSO redirect endpoints." "GET /login/sso/redirect", `action`: "login: the SSO redirect is for the
// purposes of signing an existing user in. register: the SSO redirect is for the purpose of registering a new user
// account."
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3loginssoredirect
SCENARIO("The SSO redirect starts registration for action=register and sign-in for action=login",
         "[oauth][hand-off][conformance]")
{
    GIVEN("a server with the hand-off on and registration open")
    {
        auto started = start_with_hand_off();
        auto const base = std::string{"/_matrix/client/v3/login/sso/redirect?redirectUrl=io.element.app%3A%2Fcb"};

        WHEN("the redirect is opened with each action")
        {
            auto const registering = get(started.runtime, base + "&action=register");
            auto const signing_in = get(started.runtime, base + "&action=login");

            THEN("register shows the registration form and login the sign-in form")
            {
                REQUIRE(registering.status == 200U);
                REQUIRE(contains(registering.body, R"(name="password_confirm")"));
                REQUIRE(signing_in.status == 200U);
                REQUIRE(contains(signing_in.body, R"(autocomplete="current-password")"));
                REQUIRE_FALSE(contains(signing_in.body, R"(name="password_confirm")"));
            }
        }
    }
}

// Spec: CS API v1.19 "Client login via SSO", Security considerations: "Homeservers SHOULD confirm with the user that
// they are happy to grant access to their matrix account to the site named in the redirectUrl." Handling the callback,
// step 4: "If it already includes one or more loginToken parameters, they should be removed before adding the new
// one."
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#client-login-via-sso
SCENARIO("The hand-off confirms the destination before it adds exactly one loginToken",
         "[oauth][hand-off][conformance][security]")
{
    GIVEN("a sign-in started for a redirectUrl holding a stale loginToken")
    {
        auto started = start_with_hand_off();
        auto& rt = started.runtime;
        auto browser = BrowserContext{};
        auto const opened =
            get(rt,
                "/_matrix/client/v3/login/sso/redirect?redirectUrl=" +
                    merovingian::oauth::percent_encode_redirect_value("https://app.example.com/cb?loginToken=stale"),
                browser);
        REQUIRE(opened.status == 200U);
        browser.cookie = cookie_of(opened);
        auto const pending = pending_of(opened);

        WHEN("alice signs in, then continues")
        {
            auto const confirmation = post_authorize(rt,
                                                     {
                                                         {"pending",  pending                    },
                                                         {"action",   "login"                    },
                                                         {"username", "alice"                    },
                                                         {"password", std::string{alice_password}},
            },
                                                     browser);
            auto const approved = post_authorize(rt,
                                                 {
                                                     {"pending", pending  },
                                                     {"action",  "approve"},
            },
                                                 browser);
            auto const answer = redirect_answer(approved);

            THEN("a confirmation naming the site comes first, and the redirect carries one fresh loginToken")
            {
                REQUIRE(confirmation.status == 200U);
                REQUIRE(contains(confirmation.body, "app.example.com"));
                REQUIRE(response_header(confirmation, "Location").empty());
                REQUIRE(approved.status == 303U);
                REQUIRE(answer.base == "https://app.example.com/cb");
                REQUIRE(answer.parameters.size() == 1U);
                REQUIRE(answer.parameters.contains("loginToken"));
                REQUIRE(answer.parameters.at("loginToken") != "stale");
                REQUIRE(count_occurrences(response_header(approved, "Location"), "loginToken=") == 1U);
            }
        }
    }
}
