// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The authorisation code grant's authorisation request (Matrix v1.19 CS API "Authorisation code grant", RFC 6749
// section 4.1, RFC 7636) and `prompt=create` ("User registration"), through the client-server dispatcher.

#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};

[[nodiscard]] auto conformance_config(bool registration) -> merovingian::config::Config
{
    auto config = oauth_registration_config();
    config.server().server_name = "example.org";
    if (registration)
    {
        enable_token_registration(config.security());
    }
    return config;
}

[[nodiscard]] auto contains(std::string_view text, std::string_view part) -> bool
{
    return text.find(part) != std::string_view::npos;
}

// Signs alice in through the pages of `parameters` and approves; returns the redirect.
[[nodiscard]] auto approve_as_alice(hs::ClientServerRuntime& rt,
                                    std::vector<std::pair<std::string, std::string>> const& parameters)
    -> hs::LocalHttpResponse
{
    auto browser = BrowserContext{};
    auto const page = get_authorize(rt, parameters, browser);
    browser.cookie = cookie_of(page);
    auto const pending = pending_of(page);
    auto const consent = post_authorize(rt,
                                        {
                                            {"pending",  pending                    },
                                            {"action",   "login"                    },
                                            {"username", "alice"                    },
                                            {"password", std::string{alice_password}},
    },
                                        browser);
    REQUIRE(consent.status == 200U);
    return post_authorize(rt,
                          {
                              {"pending", pending  },
                              {"action",  "approve"},
    },
                          browser);
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: OAuth 2.0 API, Authorisation code grant; Client registration, Redirect URI validation
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#authorisation-code-grant
//
// Homeservers MUST "use pre-registered, strict redirect URIs"; RFC 6749 section 4.1.2.1: with a missing, invalid or
// mismatching redirect URI the server "MUST NOT automatically redirect the user-agent to the invalid redirection URI".
SCENARIO("An authorisation request with an unregistered redirect URI is never redirected",
         "[conformance][client-server][oauth][oauth-authorize]")
{
    GIVEN("a registered web client")
    {
        auto started = hs::start_client_server(conformance_config(false));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const client_id = register_oauth_web_client(rt);
        REQUIRE_FALSE(client_id.empty());

        WHEN("the request names a redirect URI the client did not register")
        {
            auto const response = get_authorize(rt, with_parameter(oauth_authorize_parameters(client_id),
                                                                   "redirect_uri", "https://app.example.com/cb2"));

            THEN("the server answers itself and sends the browser nowhere")
            {
                // Spec MUST: strict redirect URIs; RFC 6749 MUST NOT redirect to an invalid redirect URI.
                REQUIRE(response.status == 400U);
                REQUIRE(response_header(response, "Location").empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: OAuth 2.0 API, Authorisation code grant
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#authorisation-code-grant
//
// RFC 6749 sections 4.1.2 and 4.1.2.1: the `state` the client sent is REQUIRED in the response, on success and on
// error. Clients with an HTTPS redirect URI MUST use the `fragment` response mode, so the server places the answer
// where `response_mode` says.
SCENARIO("The authorisation response carries the state and follows the response mode",
         "[conformance][client-server][oauth][oauth-authorize]")
{
    GIVEN("alice and a registered web client")
    {
        auto started = hs::start_client_server(conformance_config(true));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        REQUIRE(hs::register_local_user(rt.homeserver, "alice", alice_password, std::string{registration_token}).ok);
        auto const client_id = register_oauth_web_client(rt);
        REQUIRE_FALSE(client_id.empty());
        auto const base = oauth_authorize_parameters(client_id);

        WHEN("alice approves a request with response_mode=fragment")
        {
            auto const answer =
                redirect_answer(approve_as_alice(rt, with_parameter(base, "response_mode", "fragment")));

            THEN("the code and the state are in the fragment of the redirect URI")
            {
                // Spec MUST: the fragment response mode for an HTTPS redirect URI.
                REQUIRE(answer.base == oauth_client_redirect);
                REQUIRE(answer.separator == '#');
                REQUIRE(answer.parameters.contains("code"));
                // RFC 6749 4.1.2 REQUIRED: state, exactly as the client sent it.
                REQUIRE(answer.parameters.at("state") == "st-123 & more");
            }
        }

        WHEN("a request with response_mode=query is refused")
        {
            auto const answer = redirect_answer(get_authorize(
                rt, with_parameter(with_parameter(base, "response_mode", "query"), "response_type", "token")));

            THEN("the error and the state are in the query")
            {
                REQUIRE(answer.separator == '?');
                // RFC 6749 4.1.2.1: error is REQUIRED, unsupported_response_type for a response type not supported.
                REQUIRE(answer.parameters.at("error") == "unsupported_response_type");
                // RFC 6749 4.1.2.1 REQUIRED: state on an error too.
                REQUIRE(answer.parameters.at("state") == "st-123 & more");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: OAuth 2.0 API, Authorisation code grant
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#authorisation-code-grant
//
// Homeservers MUST "support PKCE using the S256 code challenge method"; RFC 7636 section 4.4.1: a server that requires
// PKCE answers a request without it, or with a method it does not support, with `invalid_request`.
SCENARIO("An authorisation request without an S256 code challenge is refused",
         "[conformance][client-server][oauth][oauth-authorize]")
{
    GIVEN("a registered web client")
    {
        auto started = hs::start_client_server(conformance_config(false));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const client_id = register_oauth_web_client(rt);
        auto const base = oauth_authorize_parameters(client_id);

        WHEN("the challenge is missing, or its method is plain")
        {
            auto const missing =
                redirect_answer(get_authorize(rt, with_parameter(base, "code_challenge", std::nullopt)));
            auto const plain =
                redirect_answer(get_authorize(rt, with_parameter(base, "code_challenge_method", "plain")));

            THEN("both are invalid_request")
            {
                // Spec MUST: PKCE with S256.
                REQUIRE(missing.parameters.at("error") == "invalid_request");
                REQUIRE(plain.parameters.at("error") == "invalid_request");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: OAuth 2.0 API, Scope (Full client-server API access, Device ID allocation)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#scope
//
// The scope requests full API access with `urn:matrix:client:api:*` and the device with exactly one
// `urn:matrix:client:device:<device ID>` token; RFC 6749 4.1.2.1: an unusable scope is `invalid_scope`.
SCENARIO("An authorisation request must ask for the API and exactly one device",
         "[conformance][client-server][oauth][oauth-authorize]")
{
    GIVEN("a registered web client")
    {
        auto started = hs::start_client_server(conformance_config(false));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const client_id = register_oauth_web_client(rt);
        auto const base = oauth_authorize_parameters(client_id);

        WHEN("the scope has no device token, or two")
        {
            auto const none =
                redirect_answer(get_authorize(rt, with_parameter(base, "scope", "urn:matrix:client:api:*")));
            auto const two = redirect_answer(
                get_authorize(rt, with_parameter(base, "scope",
                                                 "urn:matrix:client:api:* urn:matrix:client:device:AAAAAAAAAA "
                                                 "urn:matrix:client:device:BBBBBBBBBB")));

            THEN("both are invalid_scope")
            {
                // Spec: exactly one device scope token.
                REQUIRE(none.parameters.at("error") == "invalid_scope");
                REQUIRE(two.parameters.at("error") == "invalid_scope");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: OAuth 2.0 API, User registration
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#user-registration
//
// "Servers that support this parameter SHOULD show the account registration UI in the browser." A server that does
// not accept new accounts does not advertise `create` and shows its sign-in page.
SCENARIO("prompt=create shows the registration page only when the server accepts new accounts",
         "[conformance][client-server][oauth][oauth-authorize]")
{
    GIVEN("a server that accepts new accounts")
    {
        auto started = hs::start_client_server(conformance_config(true));
        REQUIRE(started.started);
        auto const client_id = register_oauth_web_client(started.runtime);

        WHEN("prompt=create is requested")
        {
            auto const page = get_authorize(started.runtime,
                                            with_parameter(oauth_authorize_parameters(client_id), "prompt", "create"));

            THEN("the registration page is shown")
            {
                // Spec SHOULD: show the account registration UI.
                REQUIRE(page.status == 200U);
                REQUIRE(contains(page.body, R"(autocomplete="new-password")"));
            }
        }
    }

    GIVEN("a server that does not accept new accounts")
    {
        auto started = hs::start_client_server(conformance_config(false));
        REQUIRE(started.started);
        auto const client_id = register_oauth_web_client(started.runtime);

        WHEN("prompt=create is requested")
        {
            auto const page = get_authorize(started.runtime,
                                            with_parameter(oauth_authorize_parameters(client_id), "prompt", "create"));

            THEN("the sign-in page is shown instead, with no registration form")
            {
                REQUIRE(page.status == 200U);
                REQUIRE(contains(page.body, R"(autocomplete="current-password")"));
                REQUIRE_FALSE(contains(page.body, R"(autocomplete="new-password")"));
            }
        }
    }
}
