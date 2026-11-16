// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The legacy login hand-off through the client-server dispatcher (plan P10, ADR-0802): with the OAuth 2.0 API and the
// legacy API both on, `GET /login` prefers `m.login.sso`, and the SSO redirect starts the built-in pages, which end
// in a confirmation and a single-use login token added to `redirectUrl`. No browser runs here: what a browser does
// with the cookie, the policy or the redirect is not tested.

#include "../support/JsonTestSupport.hpp"
#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;
using Fields = std::vector<std::pair<std::string, std::string>>;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};
constexpr auto sso_redirect_path = std::string_view{"/_matrix/client/v3/login/sso/redirect"};
constexpr auto app_return = std::string_view{"https://app.example.com/cb?a=1&loginToken=stale"};

[[nodiscard]] auto hand_off_config(bool oauth_enabled = true, std::vector<std::string> allowlist = {})
    -> merovingian::config::Config
{
    auto config = oauth_registration_config(oauth_enabled);
    config.server().server_name = "example.org";
    config.server().oauth.hand_off_redirect_allowlist = std::move(allowlist);
    enable_token_registration(config.security());
    return config;
}

[[nodiscard]] auto start(merovingian::config::Config config) -> hs::ClientServerStartResult
{
    auto started = hs::start_client_server(std::move(config));
    REQUIRE(started.started);
    // Every request comes from one address; the built-in limits are not what this file tests.
    started.runtime.rate_limit_engine.reset();
    REQUIRE(
        hs::register_local_user(started.runtime.homeserver, "alice", alice_password, std::string{registration_token})
            .ok);
    return started;
}

[[nodiscard]] auto contains(std::string_view text, std::string_view part) -> bool
{
    return text.find(part) != std::string_view::npos;
}

[[nodiscard]] auto audit_count(hs::HomeserverRuntime const& runtime, std::string_view event_type) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& event : runtime.database.audit_events)
    {
        if (event.event_type == event_type)
        {
            ++count;
        }
    }
    return count;
}

[[nodiscard]] auto send(hs::ClientServerRuntime& rt, std::string method, std::string target, std::string body = {})
    -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(rt, {std::move(method), std::move(target), {}, std::move(body)},
                                            /*can_wait=*/false)
        .response;
}

// A started hand-off: the redirect's answer, the pending identifier and the browser it is bound to.
struct HandOff final
{
    hs::LocalHttpResponse response;
    std::string pending;
    BrowserContext browser;
};

[[nodiscard]] auto open_hand_off(hs::ClientServerRuntime& rt, Fields const& parameters,
                                 std::string_view path = sso_redirect_path) -> HandOff
{
    auto browser = BrowserContext{};
    auto response = authorize_request(rt, "GET", std::string{path} + "?" + form_encode(parameters), {}, browser);
    auto pending = pending_of(response);
    browser.cookie = cookie_of(response);
    return {std::move(response), std::move(pending), std::move(browser)};
}

[[nodiscard]] auto post(hs::ClientServerRuntime& rt, HandOff const& hand_off, Fields fields) -> hs::LocalHttpResponse
{
    fields.emplace_back("pending", hand_off.pending);
    return post_authorize(rt, fields, hand_off.browser);
}

[[nodiscard]] auto sign_in(hs::ClientServerRuntime& rt, HandOff const& hand_off) -> hs::LocalHttpResponse
{
    return post(rt, hand_off,
                {
                    {"action",   "login"                    },
                    {"username", "alice"                    },
                    {"password", std::string{alice_password}},
    });
}

[[nodiscard]] auto token_login(hs::ClientServerRuntime& rt, std::string_view token) -> hs::LocalHttpResponse
{
    return send(rt, "POST", "/_matrix/client/v3/login",
                R"({"type":"m.login.token","token":")" + std::string{token} + R"("})");
}

} // namespace

SCENARIO("With the OAuth 2.0 API on, GET /login prefers m.login.sso and keeps the password login",
         "[integration][oauth][hand-off]")
{
    GIVEN("a server with the OAuth 2.0 API on and the legacy API on")
    {
        auto started = start(hand_off_config());
        auto& rt = started.runtime;

        WHEN("a client lists the login flows")
        {
            auto const response = send(rt, "GET", "/_matrix/client/v3/login");

            THEN("m.login.password, m.login.token and m.login.sso with oauth_aware_preferred are offered")
            {
                REQUIRE(response.status == 200U);
                CHECK(contains(response.body, R"({"type":"m.login.password"})"));
                CHECK(contains(response.body, R"({"type":"m.login.token"})"));
                CHECK(contains(response.body, R"("type":"m.login.sso")"));
                CHECK(contains(response.body, R"("oauth_aware_preferred":true)"));
            }
        }
    }

    GIVEN("a server with the OAuth 2.0 API off")
    {
        auto started = start(hand_off_config(false));
        auto& rt = started.runtime;

        WHEN("a client lists the login flows and opens the SSO redirect")
        {
            auto const flows = send(rt, "GET", "/_matrix/client/v3/login");
            auto const redirect = open_hand_off(rt, {
                                                        {"redirectUrl", std::string{app_return}}
            });

            THEN("neither changes: no SSO flow, and the redirect is not served without SSO configured")
            {
                REQUIRE(flows.status == 200U);
                CHECK_FALSE(contains(flows.body, "m.login.sso"));
                CHECK_FALSE(contains(flows.body, "oauth_aware_preferred"));
                CHECK(redirect.response.status != 200U);
                CHECK(redirect.pending.empty());
            }
        }
    }
}

SCENARIO("The SSO redirect signs alice in, confirms, and returns one single-use login token",
         "[integration][oauth][hand-off][security]")
{
    GIVEN("a server with the hand-off on")
    {
        auto started = start(hand_off_config());
        auto& rt = started.runtime;

        WHEN("an application opens the SSO redirect with a redirectUrl that already holds a loginToken")
        {
            auto const hand_off = open_hand_off(rt, {
                                                        {"redirectUrl", std::string{app_return}}
            });

            THEN("the login page is answered with the browser cookie and no redirect")
            {
                REQUIRE(hand_off.response.status == 200U);
                REQUIRE(hand_off.pending.size() == 64U);
                REQUIRE(hand_off.browser.cookie.size() == 64U);
                CHECK(response_header(hand_off.response, "Location").empty());
                CHECK(contains(hand_off.response.body, R"(autocomplete="current-password")"));
            }

            AND_WHEN("alice signs in")
            {
                auto const confirmation = sign_in(rt, hand_off);

                THEN("the confirmation page names her and the application, and may post to its origin alone")
                {
                    REQUIRE(confirmation.status == 200U);
                    CHECK(contains(confirmation.body, "@alice:example.org"));
                    CHECK(contains(confirmation.body, "app.example.com"));
                    CHECK(contains(confirmation.body, R"(value="approve")"));
                    CHECK(
                        contains(response_header(confirmation, "Content-Security-Policy"), "https://app.example.com"));
                    CHECK(response_header(confirmation, "Location").empty());
                    CHECK(audit_count(rt.homeserver, "auth.login_token.issued") == 0U);
                }

                AND_WHEN("she continues and the application redeems the token twice")
                {
                    auto const approved = post(rt, hand_off,
                                               {
                                                   {"action", "approve"}
                    });
                    auto const answer = redirect_answer(approved);
                    auto const token =
                        answer.parameters.contains("loginToken") ? answer.parameters.at("loginToken") : std::string{};
                    auto const first = token_login(rt, token);
                    auto const second = token_login(rt, token);
                    auto const replayed_page = post(rt, hand_off,
                                                    {
                                                        {"action", "approve"}
                    });

                    THEN("the browser is sent to redirectUrl with one new loginToken, which logs in once")
                    {
                        REQUIRE(approved.status == 303U);
                        CHECK(response_header(approved, "Cache-Control") == "no-store");
                        CHECK(response_header(approved, "Referrer-Policy") == "no-referrer");
                        CHECK(answer.base == "https://app.example.com/cb");
                        CHECK(answer.separator == '?');
                        CHECK(answer.parameters.at("a") == "1");
                        REQUIRE(token.size() == 64U);
                        CHECK(token != "stale");
                        CHECK_FALSE(contains(response_header(approved, "Location"), "stale"));
                        CHECK(audit_count(rt.homeserver, "auth.login_token.issued") == 1U);
                        REQUIRE(first.status == 200U);
                        auto const body = parse_object(first.body);
                        auto const* user_id = string_member(body, "user_id");
                        REQUIRE(user_id != nullptr);
                        CHECK(*user_id == "@alice:example.org");
                        CHECK(second.status == 403U);
                        // The pending authorisation was spent: a second approve is the expired page.
                        CHECK(replayed_page.status == 400U);
                        CHECK(response_header(replayed_page, "Location").empty());
                    }
                }

                AND_WHEN("she cancels")
                {
                    auto const cancelled = post(rt, hand_off,
                                                {
                                                    {"action", "deny"}
                    });

                    THEN("a page says so, nothing is sent to the application and no token is minted")
                    {
                        REQUIRE(cancelled.status == 200U);
                        CHECK(contains(cancelled.body, "Sign-in cancelled"));
                        CHECK(response_header(cancelled, "Location").empty());
                        CHECK(audit_count(rt.homeserver, "auth.login_token.issued") == 0U);
                    }
                }
            }

            AND_WHEN("the wrong password is sent")
            {
                auto const refused = post(rt, hand_off,
                                          {
                                              {"action",   "login"         },
                                              {"username", "alice"         },
                                              {"password", "wrong-password"},
                });

                THEN("the login page is answered again and nothing is redirected")
                {
                    CHECK(refused.status == 401U);
                    CHECK(response_header(refused, "Location").empty());
                    CHECK_FALSE(contains(refused.body, R"(value="approve")"));
                }
            }

            AND_WHEN("another browser posts the approval")
            {
                auto stranger = hand_off;
                stranger.browser.cookie = std::string(64U, 'a');
                auto const refused = post(rt, stranger,
                                          {
                                              {"action", "approve"}
                });

                THEN("the expired page is answered and no token is minted")
                {
                    CHECK(refused.status == 400U);
                    CHECK(response_header(refused, "Location").empty());
                    CHECK(audit_count(rt.homeserver, "auth.login_token.issued") == 0U);
                }
            }
        }
    }
}

SCENARIO("A redirectUrl the hand-off does not accept is refused with a page and no redirect",
         "[integration][oauth][hand-off][security]")
{
    GIVEN("a server with the hand-off on")
    {
        auto started = start(hand_off_config());
        auto& rt = started.runtime;
        auto const parameters = GENERATE(
            Fields{
        },
            Fields{{"redirectUrl", ""}}, Fields{{"redirectUrl", "javascript:alert(1)"}},
            Fields{{"redirectUrl", "http://app.example.com/cb"}}, Fields{{"redirectUrl", "myapp:/cb"}},
            Fields{{"redirectUrl", "https://app.example.com/cb#x"}},
            Fields{{"redirectUrl", "https://app.example.com/cb"}, {"redirectUrl", "https://evil.example.com/"}});

        WHEN("the SSO redirect is opened with it")
        {
            auto const refused = open_hand_off(rt, parameters);

            THEN("a 400 page is answered with no Location, no cookie and no pending sign-in")
            {
                CHECK(refused.response.status == 400U);
                CHECK(refused.response.page);
                CHECK(response_header(refused.response, "Location").empty());
                CHECK(response_header(refused.response, "Set-Cookie").empty());
                CHECK(refused.pending.empty());
            }
        }
    }
}

SCENARIO("The SSO redirect honours action, the identity provider form and the allowlist",
         "[integration][oauth][hand-off]")
{
    GIVEN("a server with the hand-off on and registration open")
    {
        auto started = start(hand_off_config());
        auto& rt = started.runtime;

        WHEN("the redirect is opened with action=register, an unknown action, and through /{idpId}")
        {
            auto const registering =
                open_hand_off(rt, {
                                      {"redirectUrl", "io.element.app:/cb"},
                                      {"action",      "register"          }
            });
            auto const unknown = open_hand_off(rt, {
                                                       {"redirectUrl", "io.element.app:/cb"},
                                                       {"action",      "dance"             }
            });
            auto const by_idp = open_hand_off(rt,
                                              {
                                                  {"redirectUrl", "http://127.0.0.1:8080/cb"}
            },
                                              std::string{sso_redirect_path} + "/oidc-anything");

            THEN("register shows the registration page, anything else the login page")
            {
                REQUIRE(registering.response.status == 200U);
                CHECK(contains(registering.response.body, R"(name="password_confirm")"));
                REQUIRE(unknown.response.status == 200U);
                CHECK(contains(unknown.response.body, R"(autocomplete="current-password")"));
                CHECK_FALSE(contains(unknown.response.body, R"(name="password_confirm")"));
                REQUIRE(by_idp.response.status == 200U);
                CHECK_FALSE(by_idp.pending.empty());
            }
        }
    }

    GIVEN("a server whose allowlist names one https origin")
    {
        auto started = start(hand_off_config(true, {"https://app.example.com"}));
        auto& rt = started.runtime;

        WHEN("a listed and an unlisted address are opened")
        {
            auto const listed = open_hand_off(rt, {
                                                      {"redirectUrl", "https://app.example.com/cb"}
            });
            auto const unlisted = open_hand_off(rt, {
                                                        {"redirectUrl", "https://other.example.com/cb"}
            });
            auto const loopback = open_hand_off(rt, {
                                                        {"redirectUrl", "http://localhost:8080/cb"}
            });

            THEN("only the listed origin starts a sign-in")
            {
                CHECK(listed.response.status == 200U);
                CHECK(unlisted.response.status == 400U);
                CHECK(loopback.response.status == 400U);
            }
        }
    }
}

SCENARIO("A password change ends a hand-off that alice signed in to but did not yet continue",
         "[integration][oauth][hand-off][credential-stamp][security]")
{
    GIVEN("a hand-off alice signed in to with her password")
    {
        auto started = start(hand_off_config());
        auto& rt = started.runtime;
        auto const hand_off = open_hand_off(rt, {
                                                    {"redirectUrl", std::string{app_return}}
        });
        REQUIRE(sign_in(rt, hand_off).status == 200U);

        WHEN("her password is changed on the account page and the hand-off is then continued")
        {
            REQUIRE(hs::change_password_on_account_page(rt.homeserver, "@alice:example.org", "NewAlicePass42!y").ok);
            auto const approved = post(rt, hand_off,
                                       {
                                           {"action", "approve"}
            });

            THEN("it is the expired page: no redirect and no login token")
            {
                CHECK(approved.status == 400U);
                CHECK(contains(approved.body, "Sign-in expired"));
                CHECK(response_header(approved, "Location").empty());
                CHECK(audit_count(rt.homeserver, "auth.login_token.issued") == 0U);
            }
        }

        WHEN("nothing changes before the hand-off is continued")
        {
            auto const approved = post(rt, hand_off,
                                       {
                                           {"action", "approve"}
            });

            THEN("the browser is sent back with a login token")
            {
                CHECK(approved.status == 303U);
                CHECK(audit_count(rt.homeserver, "auth.login_token.issued") == 1U);
            }
        }
    }
}
