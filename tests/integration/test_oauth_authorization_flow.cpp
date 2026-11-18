// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `GET` and `POST /_merovingian/oauth2/authorize` through the client-server dispatcher: the sign-in, account creation
// and consent pages, the redirect to the client with an authorization code or an error, the browser binding, the form
// post origin check, the shared login throttle, the per-address cap, and what a flow leaves behind (ADR-0787 to
// ADR-0789). No browser runs here: what a browser does with the cookie or the policy is not tested.

#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/auth/Argon2idAdmission.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/AuthorizationCodeRedemption.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/OAuthClock.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace db = merovingian::database;
namespace hs = merovingian::homeserver;
using Fields = std::vector<std::pair<std::string, std::string>>;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};

// OAuth on, at https://matrix.example.org, with token registration when `registration` is true.
[[nodiscard]] auto authorization_config(bool registration = true) -> merovingian::config::Config
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

[[nodiscard]] auto has_header(hs::LocalHttpResponse const& response, std::string_view prefix) -> bool
{
    for (auto const& [name, value] : response.headers)
    {
        if (name.starts_with(prefix))
        {
            return true;
        }
    }
    return false;
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

// A started page: the GET's answer, the pending identifier and the browser it is bound to.
struct StartedPage final
{
    hs::LocalHttpResponse response;
    std::string pending;
    BrowserContext browser;
};

[[nodiscard]] auto start_page(hs::ClientServerRuntime& rt, Fields const& parameters, BrowserContext browser = {})
    -> StartedPage
{
    auto response = get_authorize(rt, parameters, browser);
    auto pending = pending_of(response);
    auto const cookie = cookie_of(response);
    if (!cookie.empty())
    {
        browser.cookie = cookie;
    }
    return {std::move(response), std::move(pending), std::move(browser)};
}

[[nodiscard]] auto login(hs::ClientServerRuntime& rt, StartedPage const& page, std::string_view username,
                         std::string_view password) -> hs::LocalHttpResponse
{
    return post_authorize(rt,
                          {
                              {"pending",  page.pending         },
                              {"action",   "login"              },
                              {"username", std::string{username}},
                              {"password", std::string{password}},
    },
                          page.browser);
}

[[nodiscard]] auto act(hs::ClientServerRuntime& rt, StartedPage const& page, std::string_view action)
    -> hs::LocalHttpResponse
{
    return post_authorize(rt,
                          {
                              {"pending", page.pending       },
                              {"action",  std::string{action}},
    },
                          page.browser);
}

// Starts a runtime with alice and a registered web client.
struct Fixture final
{
    hs::ClientServerStartResult started;
    std::string alice;
    std::string client_id;
};

[[nodiscard]] auto make_fixture(bool registration = true, std::string_view client_extra = {}) -> Fixture
{
    auto started = hs::start_client_server(authorization_config(registration));
    REQUIRE(started.started);
    auto alice = std::string{};
    if (registration)
    {
        auto const registered = hs::register_local_user(started.runtime.homeserver, "alice", alice_password,
                                                        std::string{registration_token});
        REQUIRE(registered.ok);
        alice = registered.value;
    }
    auto client_id = register_oauth_web_client(started.runtime, client_extra);
    REQUIRE_FALSE(client_id.empty());
    return {std::move(started), std::move(alice), std::move(client_id)};
}

} // namespace

SCENARIO("A browser signs in, consents and is sent back to the client with a code and the state",
         "[integration][oauth][oauth-authorize]")
{
    GIVEN("alice and a registered web client")
    {
        // The fixture registers alice and the one web client every request below names, so a failure here is the
        // page's, not the setup's. Each WHEN starts its own pending authorisation from this runtime.
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;

        WHEN("the authorisation request is opened")
        {
            auto const page = start_page(rt, oauth_authorize_parameters(fixture.client_id));

            THEN("the login page is answered with a pending identifier and the browser cookie")
            {
                REQUIRE(page.response.status == 200U);
                // Both are 32 random bytes in hex (`make_oauth_secret`): a shorter value would be guessable, and the
                // pending entry is found only with the two together (ADR-0788).
                REQUIRE(page.pending.size() == 64U);
                REQUIRE(page.browser.cookie.size() == 64U);
                // The `__Host-` cookie name is honoured by a browser only with Secure, Path=/ and no Domain. Lax, not
                // Strict, so the cookie still travels on the top-level navigation from the client's site; Max-Age
                // matches the pending authorisation's ten minutes.
                auto const set_cookie = response_header(page.response, "Set-Cookie");
                CHECK(contains(set_cookie, "; Secure"));
                CHECK(contains(set_cookie, "; HttpOnly"));
                CHECK(contains(set_cookie, "SameSite=Lax"));
                CHECK(contains(set_cookie, "Max-Age=600"));
                CHECK(contains(set_cookie, "Path=/"));
                CHECK_FALSE(contains(set_cookie, "Domain="));
                CHECK(response_header(page.response, "Cache-Control") == "no-store");
                CHECK(contains(page.response.body, R"(autocomplete="current-password")"));
                // A page response is marked as one, so the dispatch boundary adds no CORS header (ADR-0785): another
                // origin must not be able to read the page and its pending identifier.
                CHECK_FALSE(has_header(page.response, "Access-Control-"));
                // The login page posts only to this server: no redirect origin in its form-action.
                CHECK_FALSE(contains(response_header(page.response, "Content-Security-Policy"), "app.example.com"));
            }

            AND_WHEN("alice signs in")
            {
                auto const consent = login(rt, page, "alice", alice_password);

                THEN("the consent page names her and the device, and its policy may post to the redirect origin")
                {
                    // The consent form's answer is a 303 to the client, so its form-action must name the matched
                    // redirect origin; only this page widens the policy, and only to that one origin.
                    REQUIRE(consent.status == 200U);
                    CHECK(contains(consent.body, "@alice:example.org"));
                    CHECK(contains(consent.body, std::string{oauth_test_device}));
                    CHECK(contains(consent.body, "app.example.com"));
                    CHECK(contains(response_header(consent, "Content-Security-Policy"),
                                   "form-action 'self' https://app.example.com"));
                    CHECK_FALSE(has_header(consent, "Access-Control-"));
                }

                AND_WHEN("she approves")
                {
                    auto const approved = act(rt, page, "approve");
                    auto const answer = redirect_answer(approved);

                    THEN("the browser is sent to the redirect URI with a code and the state in the query")
                    {
                        REQUIRE(approved.status == 303U);
                        CHECK(response_header(approved, "Cache-Control") == "no-store");
                        CHECK(answer.base == oauth_client_redirect);
                        CHECK(answer.separator == '?');
                        REQUIRE(answer.parameters.contains("code"));
                        // The state holds a space and an `&`: it comes back intact only if the redirect percent-encodes
                        // it, so a value cannot split into, or forge, another parameter of the answer.
                        CHECK(answer.parameters.at("state") == "st-123 & more");
                        CHECK_FALSE(answer.parameters.contains("error"));
                        CHECK(audit_count(rt.homeserver, "oauth.authorization.granted") == 1U);
                    }

                    THEN("the code is bound to the client, the redirect URI, the challenge, alice and the device")
                    {
                        // Redeemed straight from the store, not through the token endpoint, so this pins what the
                        // approval recorded; the token endpoint later checks each field against its own request.
                        auto const redeemed =
                            rt.homeserver.oauth_codes.redeem(answer.parameters.at("code"), hs::oauth_wall_clock_ms());
                        REQUIRE(redeemed.outcome == hs::AuthorizationCodeRedemption::Outcome::fresh);
                        CHECK(redeemed.grant.client_id == fixture.client_id);
                        CHECK(redeemed.grant.redirect_uri == oauth_client_redirect);
                        CHECK(redeemed.grant.code_challenge == oauth_test_challenge);
                        CHECK(redeemed.grant.user_id == fixture.alice);
                        CHECK(redeemed.grant.device_id == oauth_test_device);
                        CHECK(redeemed.grant.scope == oauth_test_scope);
                    }

                    THEN("no device, token or OAuth session exists yet")
                    {
                        // An approval leaves one authorization code and nothing else: the token endpoint creates the
                        // device and the session, so an unredeemed code must not already sign anyone in.
                        auto const& store = rt.homeserver.database.persistent_store;
                        CHECK_FALSE(db::has_user_device(store, fixture.alice, oauth_test_device));
                        CHECK(db::oauth_sessions_of_user(store, fixture.alice).empty());
                        for (auto const& session : rt.homeserver.database.sessions)
                        {
                            CHECK(session.user_id != fixture.alice);
                        }
                    }

                    THEN("approving again is the expired page and sends nothing")
                    {
                        // The approval consumed the pending entry; a second post with the same pending identifier and
                        // cookie must not mint a second code for the same consent.
                        auto const replay = act(rt, page, "approve");
                        CHECK(replay.status == 400U);
                        CHECK(response_header(replay, "Location").empty());
                        CHECK(contains(replay.body, "Sign-in expired"));
                    }
                }

                AND_WHEN("she denies instead")
                {
                    auto const denied = act(rt, page, "deny");
                    auto const answer = redirect_answer(denied);

                    THEN("the client is told access_denied with the state, and the denial is audited")
                    {
                        REQUIRE(denied.status == 303U);
                        CHECK(answer.parameters.at("error") == "access_denied");
                        CHECK(answer.parameters.at("state") == "st-123 & more");
                        CHECK_FALSE(answer.parameters.contains("code"));
                        CHECK(audit_count(rt.homeserver, "oauth.authorization.denied") == 1U);
                    }
                }
            }

            AND_WHEN("approve is posted before anyone signs in")
            {
                // Skipping the login form must not reach the consent step: a code needs a user the password check
                // recorded on the pending entry.
                auto const early = act(rt, page, "approve");

                THEN("it is the expired page and no code is issued")
                {
                    CHECK(early.status == 400U);
                    CHECK(response_header(early, "Location").empty());
                    CHECK(rt.homeserver.oauth_codes.size() == 0U);
                }
            }

            AND_WHEN("deny is posted before anyone signs in")
            {
                auto const denied = act(rt, page, "deny");

                THEN("the client is told access_denied, and nothing is audited for nobody")
                {
                    // A denial is a durable audit row only after a sign-in: before one there is no user to record it
                    // against, and the client is still told, so it does not wait for an answer.
                    REQUIRE(denied.status == 303U);
                    CHECK(redirect_answer(denied).parameters.at("error") == "access_denied");
                    CHECK(audit_count(rt.homeserver, "oauth.authorization.denied") == 0U);
                }
            }
        }

        WHEN("the request asks for the fragment response mode and alice approves")
        {
            auto const page = start_page(
                rt, with_parameter(oauth_authorize_parameters(fixture.client_id), "response_mode", "fragment"));
            REQUIRE(login(rt, page, "alice", alice_password).status == 200U);
            auto const answer = redirect_answer(act(rt, page, "approve"));

            THEN("the code and the state are in the fragment")
            {
                CHECK(answer.separator == '#');
                CHECK(answer.parameters.contains("code"));
                CHECK(answer.parameters.at("state") == "st-123 & more");
            }
        }

        WHEN("the request carries a login_hint naming alice")
        {
            auto const page = start_page(rt, with_parameter(oauth_authorize_parameters(fixture.client_id), "login_hint",
                                                            "mxid:@alice:example.org"));
            auto const other = start_page(rt, with_parameter(oauth_authorize_parameters(fixture.client_id),
                                                             "login_hint", "mxid:@alice:evil.example"));

            THEN("her username is prefilled, and a hint for another server is ignored")
            {
                // Same localpart, other server: `login_hint_username` takes the localpart only from a user ID of this
                // server, so the second page must not prefill `alice` for an account that is not hers.
                CHECK(contains(page.response.body, R"(value="alice")"));
                CHECK_FALSE(contains(other.response.body, R"(value="alice")"));
            }
        }

        WHEN("a second request comes from the same browser")
        {
            auto const first = start_page(rt, oauth_authorize_parameters(fixture.client_id));
            auto const second = start_page(rt, oauth_authorize_parameters(fixture.client_id), first.browser);

            THEN("the browser keeps its cookie value and gets another pending identifier")
            {
                // A well-formed cookie the request carries is reused, so two tabs of one browser do not overwrite each
                // other's binding; each request still gets its own pending entry.
                CHECK(cookie_of(second.response) == first.browser.cookie);
                CHECK(second.pending != first.pending);
            }
        }
    }
}

SCENARIO("A wrong password is one fixed answer and shares the login throttle with POST /login",
         "[integration][oauth][oauth-authorize]")
{
    GIVEN("alice, a client and a started sign-in")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const page = start_page(rt, oauth_authorize_parameters(fixture.client_id));

        WHEN("a wrong password and an unknown user are tried")
        {
            auto const wrong = login(rt, page, "alice", "WrongPass99!x");
            auto const unknown = login(rt, page, "nobody", "WrongPass99!x");

            THEN("both are a 401 login page with the same message, the username kept, the password not")
            {
                REQUIRE(wrong.status == 401U);
                REQUIRE(unknown.status == 401U);
                CHECK(contains(wrong.body, "do not match an account"));
                CHECK(contains(wrong.body, R"(value="alice")"));
                CHECK_FALSE(contains(wrong.body, "WrongPass99!x"));
            }
        }

        WHEN("wrong passwords are tried until the page throttles")
        {
            auto last = hs::LocalHttpResponse{};
            for (auto attempt = 0; attempt < 6; ++attempt)
            {
                last = login(rt, page, "alice", "WrongPass99!x");
            }
            auto legacy_request = hs::LocalHttpRequest{
                "POST",
                "/_matrix/client/v3/login",
                {},
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"AlicePass99!x"})"};
            legacy_request.remote_addr = page.browser.remote_addr;
            legacy_request.headers.push_back({"Content-Type", "application/json"});
            auto const legacy = hs::handle_client_server_request(rt, legacy_request, false).response;

            THEN("the page answers 429 with Retry-After, and POST /login from the same address is throttled too")
            {
                REQUIRE(last.status == 429U);
                CHECK_FALSE(response_header(last, "Retry-After").empty());
                CHECK(contains(last.body, "Try again in"));
                CHECK(legacy.status == 429U);
            }
        }

        WHEN("no Argon2id capacity remains")
        {
            rt.homeserver.argon2id_admission = std::make_unique<merovingian::auth::Argon2idAdmission>(0U);
            auto const busy = login(rt, page, "alice", alice_password);

            THEN("the page answers 503 busy with Retry-After")
            {
                CHECK(busy.status == 503U);
                CHECK_FALSE(response_header(busy, "Retry-After").empty());
                CHECK(contains(busy.body, "busy"));
            }
        }
    }
}

SCENARIO("An account is created from the authorisation pages when the server accepts new accounts",
         "[integration][oauth][oauth-authorize]")
{
    GIVEN("a server with token registration and a client")
    {
        // `prompt=create` opens the registration form instead of the login form. The REQUIREs prove that form is what
        // was served, so every WHEN below posts to a registration the page actually offered.
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const page =
            start_page(rt, with_parameter(oauth_authorize_parameters(fixture.client_id), "prompt", "create"));
        REQUIRE(page.response.status == 200U);
        REQUIRE(contains(page.response.body, R"(autocomplete="new-password")"));
        REQUIRE(contains(page.response.body, R"(name="registration_token")"));

        // Every post is for "carol" with the same password; only the token and the confirmation vary, so each WHEN
        // isolates one reason for refusal. The pending entry and cookie are the page's, as a browser would send them.
        auto const register_with = [&](std::string_view token, std::string_view confirmation) {
            return post_authorize(rt,
                                  {
                                      {"pending",            page.pending             },
                                      {"action",             "register"               },
                                      {"username",           "carol"                  },
                                      {"password",           "CarolPass99!x"          },
                                      {"password_confirm",   std::string{confirmation}},
                                      {"registration_token", std::string{token}       },
            },
                                  page.browser);
        };

        WHEN("carol registers with the token")
        {
            auto const consent = register_with(registration_token, "CarolPass99!x");

            THEN("the consent page is shown for her new account")
            {
                REQUIRE(consent.status == 200U);
                CHECK(contains(consent.body, "@carol:example.org"));
            }
        }

        WHEN("carol registers with a wrong token")
        {
            auto const refused = register_with("wrong-token", "CarolPass99!x");

            THEN("the form is shown again with a fixed message, her username and no password")
            {
                // Only the username is refilled. A secret the user typed is never written back into page markup, so
                // the refusal page's source cannot leak it.
                CHECK(refused.status == 403U);
                CHECK(contains(refused.body, "registration token is not valid"));
                CHECK(contains(refused.body, R"(value="carol")"));
                CHECK_FALSE(contains(refused.body, "CarolPass99!x"));
            }
        }

        WHEN("carol registers with no token")
        {
            auto const refused = register_with("", "CarolPass99!x");

            THEN("the form is shown again")
            {
                // A missing token is a malformed form (400), not a wrong token (403): this server requires one.
                CHECK(refused.status == 400U);
                CHECK(contains(refused.body, "Fill in every field"));
            }
        }

        WHEN("the two passwords differ")
        {
            auto const refused = register_with(registration_token, "OtherPass99!x");

            THEN("the form is shown again and no account exists")
            {
                CHECK(refused.status == 400U);
                CHECK(contains(refused.body, "do not match"));
                // carol's name is still free: the refused form created nothing.
                CHECK(hs::register_local_user(rt.homeserver, "carol", "CarolPass99!x", std::string{registration_token})
                          .ok);
            }
        }
    }

    GIVEN("a server that does not accept new accounts")
    {
        // Without token registration the fixture registers no alice; nothing here needs an existing account.
        auto fixture = make_fixture(false);
        auto& rt = fixture.started.runtime;

        WHEN("prompt=create is asked for and a registration is posted anyway")
        {
            // The post is sent although the page offered no form: hiding the form is not the control, refusing the
            // post is. It carries no registration token because none could be valid here.
            auto const page =
                start_page(rt, with_parameter(oauth_authorize_parameters(fixture.client_id), "prompt", "create"));
            auto const posted = post_authorize(rt,
                                               {
                                                   {"pending",          page.pending   },
                                                   {"action",           "register"     },
                                                   {"username",         "carol"        },
                                                   {"password",         "CarolPass99!x"},
                                                   {"password_confirm", "CarolPass99!x"},
            },
                                               page.browser);

            THEN("the login page is shown with a notice, and the post is refused the same way")
            {
                REQUIRE(page.response.status == 200U);
                CHECK(contains(page.response.body, "does not accept new accounts"));
                CHECK_FALSE(contains(page.response.body, R"(autocomplete="new-password")"));
                CHECK(posted.status == 403U);
                CHECK(contains(posted.body, "does not accept new accounts"));
            }
        }
    }
}

SCENARIO("An authorisation request whose client or redirect URI cannot be validated is a page, never a redirect",
         "[integration][oauth][oauth-authorize]")
{
    GIVEN("a registered client")
    {
        auto fixture = make_fixture(false);
        auto& rt = fixture.started.runtime;
        auto const base = oauth_authorize_parameters(fixture.client_id);
        auto const raw = [&](std::string query) {
            return authorize_request(rt, "GET", std::string{oauth_authorize_path} + "?" + query, {}, BrowserContext{});
        };

        WHEN("each step-1 fault is requested")
        {
            auto const answers = std::vector<hs::LocalHttpResponse>{
                raw("client_id=%zz"),
                raw(form_encode(base) + "&client_id=again"),
                get_authorize(rt, with_parameter(base, "client_id", std::nullopt)),
                get_authorize(rt, with_parameter(base, "client_id", "unknown-client")),
                get_authorize(rt, with_parameter(base, "redirect_uri", std::nullopt)),
                get_authorize(rt, with_parameter(base, "redirect_uri", "https://app.example.com/other")),
                get_authorize(rt, with_parameter(base, "redirect_uri", "https://evil.example/cb")),
            };

            THEN("every one is a 400 page with no Location and no cookie")
            {
                for (auto const& answer : answers)
                {
                    CHECK(answer.status == 400U);
                    CHECK(response_header(answer, "Location").empty());
                    CHECK(response_header(answer, "Set-Cookie").empty());
                }
                CHECK(rt.homeserver.oauth_pending_authorisations.size() == 0U);
            }
        }
    }
}

SCENARIO("An authorisation request with a bare name or an empty field reads them as not sent",
         "[integration][oauth][oauth-authorize][form-query]")
{
    GIVEN("a registered client")
    {
        auto fixture = make_fixture(false);
        auto const query = form_encode(oauth_authorize_parameters(fixture.client_id));
        auto const raw = [&](std::string const& target_query) {
            return authorize_request(fixture.started.runtime, "GET",
                                     std::string{oauth_authorize_path} + "?" + target_query, {}, BrowserContext{});
        };

        WHEN("the well-formed request is sent with a bare name, a doubled & and a trailing &")
        {
            auto const answer = raw("prompt&" + query + "&&ui_locales&");

            THEN("it is the sign-in page, as for the request without them")
            {
                CHECK(answer.status == 200U);
                CHECK(answer.page);
                CHECK_FALSE(response_header(answer, "Set-Cookie").empty());
            }
        }
        WHEN("a bare name holds a malformed escape")
        {
            auto const answer = raw("bad%zz&" + query);

            THEN("it is still refused as a 400 page")
            {
                CHECK(answer.status == 400U);
                CHECK(response_header(answer, "Location").empty());
            }
        }
    }
}

SCENARIO("A refused authorisation request is redirected to the client with the error and the state",
         "[integration][oauth][oauth-authorize]")
{
    GIVEN("a registered client")
    {
        auto fixture = make_fixture(false);
        auto& rt = fixture.started.runtime;
        auto const base = oauth_authorize_parameters(fixture.client_id);
        struct Case final
        {
            std::string_view name;
            std::optional<std::string_view> value;
            std::string_view error;
        };
        auto const cases = std::vector<Case>{
            {"response_type",         "token",                   "unsupported_response_type"},
            {"response_type",         std::nullopt,              "invalid_request"          },
            {"response_mode",         "form_post",               "invalid_request"          },
            {"code_challenge_method", "plain",                   "invalid_request"          },
            {"code_challenge_method", std::nullopt,              "invalid_request"          },
            {"code_challenge",        "short",                   "invalid_request"          },
            {"code_challenge",        std::nullopt,              "invalid_request"          },
            {"scope",                 "urn:matrix:client:api:*", "invalid_scope"            },
            {"scope",                 std::nullopt,              "invalid_scope"            },
            {"prompt",                "none",                    "login_required"           },
            {"prompt",                "consent login",           "invalid_request"          },
        };

        WHEN("each fault is requested")
        {
            THEN("each is a 302 to the redirect URI with its error, a description and the state, in the query")
            {
                for (auto const& item : cases)
                {
                    INFO(item.name << " " << item.value.value_or("(absent)"));
                    auto const response = get_authorize(rt, with_parameter(base, item.name, item.value));
                    auto answer = redirect_answer(response);
                    CHECK(response.status == 302U);
                    CHECK(answer.base == oauth_client_redirect);
                    CHECK(answer.separator == '?');
                    CHECK(answer.parameters["error"] == item.error);
                    CHECK_FALSE(answer.parameters["error_description"].empty());
                    CHECK(answer.parameters["state"] == "st-123 & more");
                    CHECK(response_header(response, "Cache-Control") == "no-store");
                    CHECK(response_header(response, "Set-Cookie").empty());
                }
                CHECK(rt.homeserver.oauth_pending_authorisations.size() == 0U);
            }
        }

        WHEN("the state is over 2048 bytes")
        {
            auto const response = get_authorize(rt, with_parameter(base, "state", std::string(2049U, 's')));
            auto answer = redirect_answer(response);

            THEN("it is invalid_request without the state")
            {
                CHECK(response.status == 302U);
                CHECK(answer.parameters["error"] == "invalid_request");
                CHECK_FALSE(answer.parameters.contains("state"));
            }
        }

        WHEN("a refusal asks for the fragment response mode")
        {
            auto const response =
                get_authorize(rt, with_parameter(with_parameter(base, "response_mode", "fragment"), "prompt", "none"));

            THEN("the error is in the fragment")
            {
                CHECK(redirect_answer(response).separator == '#');
            }
        }
    }

    GIVEN("a client registered without the authorization_code grant")
    {
        auto fixture = make_fixture(false, R"(,"grant_types":["refresh_token"])");
        auto& rt = fixture.started.runtime;

        WHEN("it asks for a code")
        {
            auto const response = get_authorize(rt, oauth_authorize_parameters(fixture.client_id));

            THEN("it is unauthorized_client")
            {
                CHECK(response.status == 302U);
                CHECK(redirect_answer(response).parameters["error"] == "unauthorized_client");
            }
        }
    }
}

SCENARIO("A form post is refused unless it comes from this server's page in the same browser",
         "[integration][oauth][oauth-authorize]")
{
    GIVEN("alice, a client and a started sign-in")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const page = start_page(rt, oauth_authorize_parameters(fixture.client_id));
        auto const login_fields = Fields{
            {"pending",  page.pending               },
            {"action",   "login"                    },
            {"username", "alice"                    },
            {"password", std::string{alice_password}},
        };
        auto const post_with = [&](BrowserContext const& browser) {
            return post_authorize(rt, login_fields, browser);
        };

        WHEN("the post's origin is wrong, null, missing, or cross-site")
        {
            auto wrong = page.browser;
            wrong.origin = "https://evil.example";
            auto null_origin = page.browser;
            null_origin.origin = "null";
            auto missing = page.browser;
            missing.origin.reset();
            auto cross_site = page.browser;
            cross_site.sec_fetch_site = "cross-site";

            THEN("each is a 403 page")
            {
                CHECK(post_with(wrong).status == 403U);
                CHECK(post_with(null_origin).status == 403U);
                CHECK(post_with(missing).status == 403U);
                CHECK(post_with(cross_site).status == 403U);
            }
        }

        WHEN("the post is not a form")
        {
            auto json = page.browser;
            json.content_type = "application/json";

            THEN("it is a 400 page")
            {
                CHECK(post_with(json).status == 400U);
            }
        }

        WHEN("the post has no cookie, another browser's cookie, or an unknown pending identifier")
        {
            auto no_cookie = page.browser;
            no_cookie.cookie.clear();
            auto other = start_page(rt, oauth_authorize_parameters(fixture.client_id),
                                    BrowserContext{.remote_addr = "198.51.100.21"});
            auto other_cookie = page.browser;
            other_cookie.cookie = other.browser.cookie;
            auto unknown_pending = login_fields;
            unknown_pending[0].second = std::string(64U, 'a');

            THEN("each is the expired page with no redirect, and the sign-in still works afterwards")
            {
                auto const answers = std::vector<hs::LocalHttpResponse>{
                    post_with(no_cookie),
                    post_with(other_cookie),
                    post_authorize(rt, unknown_pending, page.browser),
                };
                for (auto const& answer : answers)
                {
                    CHECK(answer.status == 400U);
                    CHECK(contains(answer.body, "Sign-in expired"));
                    CHECK(response_header(answer, "Location").empty());
                }
                CHECK(post_with(page.browser).status == 200U);
            }
        }

        WHEN("an unknown action is posted")
        {
            auto const answer = act(rt, page, "steal");

            THEN("it is a 400 page")
            {
                CHECK(answer.status == 400U);
                CHECK(response_header(answer, "Location").empty());
            }
        }
    }
}

SCENARIO("A hostile client name is escaped on the consent page", "[integration][oauth][oauth-authorize]")
{
    GIVEN("a client whose name holds markup")
    {
        auto fixture = make_fixture(true, R"(,"client_name":"<script>alert(1)</script>")");
        auto& rt = fixture.started.runtime;
        auto const page = start_page(rt, oauth_authorize_parameters(fixture.client_id));

        WHEN("alice signs in")
        {
            auto const consent = login(rt, page, "alice", alice_password);

            THEN("the name is shown as text, never as markup")
            {
                REQUIRE(consent.status == 200U);
                CHECK_FALSE(contains(consent.body, "<script>"));
                CHECK(contains(consent.body, "&lt;script&gt;"));
            }
        }
    }
}

SCENARIO("One client address holds at most 16 sign-ins in progress", "[integration][oauth][oauth-authorize]")
{
    GIVEN("a registered client")
    {
        auto fixture = make_fixture(false);
        auto& rt = fixture.started.runtime;
        auto const parameters = oauth_authorize_parameters(fixture.client_id);

        WHEN("17 sign-ins are started from one address and one from another")
        {
            auto statuses = std::vector<std::uint16_t>{};
            for (auto index = 0; index < 17; ++index)
            {
                statuses.push_back(get_authorize(rt, parameters).status);
            }
            auto const other = get_authorize(rt, parameters, BrowserContext{.remote_addr = "203.0.113.9"});

            THEN("the first 16 are served, the 17th is a 503 page, and the other address is served")
            {
                for (auto index = std::size_t{0U}; index < 16U; ++index)
                {
                    CHECK(statuses[index] == 200U);
                }
                CHECK(statuses[16] == 503U);
                CHECK(other.status == 200U);
            }
        }
    }
}

SCENARIO("The authorisation endpoint serves GET and POST only, and only with the OAuth 2.0 API on",
         "[integration][oauth][oauth-authorize]")
{
    GIVEN("a server with the OAuth 2.0 API on")
    {
        auto started = hs::start_client_server(authorization_config(false));
        REQUIRE(started.started);

        WHEN("the endpoint is asked with PUT")
        {
            auto const response =
                authorize_request(started.runtime, "PUT", std::string{oauth_authorize_path}, "", BrowserContext{});

            THEN("it is 405")
            {
                CHECK(response.status == 405U);
            }
        }
    }

    GIVEN("a server with the OAuth 2.0 API off")
    {
        auto config = authorization_config(false);
        config.server().oauth.enabled = false;
        auto started = hs::start_client_server(config);
        REQUIRE(started.started);

        WHEN("the endpoint is asked with GET and POST")
        {
            auto const get = get_authorize(started.runtime, oauth_authorize_parameters("any"));
            auto const post = post_authorize(started.runtime,
                                             {
                                                 {"pending", "x"}
            },
                                             BrowserContext{});

            THEN("both are 404 M_UNRECOGNIZED")
            {
                CHECK(get.status == 404U);
                CHECK(contains(get.body, "M_UNRECOGNIZED"));
                CHECK(post.status == 404U);
            }
        }
    }
}
