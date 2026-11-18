// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Shared by the OAuth 2.0 token and revocation conformance and integration scenarios: an authorization code obtained
// through the real pages (sign in, approve), the token and revocation requests as a client sends them, and a reader
// for the token answer.

#include "JsonTestSupport.hpp"
#include "OAuthAuthorizationSupport.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/http/Header.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::tests
{

inline constexpr auto oauth_token_path = std::string_view{"/_merovingian/oauth2/token"};
inline constexpr auto oauth_revoke_path = std::string_view{"/_merovingian/oauth2/revoke"};
// RFC 7636 appendix B: the verifier of oauth_test_challenge.
inline constexpr auto oauth_test_verifier = std::string_view{"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"};
inline constexpr auto oauth_form_type = std::string_view{"application/x-www-form-urlencoded"};

using OAuthFields = std::vector<std::pair<std::string, std::string>>;

// The scope of the authorisation request for `device_id`: the client-server API and that one device.
[[nodiscard]] inline auto oauth_scope_for_device(std::string_view device_id) -> std::string
{
    return "urn:matrix:client:api:* urn:matrix:client:device:" + std::string{device_id};
}

// Signs `username` in through the authorisation pages and approves: the code the redirect carries, or empty when any
// step did not answer as a successful flow does. `parameters` is the authorisation request (by default
// oauth_authorize_parameters, whose device is oauth_test_device).
[[nodiscard]] inline auto obtain_oauth_code(homeserver::ClientServerRuntime& runtime, std::string_view client_id,
                                            std::string_view username, std::string_view password,
                                            std::optional<OAuthFields> parameters = std::nullopt) -> std::string
{
    auto browser = BrowserContext{};
    auto const page = get_authorize(runtime, parameters.value_or(oauth_authorize_parameters(client_id)), browser);
    auto const pending = pending_of(page);
    browser.cookie = cookie_of(page);
    if (page.status != 200U || pending.empty() || browser.cookie.empty())
    {
        return {};
    }
    auto const consent = post_authorize(runtime,
                                        {
                                            {"pending",  pending              },
                                            {"action",   "login"              },
                                            {"username", std::string{username}},
                                            {"password", std::string{password}},
    },
                                        browser);
    if (consent.status != 200U)
    {
        return {};
    }
    auto const approved = post_authorize(runtime,
                                         {
                                             {"pending", pending  },
                                             {"action",  "approve"},
    },
                                         browser);
    auto const answer = redirect_answer(approved);
    auto const code = answer.parameters.find("code");
    return approved.status == 303U && code != answer.parameters.end() ? code->second : std::string{};
}

// The metadata members (leading comma) of a client that may use both grants the token endpoint serves: the spec's
// client metadata MUST list authorization_code and refresh_token, and the refresh grant refuses a client without it.
inline constexpr auto oauth_both_grant_types =
    std::string_view{R"(,"grant_types":["authorization_code","refresh_token"])"};

// POST `body` to `path` with `content_type` (none when empty) and the extra `headers`, from the client's web origin
// (https://app.example.com), as a browser-based client sends it.
[[nodiscard]] inline auto post_oauth_body(homeserver::ClientServerRuntime& runtime, std::string_view path,
                                          std::string body, std::string_view content_type = oauth_form_type,
                                          std::vector<http::Header> headers = {}, std::string method = "POST")
    -> homeserver::LocalHttpResponse
{
    auto request = homeserver::LocalHttpRequest{std::move(method), std::string{path}, {}, std::move(body)};
    request.remote_addr = "198.51.100.30";
    request.headers = std::move(headers);
    request.headers.push_back({"Origin", "https://app.example.com"});
    if (!content_type.empty())
    {
        request.headers.push_back({"Content-Type", std::string{content_type}});
    }
    return homeserver::handle_client_server_request(runtime, request, /*can_wait=*/false).response;
}

[[nodiscard]] inline auto post_oauth_form(homeserver::ClientServerRuntime& runtime, std::string_view path,
                                          OAuthFields const& fields) -> homeserver::LocalHttpResponse
{
    return post_oauth_body(runtime, path, form_encode(fields));
}

// The fields of an authorization code grant for `code`, as the client that asked for it sends them.
[[nodiscard]] inline auto code_grant_fields(std::string_view client_id, std::string_view code) -> OAuthFields
{
    return {
        {"grant_type",    "authorization_code"              },
        {"code",          std::string{code}                 },
        {"redirect_uri",  std::string{oauth_client_redirect}},
        {"client_id",     std::string{client_id}            },
        {"code_verifier", std::string{oauth_test_verifier}  },
    };
}

[[nodiscard]] inline auto refresh_grant_fields(std::string_view client_id, std::string_view refresh_token)
    -> OAuthFields
{
    return {
        {"grant_type",    "refresh_token"           },
        {"refresh_token", std::string{refresh_token}},
        {"client_id",     std::string{client_id}    },
    };
}

// What a 200 token answer carries; `ok` is false when a member is missing or of the wrong type.
struct OAuthTokenAnswer final
{
    bool ok{false};
    std::string access_token{};
    std::string refresh_token{};
    std::string token_type{};
    std::string scope{};
    std::int64_t expires_in{0};
};

[[nodiscard]] inline auto read_token_answer(homeserver::LocalHttpResponse const& response) -> OAuthTokenAnswer
{
    auto answer = OAuthTokenAnswer{};
    if (response.status != 200U)
    {
        return answer;
    }
    auto const body = parse_object(response.body);
    auto const* access = string_member(body, "access_token");
    auto const* refresh = string_member(body, "refresh_token");
    auto const* type = string_member(body, "token_type");
    auto const* scope = string_member(body, "scope");
    auto const* expires_in = int_member(body, "expires_in");
    if (access == nullptr || refresh == nullptr || type == nullptr || scope == nullptr || expires_in == nullptr)
    {
        return answer;
    }
    answer = {true, *access, *refresh, *type, *scope, *expires_in};
    return answer;
}

// A whole sign-in: a code for `username` and its redemption at the token endpoint.
[[nodiscard]] inline auto oauth_sign_in(homeserver::ClientServerRuntime& runtime, std::string_view client_id,
                                        std::string_view username, std::string_view password,
                                        std::optional<OAuthFields> parameters = std::nullopt) -> OAuthTokenAnswer
{
    auto const code = obtain_oauth_code(runtime, client_id, username, password, std::move(parameters));
    if (code.empty())
    {
        return {};
    }
    return read_token_answer(post_oauth_form(runtime, oauth_token_path, code_grant_fields(client_id, code)));
}

} // namespace merovingian::tests
