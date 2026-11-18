// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Shared by the OAuth 2.0 authorisation conformance and integration scenarios: a registered web client, the
// authorisation request as a browser sends it, the form posts of its pages, and readers for what the pages and
// redirects carry (the pending identifier, the browser cookie, the redirect's parameters).

#include "JsonTestSupport.hpp"
#include "OAuthRegistrationSupport.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/oauth/AuthorizationRedirect.hpp"

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::tests
{

inline constexpr auto oauth_authorize_path = std::string_view{"/_merovingian/oauth2/authorize"};
inline constexpr auto oauth_server_origin = std::string_view{"https://matrix.example.org"};
inline constexpr auto oauth_client_redirect = std::string_view{"https://app.example.com/cb"};
// RFC 7636 appendix B: a valid S256 challenge.
inline constexpr auto oauth_test_challenge = std::string_view{"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"};
inline constexpr auto oauth_test_device = std::string_view{"OAUTHDEV01"};
inline constexpr auto oauth_test_scope =
    std::string_view{"urn:matrix:client:api:* urn:matrix:client:device:OAUTHDEV01"};
inline constexpr auto oauth_browser_cookie = std::string_view{"__Host-mv-oauth"};

// Registers a web client of https://app.example.com/ whose one redirect URI is oauth_client_redirect, with
// `extra_members` (JSON members with a leading comma) added to the metadata. Returns the client ID, or empty.
[[nodiscard]] inline auto register_oauth_web_client(homeserver::ClientServerRuntime& runtime,
                                                    std::string_view extra_members = {}) -> std::string
{
    auto const body = std::string{R"({"client_uri":"https://app.example.com/","redirect_uris":[")"} +
                      std::string{oauth_client_redirect} + R"("],"token_endpoint_auth_method":"none")" +
                      std::string{extra_members} + "}";
    auto const response = post_client_registration(runtime, body);
    auto const parsed = parse_object(response.body);
    auto const* client_id = string_member(parsed, "client_id");
    return client_id == nullptr ? std::string{} : *client_id;
}

// The query parameters of a well-formed authorisation request for `client_id`, in request order.
[[nodiscard]] inline auto oauth_authorize_parameters(std::string_view client_id)
    -> std::vector<std::pair<std::string, std::string>>
{
    return {
        {"response_type",         "code"                            },
        {"client_id",             std::string{client_id}            },
        {"redirect_uri",          std::string{oauth_client_redirect}},
        {"scope",                 std::string{oauth_test_scope}     },
        {"state",                 "st-123 & more"                   },
        {"code_challenge",        std::string{oauth_test_challenge} },
        {"code_challenge_method", "S256"                            },
    };
}

// `parameters` with `name` set to `value` (replaced, or appended), or removed when `value` is nullopt.
[[nodiscard]] inline auto with_parameter(std::vector<std::pair<std::string, std::string>> parameters,
                                         std::string_view name, std::optional<std::string_view> value)
    -> std::vector<std::pair<std::string, std::string>>
{
    auto result = std::vector<std::pair<std::string, std::string>>{};
    auto placed = false;
    for (auto& [key, current] : parameters)
    {
        if (key != name)
        {
            result.emplace_back(std::move(key), std::move(current));
        }
        else if (value.has_value() && !placed)
        {
            result.emplace_back(std::string{name}, std::string{*value});
            placed = true;
        }
    }
    if (value.has_value() && !placed)
    {
        result.emplace_back(std::string{name}, std::string{*value});
    }
    return result;
}

// `application/x-www-form-urlencoded` text of `parameters`, every value percent-encoded.
[[nodiscard]] inline auto form_encode(std::vector<std::pair<std::string, std::string>> const& parameters) -> std::string
{
    auto text = std::string{};
    for (auto const& [name, value] : parameters)
    {
        if (!text.empty())
        {
            text.push_back('&');
        }
        text.append(oauth::percent_encode_redirect_value(name));
        text.push_back('=');
        text.append(oauth::percent_encode_redirect_value(value));
    }
    return text;
}

// What a browser sends with a request to the authorisation endpoint, beyond the method and the target.
struct BrowserContext final
{
    std::string remote_addr{"198.51.100.20"};
    // The value of the browser cookie, or empty for none.
    std::string cookie{};
    std::optional<std::string> origin{std::string{oauth_server_origin}};
    std::optional<std::string> sec_fetch_site{"same-origin"};
    std::string content_type{"application/x-www-form-urlencoded"};
};

[[nodiscard]] inline auto authorize_request(homeserver::ClientServerRuntime& runtime, std::string method,
                                            std::string target, std::string body, BrowserContext const& browser)
    -> homeserver::LocalHttpResponse
{
    auto request = homeserver::LocalHttpRequest{std::move(method), std::move(target), {}, std::move(body)};
    request.remote_addr = browser.remote_addr;
    if (!browser.cookie.empty())
    {
        request.headers.push_back({"Cookie", std::string{oauth_browser_cookie} + "=" + browser.cookie});
    }
    if (request.method == "POST")
    {
        if (browser.origin.has_value())
        {
            request.headers.push_back({"Origin", *browser.origin});
        }
        if (browser.sec_fetch_site.has_value())
        {
            request.headers.push_back({"Sec-Fetch-Site", *browser.sec_fetch_site});
        }
        if (!browser.content_type.empty())
        {
            request.headers.push_back({"Content-Type", browser.content_type});
        }
    }
    return homeserver::handle_client_server_request(runtime, request, /*can_wait=*/false).response;
}

// GET /authorize with `parameters` as the query.
[[nodiscard]] inline auto get_authorize(homeserver::ClientServerRuntime& runtime,
                                        std::vector<std::pair<std::string, std::string>> const& parameters,
                                        BrowserContext const& browser = {}) -> homeserver::LocalHttpResponse
{
    return authorize_request(runtime, "GET", std::string{oauth_authorize_path} + "?" + form_encode(parameters), {},
                             browser);
}

// POST /authorize with `fields` as the form.
[[nodiscard]] inline auto post_authorize(homeserver::ClientServerRuntime& runtime,
                                         std::vector<std::pair<std::string, std::string>> const& fields,
                                         BrowserContext const& browser) -> homeserver::LocalHttpResponse
{
    return authorize_request(runtime, "POST", std::string{oauth_authorize_path}, form_encode(fields), browser);
}

// The pending identifier a page's forms carry, or empty.
[[nodiscard]] inline auto pending_of(homeserver::LocalHttpResponse const& response) -> std::string
{
    constexpr auto marker = std::string_view{R"(name="pending" value=")"};
    auto const at = response.body.find(marker);
    if (at == std::string::npos)
    {
        return {};
    }
    auto const start = at + marker.size();
    auto const end = response.body.find('"', start);
    return end == std::string::npos ? std::string{} : response.body.substr(start, end - start);
}

// The browser cookie's value a response sets, or empty.
[[nodiscard]] inline auto cookie_of(homeserver::LocalHttpResponse const& response) -> std::string
{
    auto const header = response_header(response, "Set-Cookie");
    auto const prefix = std::string{oauth_browser_cookie} + "=";
    if (!header.starts_with(prefix))
    {
        return {};
    }
    auto const end = header.find(';');
    return header.substr(prefix.size(), end == std::string::npos ? std::string::npos : end - prefix.size());
}

[[nodiscard]] inline auto percent_decode(std::string_view text) -> std::string
{
    auto const hex = [](char digit) -> int {
        if (digit >= '0' && digit <= '9')
        {
            return digit - '0';
        }
        if (digit >= 'A' && digit <= 'F')
        {
            return digit - 'A' + 10;
        }
        if (digit >= 'a' && digit <= 'f')
        {
            return digit - 'a' + 10;
        }
        return -1;
    };
    // A `%XX` escape is three bytes of input for one byte of output; everything else is one for one.
    constexpr auto escape_bytes = std::size_t{3U};
    auto out = std::string{};
    // Each turn consumes one item and advances by exactly the bytes it read. A `%` without two hex digits after it
    // is kept as a literal byte, and `+` reads as a space.
    auto index = std::size_t{0U};
    while (index < text.size())
    {
        if (text[index] == '%' && text.size() - index >= escape_bytes && hex(text[index + 1U]) >= 0 &&
            hex(text[index + 2U]) >= 0)
        {
            out.push_back(static_cast<char>((hex(text[index + 1U]) * 16) + hex(text[index + 2U])));
            index += escape_bytes;
        }
        else
        {
            out.push_back(text[index] == '+' ? ' ' : text[index]);
            ++index;
        }
    }
    return out;
}

// Where a redirect's answer is: the query or the fragment of its Location, with the base address before it.
struct RedirectAnswer final
{
    std::string base{};
    char separator{'\0'};
    std::map<std::string, std::string> parameters{};
};

[[nodiscard]] inline auto redirect_answer(homeserver::LocalHttpResponse const& response) -> RedirectAnswer
{
    auto const location = response_header(response, "Location");
    auto answer = RedirectAnswer{};
    auto const fragment = location.find('#');
    auto const query = location.find('?');
    auto const at = fragment != std::string::npos ? fragment : query;
    if (at == std::string::npos)
    {
        answer.base = location;
        return answer;
    }
    answer.base = location.substr(0U, at);
    answer.separator = location[at];
    auto rest = std::string_view{location}.substr(at + 1U);
    while (!rest.empty())
    {
        auto const amp = rest.find('&');
        auto const pair = rest.substr(0U, amp);
        auto const eq = pair.find('=');
        if (eq != std::string_view::npos)
        {
            answer.parameters[percent_decode(pair.substr(0U, eq))] = percent_decode(pair.substr(eq + 1U));
        }
        rest = amp == std::string_view::npos ? std::string_view{} : rest.substr(amp + 1U);
    }
    return answer;
}

} // namespace merovingian::tests
