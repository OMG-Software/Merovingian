// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Shared by the account page conformance and integration scenarios (`/_merovingian/account`, ADR-0796): requests as a
// browser sends them (cookie, `Origin`, `Sec-Fetch-Site`, content type), the sign-in form, and readers for the session
// cookie and the form token a page carries.

#include "OAuthAuthorizationSupport.hpp"
#include "OAuthRegistrationSupport.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::tests
{

inline constexpr auto oauth_account_path = std::string_view{"/_merovingian/account"};
inline constexpr auto oauth_account_url = std::string_view{"https://matrix.example.org/_merovingian/account"};
inline constexpr auto oauth_account_cookie = std::string_view{"__Host-mv-account"};

// What a browser sends with a request to the account page, beyond the method and the target.
struct AccountBrowser final
{
    std::string remote_addr{"198.51.100.40"};
    // The value of the account cookie, or empty for none.
    std::string cookie{};
    std::optional<std::string> origin{std::string{oauth_server_origin}};
    std::optional<std::string> sec_fetch_site{"same-origin"};
    std::string content_type{"application/x-www-form-urlencoded"};
};

[[nodiscard]] inline auto account_request(homeserver::ClientServerRuntime& runtime, std::string method,
                                          std::string target, std::string body, AccountBrowser const& browser)
    -> homeserver::LocalHttpResponse
{
    auto request = homeserver::LocalHttpRequest{std::move(method), std::move(target), {}, std::move(body)};
    request.remote_addr = browser.remote_addr;
    if (!browser.cookie.empty())
    {
        request.headers.push_back({"Cookie", std::string{oauth_account_cookie} + "=" + browser.cookie});
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

// GET the account page with `query` (no `?` when empty).
[[nodiscard]] inline auto get_account(homeserver::ClientServerRuntime& runtime, std::string_view query,
                                      AccountBrowser const& browser = {}) -> homeserver::LocalHttpResponse
{
    auto target = std::string{oauth_account_path};
    if (!query.empty())
    {
        target += "?" + std::string{query};
    }
    return account_request(runtime, "GET", std::move(target), {}, browser);
}

// POST `fields` as the form of the account page.
[[nodiscard]] inline auto post_account(homeserver::ClientServerRuntime& runtime,
                                       std::vector<std::pair<std::string, std::string>> const& fields,
                                       AccountBrowser const& browser) -> homeserver::LocalHttpResponse
{
    return account_request(runtime, "POST", std::string{oauth_account_path}, form_encode(fields), browser);
}

// The account cookie's value a response sets, or empty (also for a deletion, whose value is empty).
[[nodiscard]] inline auto account_cookie_of(homeserver::LocalHttpResponse const& response) -> std::string
{
    auto const header = response_header(response, "Set-Cookie");
    auto const prefix = std::string{oauth_account_cookie} + "=";
    if (!header.starts_with(prefix))
    {
        return {};
    }
    auto const end = header.find(';');
    return header.substr(prefix.size(), end == std::string::npos ? std::string::npos : end - prefix.size());
}

// The form token a signed-in page's forms carry, or empty.
[[nodiscard]] inline auto form_token_of(homeserver::LocalHttpResponse const& response) -> std::string
{
    constexpr auto marker = std::string_view{R"(name="form_token" value=")"};
    auto const at = response.body.find(marker);
    if (at == std::string::npos)
    {
        return {};
    }
    auto const start = at + marker.size();
    auto const end = response.body.find('"', start);
    return end == std::string::npos ? std::string{} : response.body.substr(start, end - start);
}

// A signed-in browser: the session cookie and the form token of the overview page.
struct AccountSignedIn final
{
    AccountBrowser browser{};
    std::string form_token{};
    // The 303 the sign-in form was answered with.
    homeserver::LocalHttpResponse sign_in{};
};

// Signs `username` in through the sign-in form, carrying `next` (the hidden next_action and next_device_id fields, when
// given), then reads the overview for its form token. `browser.cookie` is empty when the sign-in did not succeed.
[[nodiscard]] inline auto account_sign_in(homeserver::ClientServerRuntime& runtime, std::string_view username,
                                          std::string_view password,
                                          std::vector<std::pair<std::string, std::string>> next = {}) -> AccountSignedIn
{
    auto signed_in = AccountSignedIn{};
    auto fields = std::move(next);
    fields.emplace_back("username", std::string{username});
    fields.emplace_back("password", std::string{password});
    fields.emplace_back("action", "sign_in");
    signed_in.sign_in = post_account(runtime, fields, signed_in.browser);
    if (signed_in.sign_in.status != 303U)
    {
        return signed_in;
    }
    signed_in.browser.cookie = account_cookie_of(signed_in.sign_in);
    auto const overview = get_account(runtime, {}, signed_in.browser);
    signed_in.form_token = form_token_of(overview);
    return signed_in;
}

} // namespace merovingian::tests
