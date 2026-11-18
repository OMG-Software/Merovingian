// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/OAuthPageResponse.hpp"

#include "merovingian/core/RequestCookies.hpp"
#include "merovingian/homeserver/OAuthSecret.hpp"
#include "merovingian/homeserver/RequestHeaders.hpp"
#include "merovingian/oauth/AuthorizationPages.hpp"
#include "merovingian/oauth/PageHeaders.hpp"

#include <cstddef>
#include <variant>

namespace merovingian::homeserver
{

namespace
{

    // A secret as make_oauth_secret mints it: 64 lower-case hex digits.
    constexpr auto secret_text_chars = std::size_t{oauth_secret_bytes * 2U};

} // namespace

auto oauth_page_response(std::uint16_t status, oauth::Page const& page,
                         std::vector<std::pair<std::string, std::string>> headers) -> LocalHttpResponse
{
    auto response = LocalHttpResponse{};
    response.status = status;
    response.body = page.render();
    response.headers = std::move(headers);
    response.page = true;
    return response;
}

auto oauth_plain_page(std::uint16_t status, oauth::Page const& page) -> LocalHttpResponse
{
    return oauth_page_response(status, page, oauth::page_headers());
}

auto oauth_error_page_response(std::uint16_t status, oauth::HtmlText title, oauth::HtmlText const& message)
    -> LocalHttpResponse
{
    return oauth_plain_page(status, oauth::error_page(std::move(title), message));
}

auto request_target_query(std::string_view target) noexcept -> std::string_view
{
    auto const at = target.find('?');
    return at == std::string_view::npos ? std::string_view{} : target.substr(at + 1U);
}

auto single_request_header(LocalHttpRequest const& request, std::string_view name) -> std::optional<std::string_view>
{
    auto const values = request_header_values(request, name);
    if (values.size() != 1U)
    {
        return std::nullopt;
    }
    return values.front();
}

auto is_oauth_secret_text(std::string_view value) noexcept -> bool
{
    if (value.size() != secret_text_chars)
    {
        return false;
    }
    for (auto const character : value)
    {
        if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
        {
            return false;
        }
    }
    return true;
}

auto request_secret_cookie(LocalHttpRequest const& request, std::string_view cookie_name) -> std::optional<std::string>
{
    auto const header = single_request_header(request, "Cookie");
    if (!header.has_value())
    {
        return std::nullopt;
    }
    auto parsed = core::RequestCookies::parse(*header);
    auto const* cookies = std::get_if<core::RequestCookies>(&parsed);
    if (cookies == nullptr)
    {
        return std::nullopt;
    }
    auto const value = cookies->find(cookie_name);
    if (!value.has_value() || !is_oauth_secret_text(*value))
    {
        return std::nullopt;
    }
    return std::string{*value};
}

auto retry_after_seconds(std::uint32_t retry_after_ms) noexcept -> std::uint32_t
{
    auto const seconds = (retry_after_ms / 1000U) + (retry_after_ms % 1000U == 0U ? 0U : 1U);
    return seconds == 0U ? 1U : seconds;
}

} // namespace merovingian::homeserver
