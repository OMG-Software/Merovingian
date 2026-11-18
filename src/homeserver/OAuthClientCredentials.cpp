// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthClientCredentials.hpp"

#include "merovingian/core/FormFields.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/OAuthJsonResponse.hpp"
#include "merovingian/homeserver/RequestHeaders.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace merovingian::homeserver
{

namespace
{

    [[nodiscard]] auto ascii_lower(char c) noexcept -> char
    {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    }

    // Whether `value` is an `Authorization` header value of the `Basic` scheme: the scheme alone, or followed by a
    // space and the credentials.
    [[nodiscard]] auto is_basic_scheme(std::string_view value) noexcept -> bool
    {
        constexpr auto scheme = std::string_view{"basic"};
        if (value.size() < scheme.size() || (value.size() > scheme.size() && value[scheme.size()] != ' '))
        {
            return false;
        }
        for (std::size_t index = 0U; index < scheme.size(); ++index)
        {
            if (ascii_lower(value[index]) != scheme[index])
            {
                return false;
            }
        }
        return true;
    }

} // namespace

auto oauth_client_credentials_refusal(LocalHttpRequest const& request, core::FormFields const& fields)
    -> std::optional<LocalHttpResponse>
{
    for (auto const value : request_header_values(request, "Authorization"))
    {
        if (is_basic_scheme(value))
        {
            auto response = oauth_error_response(std::uint16_t{401U}, oauth::error_invalid_client,
                                                 "This server has only public clients, which send no credentials.");
            response.headers.emplace_back("WWW-Authenticate", "Basic");
            return response;
        }
    }
    if (fields.find("client_secret").has_value())
    {
        return oauth_error_response(std::uint16_t{400U}, oauth::error_invalid_client,
                                    "This server has only public clients, which send no client_secret.");
    }
    return std::nullopt;
}

} // namespace merovingian::homeserver
