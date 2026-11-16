// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/oauth/FormPostOrigin.hpp"

#include "merovingian/oauth/AsciiCase.hpp"

#include <cstdint>

namespace merovingian::oauth
{
namespace
{

    // The port an https origin leaves out (RFC 6454 section 6.1).
    constexpr auto https_default_port = std::uint16_t{443U};

} // namespace

auto form_post_origin(OAuthBaseUrl const& base_url) -> std::string
{
    // OAuthBaseUrl::read accepts only https, so the scheme is fixed here rather than copied in the case it was written.
    auto origin = std::string{"https://"};
    origin.append(ascii_lower(base_url.uri().host()));
    if (auto const port = base_url.uri().port(); port.has_value() && *port != https_default_port)
    {
        origin.push_back(':');
        origin.append(std::to_string(*port));
    }
    return origin;
}

auto form_post_origin_is_accepted(OAuthBaseUrl const& base_url, std::optional<std::string_view> origin,
                                  std::optional<std::string_view> sec_fetch_site) -> bool
{
    if (!origin.has_value() || *origin != form_post_origin(base_url))
    {
        return false;
    }
    return !sec_fetch_site.has_value() || *sec_fetch_site == "same-origin";
}

} // namespace merovingian::oauth
