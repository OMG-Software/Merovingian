// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/appservice/cleartext_policy.hpp"

#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/net/loopback_literal.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::appservice
{

namespace
{

    [[nodiscard]] auto lower_ascii(char byte) noexcept -> char
    {
        return (byte >= 'A' && byte <= 'Z') ? static_cast<char>(byte - 'A' + 'a') : byte;
    }

    [[nodiscard]] auto equal_ignoring_ascii_case(std::string_view left, std::string_view right) noexcept -> bool
    {
        return std::ranges::equal(left, right, [](char a, char b) {
            return lower_ascii(a) == lower_ascii(b);
        });
    }

} // namespace

auto cleartext_host_permitted(std::string_view host, std::vector<std::string> const& allowed_cleartext_hosts) noexcept
    -> bool
{
    if (net::is_loopback_ip_literal(host))
    {
        return true;
    }
    return std::ranges::any_of(allowed_cleartext_hosts, [host](std::string const& allowed) {
        return !allowed.empty() && equal_ignoring_ascii_case(host, allowed);
    });
}

auto appservice_url_problem(std::string_view url, std::vector<std::string> const& allowed_cleartext_hosts)
    -> std::optional<std::string>
{
    auto const parsed = http::parse_outbound_url(url, true);
    if (!parsed.has_value())
    {
        return std::string{"url must be an absolute http or https url with a host and no userinfo or fragment"};
    }
    if (!parsed->query.empty() || url.find('?') != std::string_view::npos)
    {
        return std::string{"url must not have a query string"};
    }
    if (parsed->scheme == "http" && !cleartext_host_permitted(parsed->host, allowed_cleartext_hosts))
    {
        return std::string{"cleartext http url host is neither a loopback IP literal nor listed in "
                           "appservice.allow_cleartext_hosts; use https or list the host"};
    }
    return std::nullopt;
}

} // namespace merovingian::appservice
