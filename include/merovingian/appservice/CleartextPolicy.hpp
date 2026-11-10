// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::appservice
{

// True when plain http may be sent to `host`: it is a loopback IP literal (net::is_loopback_ip_literal) or
// equals an entry of `allowed_cleartext_hosts` exactly, ignoring ASCII case. A name such as `localhost` is
// permitted only when listed. `host` is the parsed host (an IPv6 literal without brackets).
[[nodiscard]] auto cleartext_host_permitted(std::string_view host,
                                            std::vector<std::string> const& allowed_cleartext_hosts) noexcept -> bool;

// Checks an appservice registration `url` against the rule of ADR-0515 and returns why it is refused, or
// nullopt when it may be used. The url must parse as an absolute http or https url without userinfo or a
// fragment, must have no query string (the spec allows only "a path after the domain name"), and, when its
// scheme is http, must name a host that cleartext_host_permitted accepts. The text never contains any part
// of the url, so it is safe to log. Pure: no DNS and no network I/O.
[[nodiscard]] auto appservice_url_problem(std::string_view url, std::vector<std::string> const& allowed_cleartext_hosts)
    -> std::optional<std::string>;

} // namespace merovingian::appservice
