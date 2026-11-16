// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/ParsedUri.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::oauth
{

// The rules for the `redirectUrl` of the legacy SSO redirect when it hands the browser to the built-in pages (plan
// P10, ADR-0802). Pure: no state, no I/O.

// `redirect_url` read with ParsedUri::read (so at most ParsedUri::max_uri_bytes, printable ASCII, no fragment, no
// userinfo) and accepted when its scheme, compared in ASCII lower case, is
//
//  - `https`, with a host;
//  - `http`, with the host `localhost`, `127.0.0.1` or `[::1]` (any port): a native client's loopback listener;
//  - a private-use scheme, one holding a `.` (RFC 8252 section 7.1), with or without an authority.
//
// Anything else is refused: `javascript:`, `data:`, `file:` and every scheme without a `.` other than the two above.
// With a non-empty `allowlist` (`server.oauth.hand_off_redirect_allowlist`, its entries already checked by
// hand_off_allowlist_entry_error) the target must also match an entry: an `https` origin entry matches an `https`
// target with the same host (ASCII lower case) and the same port (443 when none is written); a bare scheme entry
// (`io.element.app:`) matches a target of that scheme in any case. An `http` loopback target matches no entry, so an
// allowlist refuses it. nullopt when refused.
[[nodiscard]] auto hand_off_redirect_target(std::string_view redirect_url, std::span<std::string const> allowlist)
    -> std::optional<ParsedUri>;

// The address the browser is sent to after the hand-off: `target` with every query parameter named exactly
// `loginToken` removed (spec "Handling the callback from the Authentication server", step 4: "If it already includes
// one or more loginToken parameters, they should be removed before adding the new one"), then `loginToken=<token>`
// added to the query by authorization_redirect_address (percent-encoded). nullopt only if the address without those
// parameters is no longer one ParsedUri reads, which removing whole parameters cannot cause.
[[nodiscard]] auto hand_off_return_address(ParsedUri const& target, std::string_view login_token)
    -> std::optional<std::string>;

} // namespace merovingian::oauth
