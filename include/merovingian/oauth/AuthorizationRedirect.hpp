// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/ParsedUri.hpp"
#include "merovingian/oauth/ResponseMode.hpp"

#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::oauth
{

// One parameter of an authorisation answer: `code`, `state`, `error` or `error_description`.
using RedirectParameter = std::pair<std::string_view, std::string_view>;

// `value` percent-encoded so that only RFC 3986 unreserved characters (`A-Z a-z 0-9 - . _ ~`) stay as they are; every
// other byte, a space and CR and LF included, becomes `%XX` with upper-case hex digits. The one encoding of a
// parameter name or value in an authorisation answer.
[[nodiscard]] auto percent_encode_redirect_value(std::string_view value) -> std::string;

// The address the browser is sent to with an authorisation answer (spec "Login flow", "Callback"): `target`, the
// redirect URI `match_redirect_uri` found, exactly as the request gave it, with `parameters` in order, each
// `name=value` with both percent-encoded and joined by `&`.
//
//  - ResponseMode::query: appended to the query, after `&` when `target` already has a non-empty query, directly when
//    it ends in a bare `?`, after a new `?` otherwise.
//  - ResponseMode::fragment: after `#`. A ParsedUri never has a fragment, so the fragment is only the answer.
//
// With no parameters the target is returned unchanged. Pure: the caller chose the parameters, and only it decides that
// the target was validated.
[[nodiscard]] auto authorization_redirect_address(ParsedUri const& target, ResponseMode mode,
                                                  std::span<RedirectParameter const> parameters) -> std::string;

} // namespace merovingian::oauth
