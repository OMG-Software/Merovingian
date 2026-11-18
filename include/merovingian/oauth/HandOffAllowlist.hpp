// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/Error.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::oauth
{

// The most entries `server.oauth.hand_off_redirect_allowlist` may hold. The hand-off compares a redirect target with
// every entry; a short fixed list keeps that bounded and keeps the list something an operator reviews by eye.
inline constexpr std::size_t max_hand_off_allowlist_entries = 32U;

// Why `entry` cannot be an entry of the hand-off redirect allowlist, or nothing when it can (ADR-0774). An entry is
// one of two shapes, each read with ParsedUri::read and written in lower case so a later match can be byte for byte:
//
//  - an `https` origin: `https://host` or `https://host:port`, with nothing after the authority (no path, not even
//    `/`, no query) and no explicit `:443`, which would be a second spelling of the same origin;
//  - a bare private-use scheme followed by its colon (`io.element.app:`): no authority, path or query. The scheme
//    holds a `.`, as RFC 8252 asks of a private-use scheme, which also refuses `http:`, `https:`, `javascript:` and
//    every other scheme with a general meaning.
//
// Never a URL prefix: a prefix match accepts `https://app.example.com.evil.example`. The message is fixed text.
[[nodiscard]] auto hand_off_allowlist_entry_error(std::string_view entry) -> std::optional<core::Error>;

// Why `entries` cannot be the hand-off redirect allowlist, or nothing when it can: each entry as above, no entry
// twice, at most max_hand_off_allowlist_entries. An empty list is valid.
[[nodiscard]] auto hand_off_allowlist_error(std::span<std::string const> entries) -> std::optional<core::Error>;

} // namespace merovingian::oauth
