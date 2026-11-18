// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// The random bytes in every OAuth 2.0 secret this server mints: a pending authorisation's identifier, an
// authorisation code and the browser-binding cookie value. 256 bits, as an access token has.
inline constexpr auto oauth_secret_bytes = std::size_t{32U};

// A fresh secret of `oauth_secret_bytes` from the project's secure random source (`crypto::secure_random_hex`), as 64
// lower-case hex digits: safe unescaped in a URL query, a fragment, a form field and a cookie value. nullopt when the
// random source fails. Returned once to the caller and never kept: a store keeps only `oauth_secret_hash` of it.
[[nodiscard]] auto make_oauth_secret() -> std::optional<std::string>;

// The hash an OAuth 2.0 store keeps of a secret: unkeyed BLAKE2b-256 as lower-case hex, as `LoginTokenStore` keeps a
// login token. The secret is 256 random bits, so an unkeyed hash cannot be reversed by guessing. nullopt when
// hashing fails. Compare two results only with `crypto::constant_time_equal`.
[[nodiscard]] auto oauth_secret_hash(std::string_view secret) -> std::optional<std::string>;

} // namespace merovingian::homeserver
