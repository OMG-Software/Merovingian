// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/GrantedScope.hpp"
#include "merovingian/oauth/OAuthRefusal.hpp"

#include <cstddef>
#include <string_view>
#include <variant>

namespace merovingian::oauth
{

// The scope token granting full Client-Server API access (spec "Scope", "Allocated scope tokens").
inline constexpr std::string_view scope_token_api_all = "urn:matrix:client:api:*";
// The prefix of the device scope token; the device ID follows it.
inline constexpr std::string_view scope_token_device_prefix = "urn:matrix:client:device:";

// The longest `scope` read, in bytes: the two tokens this server knows take at most 25 + 255 + 1 + 23 bytes; 2048
// leaves room for tokens a client adds for other servers, which are dropped.
inline constexpr std::size_t max_scope_bytes = 2048U;
// The most tokens read: a client sends two or three.
inline constexpr std::size_t max_scope_tokens = 32U;
// The shortest device ID accepted: the spec says ten unreserved characters are enough to be unique per user, and
// lets the server refuse a shorter one.
inline constexpr std::size_t min_oauth_device_id_chars = 10U;

// Whether `device_id` may be allocated through the OAuth 2.0 API: auth::device_id_is_valid, at least
// min_oauth_device_id_chars, and only RFC 3986 unreserved characters (`A-Z a-z 0-9 - . _ ~`).
[[nodiscard]] auto oauth_device_id_is_valid(std::string_view device_id) noexcept -> bool;

// Reads the `scope` parameter of an authorisation or token request, after form decoding (RFC 6749 section 3.3): one
// or more tokens of `%x21 / %x23-5B / %x5D-7E`, separated by single spaces. Refused with `invalid_scope` when it is
// empty, has a leading, trailing or doubled space or any other byte, exceeds a cap above, lacks
// `urn:matrix:client:api:*`, or holds no `urn:matrix:client:device:<id>` token or more than one (even the same one
// twice), or that device ID fails oauth_device_id_is_valid. Any other token is dropped, never refused; only the stable
// token forms are known. The refusal's message is fixed text.
[[nodiscard]] auto parse_scope(std::string_view scope) -> std::variant<GrantedScope, OAuthRefusal>;

} // namespace merovingian::oauth
