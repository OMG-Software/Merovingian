// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/MasqueradeIdentity.hpp" // split-shim

#include <optional>
#include <string>
#include <string_view>

namespace merovingian::appservice
{

inline constexpr std::string_view masquerade_token_prefix = "appservice-masquerade:v1:";

// True when `token` carries the reserved internal-masquerade shape. Used
// both to recognise a token this process minted and to REJECT a raw
// externally-supplied token in this shape before any auth logic runs.
[[nodiscard]] auto is_masquerade_token(std::string_view token) noexcept -> bool;

// Encodes `identity` as an internal masquerade token. Uses explicit decimal
// length prefixes (not a delimiter) for each field so a `:` inside a user
// id or appservice id can never be misparsed as a field boundary.
[[nodiscard]] auto encode_masquerade_token(MasqueradeIdentity const& identity) -> std::string;

// Decodes a token produced by encode_masquerade_token. Returns std::nullopt
// for anything that does not exactly match the expected shape — including a
// prefix match with a corrupted body, which must fail closed rather than
// partially resolve an identity.
[[nodiscard]] auto decode_masquerade_token(std::string_view token) -> std::optional<MasqueradeIdentity>;

// True when `method` + `path` (query string already stripped) names an
// Account Management endpoint, on which identity assertion MUST NOT be
// honoured. Spec (Application Service API, Identity assertion): "This applies
// to all aspects of the Client-Server API, except for Account Management."
//
// Covered: every path under `/_matrix/client/<version>/account/` (password
// change and its requestToken calls, deactivation, and the whole 3PID
// management family), except `GET .../account/whoami` — the spec's own
// worked example of identity assertion. An unknown path under `/account/` is
// treated as covered (fail closed), so a future endpoint cannot silently
// become assertable.
[[nodiscard]] auto is_account_management_endpoint(std::string_view method, std::string_view path) noexcept -> bool;

} // namespace merovingian::appservice
