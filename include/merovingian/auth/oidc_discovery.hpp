// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"

namespace merovingian::auth
{

// Holds the OIDC authorisation server metadata as a canonical JSON object.
// When `configured` is false the caller should return 404 M_UNRECOGNIZED;
// when true the caller should return the fields object with status 200.
struct AuthMetadata final
{
    bool configured{false};
    canonicaljson::Object fields{};
};

// Builds the Matrix v1.19 / RFC 8414 authorisation server metadata response
// from the server's OIDC configuration. All required fields are populated when
// `config.enabled` is true; optional fields are emitted only when non-empty.
[[nodiscard]] auto make_auth_metadata(config::OidcConfig const& config) -> AuthMetadata;

} // namespace merovingian::auth
