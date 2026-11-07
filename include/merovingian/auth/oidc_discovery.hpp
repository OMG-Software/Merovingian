// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/auth/AuthMetadata.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/OidcConfig.hpp"

namespace merovingian::auth
{

// Builds the Matrix v1.19 / RFC 8414 authorisation server metadata response
// from the server's OIDC configuration. All required fields are populated when
// `config.enabled` is true; optional fields are emitted only when non-empty.
[[nodiscard]] auto make_auth_metadata(config::OidcConfig const& config) -> AuthMetadata;

} // namespace merovingian::auth
