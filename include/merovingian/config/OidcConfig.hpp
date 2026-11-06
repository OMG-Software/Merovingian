// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::config
{

// OIDC authorisation server metadata configuration for MSC2965 discovery.
// When `enabled` is false, GET /_matrix/client/v1/auth_metadata returns
// 404 M_UNRECOGNIZED. When enabled, the endpoint returns RFC 8414 metadata
// built from these fields; no actual OAuth flow is implemented here.
struct OidcConfig final
{
    bool enabled{false};
    std::string issuer{};
    std::string authorization_endpoint{};
    std::string token_endpoint{};
    std::string registration_endpoint{};
    std::string revocation_endpoint{};
    std::string device_authorization_endpoint{};
    std::string account_management_uri{};
    std::vector<std::string> account_management_actions_supported{};
};

} // namespace merovingian::config
