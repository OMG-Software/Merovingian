// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::oauth
{

// What the OAuth 2.0 server metadata advertises beyond its fixed part. The caller fills it from the configuration;
// every field defaults to "not offered".
struct ServerMetadataOptions final
{
    // `server.oauth.device_grant_enabled`: adds the device code grant type and `device_authorization_endpoint`.
    bool device_grant_enabled{false};
    // `security.registration.enabled`: adds `prompt_values_supported: ["create"]`. The field is left out otherwise,
    // so a client never offers account creation the registration page would refuse (ADR-0762).
    bool registration_enabled{false};
    // The account management actions the account page implements, in the order to advertise. Empty leaves out both
    // `account_management_uri` and `account_management_actions_supported`. The served document passes all six
    // (`account_management_actions()`, `AccountPages.hpp`).
    std::vector<std::string> account_management_actions{};
};

} // namespace merovingian::oauth
