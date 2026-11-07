// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/EncryptionSecurityConfig.hpp"
#include "merovingian/config/FederationSecurityConfig.hpp"
#include "merovingian/config/LoggingSecurityConfig.hpp"
#include "merovingian/config/LoginThrottleSecurityConfig.hpp"
#include "merovingian/config/LoginTokenSecurityConfig.hpp"
#include "merovingian/config/MediaSecurityConfig.hpp"
#include "merovingian/config/PasswordHashingConfig.hpp"
#include "merovingian/config/PasswordPolicyConfig.hpp"
#include "merovingian/config/RegistrationSecurityConfig.hpp"
#include "merovingian/config/SecretsSecurityConfig.hpp"
#include "merovingian/config/TrustSafetySecurityConfig.hpp"

#include <cstdint>

namespace merovingian::config
{

struct SecurityConfig final
{
    RegistrationSecurityConfig registration{};
    PasswordPolicyConfig password_policy{};
    PasswordHashingConfig password_hashing{};
    LoginThrottleSecurityConfig login_throttle{};
    LoginTokenSecurityConfig login_token{};
    EncryptionSecurityConfig encryption{};
    FederationSecurityConfig federation{};
    MediaSecurityConfig media{};
    TrustSafetySecurityConfig trust_safety{};
    LoggingSecurityConfig logging{};
    SecretsSecurityConfig secrets{};
    // Server-side token expiry, in milliseconds. 0 disables expiry for that
    // token kind (treated as no expiry). Defaults: access 1h, refresh 30d. The
    // advertised expires_in_ms reads from access_token_lifetime_ms so the
    // advertised TTL matches the enforced one.
    std::int64_t access_token_lifetime_ms{3600000};
    std::int64_t refresh_token_lifetime_ms{2592000000};
    // How long `audit_log` rows are kept, in days (ADR-0489). 0 keeps every row for ever. A non-zero value is
    // 30..3650 (`min_audit_log_retention_days`, `max_audit_log_retention_days`): evidence is never kept for less
    // than a month. A row is deleted only once it is older than this, and each deletion is itself audited.
    std::uint32_t audit_log_retention_days{365U};
};

} // namespace merovingian::config
