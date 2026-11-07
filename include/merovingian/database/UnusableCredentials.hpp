// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::database
{

// ADR-0488: credential rows that can no longer authenticate anyone. An access token row is unusable once it is
// revoked (revocation is one-way, ADR-0052) or has been expired for `expired_access_grace`, which keeps the "token
// expired" audit reason for a while. A refresh token row is unusable once it has expired: an expired refresh token
// is refused before the reuse check, so deleting it changes no answer. A REVOKED refresh token that has not
// expired is kept, because presenting it is how a stolen, rotated token is detected (ADR-0074).
struct UnusableCredentials final
{
    std::vector<std::string> access_token_hashes{};
    std::vector<std::string> refresh_token_hashes{};
};

} // namespace merovingian::database
