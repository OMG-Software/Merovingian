// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/ServerDiscoveryResult.hpp"

#include <string>

namespace merovingian::homeserver
{

// Result of resolving a `Location` redirect URL from the authenticated
// federation media download endpoint. `ok` is true when the URL uses HTTPS,
// has a resolvable host, and resolves only to non-private/non-loopback
// addresses. `discovery` carries the pinned addresses when resolution
// succeeds; `reason` explains the failure when it does not.
struct MediaRedirectResolutionResult final
{
    bool ok{false};
    std::string reason{};
    federation::ServerDiscoveryResult discovery{};
    std::string url{}; // Canonical URL from the transport's parser; use this for the fetch.
};

} // namespace merovingian::homeserver
