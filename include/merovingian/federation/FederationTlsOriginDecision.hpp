// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

// Validates that the resolved federation destination is acceptable for the
// original server name from a TLS-certificate-identity perspective. This is
// a logical pre-check, not a live TLS handshake; callers use it before
// connecting to avoid routing a request to a host whose certificate could not
// validly cover the server name.
struct FederationTlsOriginDecision final
{
    bool valid{false};
    std::string reason{};
};

} // namespace merovingian::federation
