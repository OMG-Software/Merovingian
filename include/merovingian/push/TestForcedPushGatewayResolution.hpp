// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::push
{

// Test-only override for one push-gateway host. Mirrors
// identity::TestForcedIdentityResolution's contract exactly (see that type's
// doc comment for the rationale): when a caller supplies a non-null map and
// it has an entry keyed by the gateway URL's host, PushGatewayClient::notify()
// uses these pinned addresses and in-memory CA bundle instead of SSRF-safe
// discovery. Always empty in production; no production construction path
// populates it. Exists so integration tests can drive a real local HTTPS
// gateway (self-signed certificate, loopback address) without weakening the
// production SSRF/discovery boundary in push_gateway_client.cpp.
struct TestForcedPushGatewayResolution final
{
    std::vector<std::string> pinned_addresses{};
    std::string trusted_ca_pem{};
};

} // namespace merovingian::push
