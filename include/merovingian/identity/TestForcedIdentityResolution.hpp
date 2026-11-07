// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::identity
{

// Test-only override for one identity-server host. Mirrors the homeserver's
// `TestOnlyForcedOutboundResolution` contract: when `HomeserverRuntime` has an
// entry keyed by the IS host, `IdentityServerClient::perform()` uses these
// pinned addresses and in-memory CA bundle instead of SSRF-safe discovery. The
// IS base URL already carries the port (no `resolved_port` override is needed,
// unlike the federation seam which resolves a different port via SRV/.well-
// known), so only the pinned addresses and CA bundle are required. The struct
// lives here — not in `HomeserverRuntime.hpp` — so the `identity` module does not depend
// on `homeserver` (the dependency runs `homeserver → identity`). Always empty
// in production; no production construction path populates it.
struct TestForcedIdentityResolution final
{
    std::vector<std::string> pinned_addresses{};
    std::string trusted_ca_pem{};
};

} // namespace merovingian::identity
