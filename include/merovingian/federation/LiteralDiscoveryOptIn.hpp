// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::federation
{

// Test-only opt-in token for the well-known delegation overload below.
//
// Security (audit M-06, 2026-09): that overload resolves through an internal
// literal network whose address lookup returns the documentation address
// 203.0.113.10 for every non-numeric host. It performs no DNS resolution and
// therefore applies none of the real SSRF address checks that a live lookup
// feeds, so it must never be reachable from a production federation path. The
// explicit default constructor means the token cannot be materialised from a
// bare `{}`; every use is a deliberate, greppable opt-in, and a production call
// site written against the old two-argument signature fails to compile.
struct LiteralDiscoveryOptIn final
{
    explicit LiteralDiscoveryOptIn() = default;
};

} // namespace merovingian::federation
