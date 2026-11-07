// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::config
{

// Identity Service API configuration (Matrix v1.19 Identity Service API).
// The homeserver acts as a client of one or more remote identity servers for
// third-party identifier (3PID) invites, binds, unbinds, and requestToken
// flows. `trusted_servers` is the allowlist of IS base URLs the homeserver
// will contact: a 3PID invite/bind whose `id_server` is not in this list is
// refused (M_UNRECOGNIZED / 404), so operators pin the IS attack surface.
// `allowed_bind_domains`, when non-empty, limits the email domains this server will tell an identity server about
// (M_THREEPID_DENIED otherwise; ADR-0498). Timeouts bound the outbound IS HTTP calls (see OutboundClient).
// Empty by default: with no trusted servers, every 3PID operation that
// requires an IS fails closed with a clear error rather than silently
// minting tokens locally.
struct IdentityServerConfig final
{
    std::vector<std::string> trusted_servers{};
    std::vector<std::string> allowed_bind_domains{};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{30U};
};

} // namespace merovingian::config
