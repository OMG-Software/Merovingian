// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::config
{

// The default federation deny list: loopback, RFC 1918 and ULA blocks, in a
// fixed order, formatted as "address/prefix" from the one numeric table in
// Config.cpp (ADR-0516). Both this list and is_private_or_loopback_range()
// derive from that table, so the two cannot drift apart.
[[nodiscard]] auto default_federation_deny_ip_ranges() -> std::vector<std::string>;

} // namespace merovingian::config
