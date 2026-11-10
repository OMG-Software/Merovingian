// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::homeserver
{

// Test-only override for a single outbound federation destination.
//
// perform_sync_outbound_call (RoomService.cpp) always resolves a destination
// through federation::discover_server(), which unconditionally rejects
// loopback and private-range addresses (src/federation/Security.cpp
// ip_address_is_private_or_loopback) unless security.federation.
// allow_private_ip_ranges names an RFC 1918 or ULA network (ADR-0231), and
// never loopback — and production outbound calls never populate an in-memory
// CA bundle, so a
// self-signed test certificate would fail TLS verification even if discovery
// succeeded. There is therefore no way to integration-test a live federation
// round trip against a local test server without this seam.
//
// When HomeserverRuntime::test_forced_outbound_resolution has an entry keyed
// by the transaction's destination server_name, perform_sync_outbound_call
// uses it directly instead of calling discover_server(), and its
// trusted_ca_pem is forwarded to the outbound TLS call in place of the
// system trust store. No production construction path (start_runtime,
// main.cpp, the federation worker) ever populates this map — it is empty by
// default, so production SSRF and TLS-trust behaviour is unchanged. Used
// exclusively by tests/integration/test_join_room_flow.cpp.
struct TestOnlyForcedOutboundResolution final
{
    std::string resolved_host{};
    std::uint16_t resolved_port{8448U};
    std::vector<std::string> pinned_addresses{};
    std::string trusted_ca_pem{};
};

} // namespace merovingian::homeserver
