// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/federation/OutboundTransaction.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::federation
{

// Composed shape ready to send: transaction shape + validated destination
// resolution + signing identity. Callers populate `pinned_addresses` from
// the address set already accepted by `federation_discovery_policy` so the
// SSRF policy remains the single source of truth.
struct OutboundCall final
{
    OutboundTransaction transaction{};
    std::string resolved_host{};
    // M-02: the name the destination's certificate must be valid for, and the
    // URL host used for SNI and the Host header. Differs from resolved_host
    // whenever discovery went through an SRV record: resolved_host is then the
    // SRV target, but the spec requires the certificate to match the original
    // (or well-known delegated) hostname. Copy this from
    // ServerDiscoveryResult::tls_server_name. Empty means "same as
    // resolved_host", which is correct for callers that bypass discovery and
    // set resolved_host to an authoritative name directly.
    std::string tls_server_name{};
    std::uint16_t resolved_port{8448U};
    std::vector<std::string> pinned_addresses{};
    std::string key_id{};
    // Raw 64-byte libsodium Ed25519 secret key for this server's signing
    // identity, used to sign the X-Matrix Authorization header. Owned by the
    // call object as an mlocked, zeroised core::SecretBuffer so no caller has
    // to keep an external buffer alive across lock releases, async worker tasks,
    // or orphan futures. build_outbound_request signs synchronously and discards
    // its span before the OutboundCall is destroyed.
    core::SecretBuffer secret_key{};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{60U};
    // Optional PEM CA bundle trusted in place of the system trust store,
    // forwarded to http::OutboundRequest::trusted_ca_pem. Empty means "use
    // system trust" (all production federation traffic). Only ever populated
    // by HomeserverRuntime's test-only forced-resolution override.
    std::string trusted_ca_pem{};
    // Forwarded to http::OutboundRequest::max_response_body_bytes. Defaults
    // to the same 16 MiB ceiling as OutboundRequest itself; callers whose
    // response can legitimately exceed that (send_join for a large room)
    // override it from the caller-supplied config budget.
    std::size_t max_response_body_bytes{16U * 1024U * 1024U};
};

} // namespace merovingian::federation
