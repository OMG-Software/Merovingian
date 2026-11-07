// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::federation
{

struct ServerDiscoveryResult final
{
    std::string server_name{};
    std::string well_known_host{};
    std::string resolved_host{};
    // M-02: the name the destination's TLS certificate must be valid for, and
    // the name to send as SNI and in the Host header. This is NOT always
    // resolved_host: when discovery went through an SRV record, resolved_host is
    // the SRV *target*, and the spec is explicit that the certificate must still
    // match the original hostname (or the well-known delegated hostname), never
    // the SRV target — see server-server-api.md steps 4 and 5, and the section
    // "The reasons we require <hostname> rather than <delegated_hostname> for
    // SRV delegation are". Honouring the SRV target instead would let anyone who
    // can forge an unsigned DNS response redirect a server to a host that proves
    // an identity of its own choosing.
    //
    // Callers building an outbound URL must use THIS as the URL host, and pass
    // pinned_addresses to CURLOPT_RESOLVE so the connection still lands on the
    // resolved target. That keeps SNI, Host and certificate validation on the
    // authoritative name while the packets go where discovery said.
    std::string tls_server_name{};
    std::uint16_t resolved_port{8448U};
    std::vector<std::string> pinned_addresses{};
    bool tls_required{true};
    bool discovery_allowed{false};
    std::string reason{};
};

} // namespace merovingian::federation
