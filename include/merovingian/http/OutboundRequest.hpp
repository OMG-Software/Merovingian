// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/OutboundHeader.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::http
{

// Outbound HTTPS request for federation traffic.
//
// Security invariants enforced by perform():
//   - method must be a known token (GET, POST, PUT, DELETE).
//   - url must be an absolute https:// URL; cleartext is rejected.
//   - url must include a host segment.
//   - pinned_addresses must contain at least one address; perform() does not
//     resolve the host itself so the SSRF policy in
//     merovingian::federation::security stays the single source of truth.
//     One CURLOPT_RESOLVE entry retains all approved addresses. Every actual
//     socket destination is checked against those numeric IPs and the parsed
//     port before opening it. Proxies and socket reuse are disabled because
//     they bypass that request's peer check.
//
// libcurl is configured with peer and hostname certificate verification on,
// redirects refused, and the protocol restricted to https. Responses larger
// than max_response_body_bytes are rejected with response_too_large.
struct OutboundRequest final
{
    std::string method{"GET"};
    std::string url{};
    std::vector<OutboundHeader> headers{};
    std::string body{};
    std::vector<std::string> pinned_addresses{};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{60U};
    std::size_t max_response_body_bytes{16U * 1024U * 1024U};
    // Optional PEM-encoded CA bundle used in place of the system trust store.
    // Empty means "use system trust". Production federation traffic leaves
    // this empty; tests and pinned-CA deployments populate it.
    std::string trusted_ca_pem{};
    // Opt-in escape hatch from the https-only invariant above. There are
    // exactly two sanctioned uses:
    //   1. A destination the OPERATOR configured out-of-band (a local
    //      filesystem artifact, not something a network peer can point at):
    //      an appservice registration file's `url`, which the Matrix
    //      Application Service API's own canonical example (and most
    //      real-world bridges) gives as a plain `http://` localhost address.
    //   2. A URL preview hop (ADR-0213), made only through the preview gate
    //      (`gated_fetch` in homeserver/UrlPreviewService.cpp). It is
    //      client-named, but carries no credential, and the gate checks and
    //      pins its addresses like any other request.
    // It MUST be left false for every other URL that is attacker- or
    // client-influenced in any way (federation destinations, a pusher's
    // registered gateway URL, an identity server named by a client): those
    // stay https-only. When true, `url` may be `http://` OR `https://`; TLS
    // verification still applies whenever the connection does end up being
    // TLS.
    bool allow_cleartext_http{false};
};

} // namespace merovingian::http
