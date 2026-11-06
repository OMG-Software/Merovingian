// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/http/OutboundResult.hpp"
#include "merovingian/http/ParsedOutboundUrl.hpp"
#include "merovingian/http/SystemCaTrust.hpp"
#include "merovingian/http/outbound_error.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::http
{

// Probes the standard system CA trust store locations across the platforms
// Merovingian targets. The bundled libcurl is built from source without a
// fixed --with-ca-bundle, so its compiled-in default may not match the
// deployment host; perform() points libcurl at the resolved locations
// explicitly when a request carries no in-memory CA bundle.
[[nodiscard]] auto detect_system_ca_trust() -> SystemCaTrust;

// Parses one absolute HTTPS URL (or HTTP only when explicitly allowed),
// rejecting URL forms whose authority could diverge from the transport pin:
// userinfo, fragments, control bytes, backslashes, encoded authority bytes,
// invalid IP literals, and malformed ports. This performs no DNS or network
// I/O and shares its parser and rules with OutboundClient::perform().
[[nodiscard]] auto parse_outbound_url(std::string_view url, bool allow_cleartext_http = false)
    -> std::optional<ParsedOutboundUrl>;

// Pure validator. Returns OutboundError::none when the request is well-formed.
// Does not perform DNS, TLS, or any network I/O.
[[nodiscard]] auto validate_outbound_request(OutboundRequest const& request) noexcept -> OutboundError;

// Federation outbound HTTP client.
//
// A single OutboundClient instance may be reused across calls and shared
// across threads: perform() drives a per-thread transport handle, so the
// runtime can hand one instance to both the federation dispatch worker and the
// HTTP request-handler thread pool without locking or risking cross-thread
// corruption. The client holds no per-instance state; all operations are
// noexcept-friendly and return errors through OutboundResult.
class OutboundClient final
{
public:
    OutboundClient();
    ~OutboundClient();

    OutboundClient(OutboundClient const&) = delete;
    auto operator=(OutboundClient const&) -> OutboundClient& = delete;
    OutboundClient(OutboundClient&&) noexcept = delete;
    auto operator=(OutboundClient&&) noexcept -> OutboundClient& = delete;

    // Performs the request and returns the result. Fails closed when request
    // invariants are violated or when the underlying transport reports an
    // error. Pre-network validation runs before any DNS, TLS, or socket I/O.
    // Safe to call concurrently from multiple threads on the same instance.
    [[nodiscard]] auto perform(OutboundRequest const& request) -> OutboundResult;
};

} // namespace merovingian::http
