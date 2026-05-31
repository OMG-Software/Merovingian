// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::http
{

// Reasons the outbound HTTP client may refuse or fail a request.
// Each value maps to a stable, audit-friendly name through outbound_error_name.
// Failures fail closed: the response payload is meaningless when ok is false,
// except for redirect_rejected where the 3xx status and headers are preserved
// in the response so callers can audit the rejection.
enum class OutboundError : std::uint8_t
{
    none,
    invalid_url,
    invalid_method,
    https_required,
    unresolved_host,
    tls_verification_failed,
    connection_failed,
    redirect_rejected,
    response_too_large,
    timeout,
    network_error,
};

struct OutboundHeader final
{
    std::string name{};
    std::string value{};
};

// Outbound HTTPS request for federation traffic.
//
// Security invariants enforced by perform():
//   - method must be a known token (GET, POST, PUT, DELETE).
//   - url must be an absolute https:// URL; cleartext is rejected.
//   - url must include a host segment.
//   - pinned_addresses must contain at least one address; perform() does not
//     resolve the host itself so the SSRF policy in
//     merovingian::federation::security stays the single source of truth.
//     The addresses are bound to the URL host:port through libcurl's
//     CURLOPT_RESOLVE so the connection cannot drift to a different address.
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
};

struct OutboundResponse final
{
    std::uint16_t status{0U};
    std::vector<OutboundHeader> headers{};
    std::string body{};
};

struct OutboundResult final
{
    bool ok{false};
    OutboundResponse response{};
    OutboundError error{OutboundError::network_error};
    std::string error_detail{};
};

// Returns a stable, audit-friendly name for the given error code.
// The returned view is suitable for logging and structured audit events;
// it is not part of any Matrix wire protocol.
[[nodiscard]] auto outbound_error_name(OutboundError error) noexcept -> std::string_view;

// Resolved host CA trust store locations. Either field may be empty when the
// corresponding location is absent from the host.
struct SystemCaTrust final
{
    std::string bundle_file{}; // concatenated PEM bundle (libcurl CAINFO)
    std::string bundle_dir{};  // OpenSSL hashed certificate directory (CAPATH)
};

// Probes the standard system CA trust store locations across the platforms
// Merovingian targets. The bundled libcurl is built from source without a
// fixed --with-ca-bundle, so its compiled-in default may not match the
// deployment host; perform() points libcurl at the resolved locations
// explicitly when a request carries no in-memory CA bundle.
[[nodiscard]] auto detect_system_ca_trust() -> SystemCaTrust;

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
