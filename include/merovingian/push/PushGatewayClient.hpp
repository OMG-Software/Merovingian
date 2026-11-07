// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/PushConfig.hpp"
#include "merovingian/federation/CachedServerDiscovery.hpp"
#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/http/OutboundError.hpp"
#include "merovingian/push/GatewayCircuitOutcome.hpp"
#include "merovingian/push/GatewayInFlightLimiter.hpp"
#include "merovingian/push/PushGatewayNotification.hpp"
#include "merovingian/push/PushGatewayRejection.hpp"
#include "merovingian/push/PushGatewayResult.hpp"
#include "merovingian/push/TestForcedPushGatewayResolution.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::push
{

// Pure builder: no network, no I/O. Serializes `notification` to the
// canonical-JSON request body the Push Gateway API expects. Unit-testable in
// isolation from the outbound transport.
[[nodiscard]] auto build_notify_request_body(PushGatewayNotification const& notification) -> std::string;

// Pure parser: no network. Returns nullopt for a malformed body (missing or
// wrong-typed `rejected`).
[[nodiscard]] auto parse_notify_response(std::string_view body) -> std::optional<PushGatewayRejection>;

// The gateway a pusher's URL names, as `host:port` with the host case-folded and
// any trailing dot removed, so every spelling of one gateway shares a key; or
// nullopt for a URL notify() would refuse. Keys the gateway circuit breaker
// (OUT-3, ADR-0151).
[[nodiscard]] auto push_gateway_host(std::string_view gateway_url) -> std::optional<std::string>;

[[nodiscard]] auto gateway_circuit_outcome(PushGatewayResult const& result) noexcept -> GatewayCircuitOutcome;

// gateway_circuit_outcome(result), except that an HTTP answer that took longer than half of
// `total_timeout` is `slow_answer`. `elapsed` is how long the request took.
[[nodiscard]] auto gateway_circuit_outcome(PushGatewayResult const& result, std::chrono::milliseconds elapsed,
                                           std::chrono::seconds total_timeout) noexcept -> GatewayCircuitOutcome;

// How many requests may be in flight to one gateway host, and to one resolved address, out of
// `config.max_in_flight_deliveries` (F-79, ADR-0409): an eighth and a quarter, at least two each (or the whole budget
// when it is smaller), so a small budget is not serialised behind one loopback or shared address.
[[nodiscard]] auto push_gateway_host_in_flight_cap(config::PushConfig const& config) noexcept -> std::size_t;
[[nodiscard]] auto push_gateway_address_in_flight_cap(config::PushConfig const& config) noexcept -> std::size_t;

// Whether the gateway answered and listed `pushkey` as rejected. The spec's
// `rejected` names "all pushkeys given in the notification request that are not
// valid", so a list naming only other pushkeys does not reject this pusher.
[[nodiscard]] auto pushkey_was_rejected(PushGatewayResult const& result, std::string_view pushkey) -> bool;

// Outbound Push Gateway API client. Mirrors identity::IdentityServerClient's
// shape and security posture: every call resolves the gateway host to
// SSRF-safe pinned addresses via CachedServerDiscovery (private/loopback
// ranges rejected upstream) and goes through http::OutboundClient with TLS
// verification on. A pusher's gateway URL is attacker-influenced data — any
// client can register a pusher with any URL — so this is a genuine SSRF
// surface and is treated as hostile: no ad-hoc DNS, no client-supplied
// address ever reaches the transport directly.
//
// notify() fails closed on `config.enabled == false` before touching the
// network at all, so this client is safe to wire in even while push
// delivery is disabled by default.
//
// Borrows its dependencies by reference; callers must keep them alive for
// the lifetime of the client. Network calls never take the caller's own
// locks (this class holds none of its own), matching the project's
// "network calls must never hold runtime.mutex" rule.
class PushGatewayClient final
{
public:
    // With `limiter`, notify() takes a slot on the gateway host and on every address it resolves to
    // for the length of the request, and returns `busy` when either is full (F-79).
    PushGatewayClient(http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery,
                      config::PushConfig const& config,
                      std::map<std::string, TestForcedPushGatewayResolution> const* forced_resolution = nullptr,
                      std::optional<std::reference_wrapper<GatewayInFlightLimiter>> limiter = std::nullopt) noexcept;

    // The whole-request timeout this client sends with (`config.total_timeout_seconds`).
    [[nodiscard]] auto total_timeout() const noexcept -> std::chrono::seconds;

    // POST /_matrix/push/v1/notify at `gateway_url` (the pusher's
    // `data.url`, required to be an HTTPS URL with path
    // `/_matrix/push/v1/notify` per spec). Returns PushGatewayResult; see its
    // doc comment for how to interpret each outcome.
    [[nodiscard]] auto notify(std::string_view gateway_url, PushGatewayNotification const& notification)
        -> PushGatewayResult;

private:
    http::OutboundClient& outbound_;
    federation::CachedServerDiscovery& discovery_;
    config::PushConfig const& config_;
    // Test-only seam (see TestForcedPushGatewayResolution above). nullptr in
    // production; when non-null and keyed by the gateway host, notify() uses
    // the entry's pinned addresses + in-memory CA bundle instead of discovery.
    std::map<std::string, TestForcedPushGatewayResolution> const* test_forced_resolution_{nullptr};
    std::optional<std::reference_wrapper<GatewayInFlightLimiter>> limiter_{};
};

} // namespace merovingian::push
