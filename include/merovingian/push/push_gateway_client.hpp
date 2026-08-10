// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::push
{

// One entry of the Push Gateway `/notify` request's `devices` array: one
// pusher to notify. `data_format` mirrors the pusher's `data.format`
// (excluding `url`, which routes the request instead of being sent in the
// body); `tweak_sound`/`tweak_highlight` come from push-rule evaluation.
struct PushGatewayDevice final
{
    std::string app_id{};
    std::string pushkey{};
    std::uint64_t pushkey_ts{0U};
    std::optional<std::string> data_format{};
    std::optional<std::string> tweak_sound{};
    bool tweak_highlight{false};
};

struct PushGatewayCounts final
{
    std::uint32_t unread{0U};
    std::uint32_t missed_calls{0U};
};

// Everything needed to build one `POST /_matrix/push/v1/notify` request body
// (docs/matrix-v1.19-spec/push-gateway-api.md). `content_json` is the
// pre-serialized `content` field of the event, already omitted by the caller
// when the format is `event_id_only` or the event has no content; empty
// means "omit `content`".
struct PushGatewayNotification final
{
    std::string event_id{};
    std::string room_id{};
    std::string room_alias{};
    std::string room_name{};
    std::string type{};
    std::string sender{};
    std::string sender_display_name{};
    bool user_is_target{false};
    std::string prio{"high"};
    std::string content_json{};
    PushGatewayCounts counts{};
    std::vector<PushGatewayDevice> devices{};
};

// Pure builder: no network, no I/O. Serializes `notification` to the
// canonical-JSON request body the Push Gateway API expects. Unit-testable in
// isolation from the outbound transport.
[[nodiscard]] auto build_notify_request_body(PushGatewayNotification const& notification) -> std::string;

// Parsed `200` response to `/notify`: the list of pushkeys the gateway
// rejects as permanently invalid.
struct PushGatewayRejection final
{
    std::vector<std::string> rejected_pushkeys{};
};

// Pure parser: no network. Returns nullopt for a malformed body (missing or
// wrong-typed `rejected`).
[[nodiscard]] auto parse_notify_response(std::string_view body) -> std::optional<PushGatewayRejection>;

// Outcome of one PushGatewayClient::notify() call.
//   - `disabled == true` means config.enabled was false and no network call
//     was made at all (the config-gate fail-closed path).
//   - `ok == false` (with `disabled == false`) means a transport failure —
//     DNS/TLS/SSRF/connection/timeout; see `error`/`error_detail`.
//   - `ok == true` means the gateway was reached; `status` carries its HTTP
//     status and `rejected_pushkeys` — populated only on a 200 — is the
//     spec's "list of rejected push keys" the caller MUST stop sending to
//     and remove the associated pushers for. This client never touches the
//     database itself; the caller owns acting on the rejection.
struct PushGatewayResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    std::vector<std::string> rejected_pushkeys{};
    http::OutboundError error{http::OutboundError::network_error};
    std::string error_detail{};
};

// Test-only override for one push-gateway host. Mirrors
// identity::TestForcedIdentityResolution's contract exactly (see that type's
// doc comment for the rationale): when a caller supplies a non-null map and
// it has an entry keyed by the gateway URL's host, PushGatewayClient::notify()
// uses these pinned addresses and in-memory CA bundle instead of SSRF-safe
// discovery. Always empty in production; no production construction path
// populates it. Exists so integration tests can drive a real local HTTPS
// gateway (self-signed certificate, loopback address) without weakening the
// production SSRF/discovery boundary in push_gateway_client.cpp.
struct TestForcedPushGatewayResolution final
{
    std::vector<std::string> pinned_addresses{};
    std::string trusted_ca_pem{};
};

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
    PushGatewayClient(
        http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery, config::PushConfig const& config,
        std::map<std::string, TestForcedPushGatewayResolution> const* forced_resolution = nullptr) noexcept;

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
};

} // namespace merovingian::push
