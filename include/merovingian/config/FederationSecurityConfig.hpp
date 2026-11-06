// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/FederationBackfillConfig.hpp"
#include "merovingian/config/FederationQueryConfig.hpp"
#include "merovingian/config/FederationStateResolutionConfig.hpp"
#include "merovingian/http/rate_limit.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::config
{

struct FederationSecurityConfig final
{
    FederationQueryConfig query{};
    FederationStateResolutionConfig state_resolution{};
    bool enabled{true};
    std::string default_policy{"allow"};
    std::vector<std::string> allowed_servers{};
    std::vector<std::string> denied_servers{};
    bool require_valid_tls{true};
    bool verify_json_signatures{true};
    std::vector<std::string> deny_ip_ranges{
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7",
    };
    // The one exception to the private-address block (ADR-0231): RFC 1918 and
    // ULA networks, named as CIDRs, that federation may reach. Each entry must
    // pass private_ip_range_is_allowable(). Empty by default; meant for test
    // harnesses such as Complement and private federations on a LAN or VPN.
    std::vector<std::string> allow_private_ip_ranges{};
    std::string max_transaction_size{"20MiB"};
    // Matrix Server-Server API v1.19 caps /send transactions at 50 PDUs
    // and 100 EDUs. Operators may lower these caps but validation rejects
    // values above the spec maximum.
    std::uint32_t max_transaction_pdus{50U};
    std::uint32_t max_transaction_edus{100U};
    // Authenticated inbound federation pressure caps. These are keyed by the
    // verified remote origin, not by client IP or claimed event sender.
    http::RateLimitPolicy per_origin_transaction_rate{600U, 60U};
    http::RateLimitPolicy per_origin_pdu_rate{6000U, 60U};
    http::RateLimitPolicy per_origin_edu_rate{12000U, 60U};
    // Per-origin cap on inbound federation requests OUTSIDE /send (query,
    // backfill, membership, key and state endpoints). /send keeps its own
    // weighted transaction/PDU/EDU trio above and is exempt so a transaction
    // and its contents are never double-counted.
    http::RateLimitPolicy per_origin_request_rate{3000U, 60U};
    // Budgets for remote signing-key resolution, which necessarily happens
    // BEFORE a request's X-Matrix signature can be checked -- verifying the
    // signature requires the key. Without a budget, an unauthenticated sender
    // can name any origin in an X-Matrix header and make this server perform
    // .well-known + SRV + DNS discovery and an outbound GET
    // /_matrix/key/v2/server against a host of their choosing: a DoS surface
    // here and a reflection vector at the named third party. Unlike the
    // per_origin_* budgets above, these are keyed on the source IP, because
    // the origin is precisely the field the attacker controls and varies.
    //
    // `security.federation.default_policy=deny` with a populated
    // `allowed_servers` list closes this independently -- the policy check runs
    // before resolution -- so allow-list deployments are unaffected either way.
    //
    // key_resolution_per_ip_rate bounds how often one source IP may cause a
    // resolution of an origin this server has no usable cached key for.
    http::RateLimitPolicy key_resolution_per_ip_rate{30U, 60U};
    // Cap on resolutions in flight across the whole process, so a sender
    // spreading across many source IPs still cannot exhaust the outbound path.
    // Over the cap the request is rejected rather than queued: queuing converts
    // an overload into a slower overload while holding the resources anyway.
    // Must be >= 1 (validated); 0 would deadlock every resolution.
    std::uint32_t key_resolution_max_in_flight{16U};
    // How long a failed resolution is remembered, so repeated requests naming
    // the same unresolvable origin are cheap. Bounds the honest-misconfiguration
    // case; a sender varying the origin defeats it by design, which is what the
    // two budgets above are for. "0s" disables the negative cache.
    std::string key_resolution_failure_ttl{"60s"};
    FederationBackfillConfig backfill{};
    std::uint32_t accepted_transaction_cache_entries{50000U};
    std::uint32_t audit_event_cache_entries{10000U};
    std::uint32_t key_resolution_cache_entries{16384U};
    std::uint32_t bad_signature_cache_entries{4096U};
    http::RateLimitPolicy bad_signature_per_ip_rate{30U, 60U};
    std::uint32_t pending_join_max_rooms{32U};
    std::uint32_t pending_join_max_pdus{32U};
    std::string pending_join_max_size{"512KiB"};
    std::uint32_t outbound_queue_capacity{4096U};
    std::uint32_t outbound_max_retries{32U};
    std::uint32_t outbound_delivery_threads{4U};
    std::string remote_timeout{"60s"};
    // Separate, extendable budget for the make_join/send_join/make_leave/send_leave
    // membership dance. A large remote room's make_join can take longer than the
    // 60s general federation timeout; this is distinct from `remote_timeout`.
    std::string join_timeout{"180s"};
    // Cap on concurrent make_join candidate probes and inbound sender-key fan-out.
    // Must be >= 1 (validated); 0 would degenerate to no work.
    std::uint32_t join_parallelism{8U};
    // Overall wall-clock budget for the whole make_join race across ALL candidates,
    // independent of the per-candidate `join_timeout`. Without this, a large `via`
    // list races in batches of `join_parallelism` and can take many minutes even
    // though each individual candidate stays within its own budget — long after the
    // calling client's own HTTP request has timed out. Candidates still in flight
    // when the deadline is reached are moved to `orphan_futures_` to finish in the
    // background, same as when a candidate loses to a winner.
    std::string join_race_deadline{"45s"};
    // Hard cap on the number of via-derived candidates actually raced. Every
    // candidate is spawned as an OS thread immediately (throttled to run by
    // `join_parallelism`, but not to spawn), so an unbounded `via` list means
    // unbounded upfront thread creation. Must be >= 1 (validated).
    std::uint32_t join_max_candidates{20U};
    // Cap on concurrent remote signing-key resolutions when verifying the
    // signatures of events in a send_join response's `state`/`auth_chain`
    // arrays (one m.room.member per room member — thousands for a large
    // room). Distinct (sender_domain, key_id) pairs are deduplicated before
    // this cap is applied, so it bounds concurrent *distinct home servers*
    // contacted, not concurrent events. Must be >= 1 (validated).
    std::uint32_t join_state_key_parallelism{100U};
    // Response body cap applied specifically to make_join/send_join, distinct
    // from the general 16 MiB http::OutboundRequest default. A send_join
    // response embeds the room's full current state (one m.room.member per
    // member) plus the auth chain; for a genuinely large room (tens of
    // thousands of members) this routinely exceeds 16 MiB and the call was
    // rejected outright with `response_too_large` even after join_timeout
    // gave it enough wall-clock time. Restart required: this also sizes the
    // federation-worker IPC frame cap, which is fixed at worker spawn time
    // (see reload_policy.cpp).
    std::string join_response_max_size{"64MiB"};
};

} // namespace merovingian::config
