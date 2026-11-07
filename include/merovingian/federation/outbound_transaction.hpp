// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/federation/FederationDestination.hpp"
#include "merovingian/federation/OutboundCall.hpp"
#include "merovingian/federation/OutboundTransaction.hpp"
#include "merovingian/federation/OutboundTransactionResult.hpp"
#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/http/OutboundRequest.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Generates an opaque Matrix federation transaction ID suitable for
// /_matrix/federation/v1/send/{txnId}. The value is intentionally decoupled
// from local session counters so restarts cannot cause peers to deduplicate a
// fresh transaction as a replay of an older one.
[[nodiscard]] auto make_federation_transaction_id() -> std::string;

[[nodiscard]] auto make_outbound_transaction(std::string_view destination, std::string_view method,
                                             std::string_view target, std::string_view origin, std::string_view body)
    -> OutboundTransaction;

// Builds the canonical-JSON body of a federation /send transaction carrying a
// single EDU and no PDUs. Pure function; performs no network I/O. The body
// includes the Matrix-required top-level `origin`, `origin_server_ts`, empty
// `pdus`, and one-entry `edus` array. The EDU is keyed by "edu_type" (per the
// Matrix federation spec, NOT "type") so receivers such as Synapse do not
// reject the entire transaction with a missing-field error. `edu_content_json`
// is parsed and re-serialized canonically; invalid content or a serialization
// failure yields std::nullopt.
[[nodiscard]] auto build_edu_transaction_body(std::string_view origin, std::string_view edu_type,
                                              std::string_view edu_content_json) -> std::optional<std::string>;

// Builds a PUT /send/{txnId} body carrying one PDU (`pdu_json`, re-serialized canonically)
// with the Matrix-required top-level `origin` and `origin_server_ts`, and an empty `edus`
// array. An empty origin or a PDU that is not a JSON object yields std::nullopt.
[[nodiscard]] auto build_pdu_transaction_body(std::string_view origin, std::string_view pdu_json)
    -> std::optional<std::string>;

// Builds the canonical-JSON *content* of an m.receipt EDU per Matrix spec
// §receipts. Shape: { roomId: { receiptType: { userId: { event_ids: [eventId],
// data: { ts: N, thread_id: T } } } } }; `thread_id` is omitted for an
// unthreaded receipt (empty `thread_id`). Pure function; returns std::nullopt on
// serialization failure.
[[nodiscard]] auto build_receipt_edu_content(std::string_view room_id, std::string_view receipt_type,
                                             std::string_view user_id, std::string_view event_id, std::int64_t ts,
                                             std::string_view thread_id = {}) -> std::optional<std::string>;

[[nodiscard]] auto compute_backoff(std::uint32_t retry_count) noexcept -> std::uint64_t;

[[nodiscard]] auto destination_should_retry(FederationDestination const& destination, std::uint64_t now_ts) noexcept
    -> bool;

// Builds the OutboundRequest the HTTP client should send for the given call.
// Pure function; performs no DNS, TLS, or network I/O. The returned request
// carries the URL (https://<resolved_host>:<resolved_port><target>), the
// caller-pinned addresses for SSRF defense, the request body verbatim, and
// the X-Matrix Authorization header derived through
// `make_federation_signature`.
[[nodiscard]] auto build_outbound_request(OutboundCall const& call) -> http::OutboundRequest;

// A transaction was delivered, but the attempt took long enough to count against the destination
// (F-20, ADR-0354): its backoff grows from `failures_before`, the count before this attempt.
auto apply_slow_success(FederationDestination& destination, std::uint32_t failures_before,
                        std::uint64_t now_ts) noexcept -> void;

// Updates the federation destination retry state based on a call result.
// A 2xx response clears the failure counter and records last_success_ts.
// Any other outcome increments the failure counter and sets retry_after_ts
// to `now_ts + compute_backoff(consecutive_failures)`.
auto apply_outbound_result(FederationDestination& destination, OutboundTransactionResult const& result,
                           std::uint64_t now_ts) noexcept -> void;

// Executes a single attempt against the destination. Returns early with
// `error == "circuit_open"` and no network I/O when
// `destination_should_retry` rejects the attempt. Otherwise calls
// `client.perform()` and applies the result through `apply_outbound_result`.
// `now_ts` gates the attempt (destination backoff). `finished_clock`, when given, is read after the
// exchange and is when a failure's backoff starts (ADR-0309): an attempt can take longer than the
// backoff, and counted from its start the destination would be due again the moment it failed.
[[nodiscard]] auto perform_outbound_transaction(http::OutboundClient& client, OutboundCall const& call,
                                                FederationDestination& destination, std::uint64_t now_ts,
                                                std::function<std::uint64_t()> const& finished_clock = {})
    -> OutboundTransactionResult;

} // namespace merovingian::federation
