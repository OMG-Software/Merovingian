// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/outbound_transaction.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <sodium.h>

namespace merovingian::federation
{

namespace
{

    constexpr auto base_retry_interval_ms = std::uint64_t{2000U};
    constexpr auto max_retry_interval_ms = std::uint64_t{300000U};
    constexpr auto max_consecutive_failures_before_circuit_open = std::uint32_t{3U};

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("outbound_transaction", event, fields, severity);
    }

    [[nodiscard]] auto build_url(OutboundCall const& call) -> std::string
    {
        auto url = std::string{"https://"};
        // IPv6 literals contain colons that would collide with the port separator
        // in the URL authority, so they must be bracketed per RFC 3986.
        auto const needs_brackets =
            call.resolved_host.find(':') != std::string::npos && call.resolved_host.front() != '[';
        if (needs_brackets)
        {
            url += '[';
        }
        url += call.resolved_host;
        if (needs_brackets)
        {
            url += ']';
        }
        // Always include the port so CURLOPT_RESOLVE entries match the URL
        // authority. Matrix federation defaults to 8448 anyway, so the URL
        // is rarely shorter without it.
        url += ':';
        url += std::to_string(call.resolved_port);
        url += call.transaction.target;
        return url;
    }

    [[nodiscard]] auto build_authorization_header(OutboundCall const& call) -> std::string
    {
        // X-Matrix authorization header per the Matrix federation spec. The
        // signature is produced through the same primitive the inbound
        // verifier uses so the project speaks a single signing scheme.
        auto signature =
            make_federation_signature(call.transaction.origin, call.transaction.destination, call.transaction.method,
                                      call.transaction.target, call.transaction.body, call.secret_key);
        auto header = std::string{"X-Matrix origin=\""};
        header += call.transaction.origin;
        header += "\",destination=\"";
        header += call.transaction.destination;
        header += "\",key=\"";
        header += call.key_id;
        header += "\",sig=\"";
        header += signature;
        header += '"';
        return header;
    }

    [[nodiscard]] auto status_is_success(std::uint16_t status) noexcept -> bool
    {
        return status >= 200U && status < 300U;
    }

} // namespace

auto make_outbound_transaction(std::string_view destination, std::string_view method, std::string_view target,
                               std::string_view origin, std::string_view body) -> OutboundTransaction
{
    auto transaction = OutboundTransaction{};
    transaction.destination = destination;
    transaction.method = method;
    transaction.target = target;
    transaction.origin = origin;
    transaction.body = body;
    return transaction;
}

auto make_federation_transaction_id() -> std::string
{
    if (sodium_init() < 0)
    {
        return {};
    }
    auto bytes = std::array<unsigned char, 16U>{};
    randombytes_buf(bytes.data(), bytes.size());
    auto output = std::string(bytes.size() * 2U + 1U, '\0');
    std::ignore = sodium_bin2hex(output.data(), output.size(), bytes.data(), bytes.size());
    output.pop_back();
    return output;
}

auto build_edu_transaction_body(std::string_view origin, std::string_view edu_type, std::string_view edu_content_json)
    -> std::optional<std::string>
{
    if (origin.empty())
    {
        return std::nullopt;
    }
    auto edu_value = canonicaljson::parse_lossless(edu_content_json);
    if (edu_value.error != canonicaljson::ParseError::none)
    {
        return std::nullopt;
    }

    // Matrix federation transactions key each EDU by "edu_type" (not "type").
    // Synapse reads edu["edu_type"] and raises KeyError otherwise, rejecting the
    // entire transaction (PDUs included) with HTTP 500 — so the wrong key silently
    // breaks all outbound typing/receipt/to-device delivery.
    auto edu_obj = canonicaljson::Object{};
    edu_obj.push_back(canonicaljson::make_member("edu_type", canonicaljson::Value{std::string{edu_type}}));
    edu_obj.push_back(canonicaljson::make_member("content", std::move(edu_value.value)));

    auto edus_array = canonicaljson::Array{};
    edus_array.push_back(canonicaljson::Value{std::move(edu_obj)});

    auto tx_root = canonicaljson::Object{};
    auto const now_ms = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    tx_root.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{origin}}));
    tx_root.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{now_ms}));
    tx_root.push_back(canonicaljson::make_member("pdus", canonicaljson::Value{canonicaljson::Array{}}));
    tx_root.push_back(canonicaljson::make_member("edus", canonicaljson::Value{std::move(edus_array)}));

    auto const tx_body = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(tx_root)});
    if (tx_body.error != canonicaljson::CanonicalJsonError::none)
    {
        return std::nullopt;
    }
    return tx_body.output;
}

auto build_receipt_edu_content(std::string_view room_id, std::string_view receipt_type, std::string_view user_id,
                               std::string_view event_id, std::int64_t ts) -> std::optional<std::string>
{
    // Matrix spec receipt EDU content shape (per §receipts):
    // { roomId: { receiptType: { userId: { event_ids: [eventId], data: { ts: N } } } } }
    auto receipt_data = canonicaljson::Object{};
    receipt_data.push_back(canonicaljson::make_member("ts", canonicaljson::Value{ts}));

    auto user_obj = canonicaljson::Object{};
    user_obj.push_back(canonicaljson::make_member("data", canonicaljson::Value{std::move(receipt_data)}));
    user_obj.push_back(canonicaljson::make_member(
        "event_ids", canonicaljson::Value{canonicaljson::Array{canonicaljson::Value{std::string{event_id}}}}));

    auto receipt_type_users = canonicaljson::Object{};
    receipt_type_users.push_back(
        canonicaljson::make_member(std::string{user_id}, canonicaljson::Value{std::move(user_obj)}));

    auto room_obj = canonicaljson::Object{};
    room_obj.push_back(
        canonicaljson::make_member(std::string{receipt_type}, canonicaljson::Value{std::move(receipt_type_users)}));

    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member(std::string{room_id}, canonicaljson::Value{std::move(room_obj)}));

    auto const result = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(content)});
    if (result.error != canonicaljson::CanonicalJsonError::none)
    {
        return std::nullopt;
    }
    return result.output;
}

auto compute_backoff(std::uint32_t retry_count) noexcept -> std::uint64_t
{
    auto interval = base_retry_interval_ms;
    if (retry_count == 0U)
    {
        return interval;
    }
    for (auto attempt = std::uint32_t{0U}; attempt < retry_count; ++attempt)
    {
        if (interval >= max_retry_interval_ms)
        {
            return max_retry_interval_ms;
        }
        if (interval > max_retry_interval_ms / 2U)
        {
            return max_retry_interval_ms;
        }
        interval *= 2U;
    }
    return interval;
}

auto destination_should_retry(FederationDestination const& destination, std::uint64_t now_ts) noexcept -> bool
{
    if (destination.consecutive_failures >= max_consecutive_failures_before_circuit_open)
    {
        if (now_ts < destination.retry_after_ts)
        {
            return false;
        }
    }
    if (now_ts < destination.retry_after_ts)
    {
        return false;
    }
    return true;
}

auto build_outbound_request(OutboundCall const& call) -> http::OutboundRequest
{
    auto request = http::OutboundRequest{};
    request.method = call.transaction.method;
    request.url = build_url(call);
    request.body = call.transaction.body;
    request.pinned_addresses = call.pinned_addresses;
    request.connect_timeout_seconds = call.connect_timeout_seconds;
    request.total_timeout_seconds = call.total_timeout_seconds;
    request.headers.push_back(http::OutboundHeader{"Authorization", build_authorization_header(call)});
    request.headers.push_back(http::OutboundHeader{"Content-Type", "application/json"});
    return request;
}

auto apply_outbound_result(FederationDestination& destination, OutboundTransactionResult const& result,
                           std::uint64_t now_ts) noexcept -> void
{
    if (result.sent && status_is_success(result.http_status))
    {
        destination.consecutive_failures = 0U;
        destination.last_success_ts = now_ts;
        destination.retry_after_ts = 0U;
        destination.state = "ok";
        return;
    }
    destination.consecutive_failures = destination.consecutive_failures + 1U;
    destination.retry_after_ts = now_ts + compute_backoff(destination.consecutive_failures);
    destination.state = "backoff";
}

auto perform_outbound_transaction(http::OutboundClient& client, OutboundCall const& call,
                                  FederationDestination& destination, std::uint64_t now_ts) -> OutboundTransactionResult
{
    if (!destination_should_retry(destination, now_ts))
    {
        log_diagnostic("transaction.circuit_open",
                       {
                           {"destination",          call.transaction.destination,                     false},
                           {"target",               call.transaction.target,                          false},
                           {"consecutive_failures", std::to_string(destination.consecutive_failures), false},
                           {"retry_after_ts",       std::to_string(destination.retry_after_ts),       false}
        });
        return OutboundTransactionResult{false, std::uint16_t{0U}, std::string{}, std::string{"circuit_open"}};
    }

    auto const request = build_outbound_request(call);
    auto const outcome = client.perform(request);

    auto result = OutboundTransactionResult{};
    result.sent = outcome.ok;
    result.http_status = outcome.response.status;
    result.response_body = outcome.response.body;
    result.error = outcome.ok ? std::string{} : std::string{http::outbound_error_name(outcome.error)};

    apply_outbound_result(destination, result, now_ts);

    if (result.sent && status_is_success(result.http_status))
    {
        log_diagnostic("transaction.delivered", {
                                                    {"destination", call.transaction.destination,       false},
                                                    {"method",      call.transaction.method,            false},
                                                    {"target",      call.transaction.target,            false},
                                                    {"http_status", std::to_string(result.http_status), false}
        });
    }
    else
    {
        log_diagnostic("transaction.failed",
                       {
                           {"destination",   call.transaction.destination,                     false},
                           {"method",        call.transaction.method,                          false},
                           {"target",        call.transaction.target,                          false},
                           {"http_status",   std::to_string(result.http_status),               false},
                           {"error",         result.error,                                     false},
                           {"response_body", result.response_body,                             false},
                           {"failures",      std::to_string(destination.consecutive_failures), false}
        });
    }

    return result;
}

} // namespace merovingian::federation
