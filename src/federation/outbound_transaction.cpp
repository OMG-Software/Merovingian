// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/outbound_transaction.hpp"

#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <cmath>
#include <string>
#include <vector>

namespace merovingian::federation
{

namespace
{

    constexpr auto base_retry_interval_ms = std::uint64_t{2000U};
    constexpr auto max_retry_interval_ms = std::uint64_t{300000U};
    constexpr auto max_consecutive_failures_before_circuit_open = std::uint32_t{3U};

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("outbound_transaction", event, std::move(fields)));
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
        auto signature = make_federation_signature(call.transaction.origin, call.transaction.destination,
                                                   call.transaction.method, call.transaction.target,
                                                   call.transaction.body, call.secret_key);
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

auto compute_backoff(std::uint32_t retry_count) noexcept -> std::uint64_t
{
    if (retry_count == 0U)
    {
        return base_retry_interval_ms;
    }
    auto const exponential = static_cast<std::uint64_t>(static_cast<double>(base_retry_interval_ms) *
                                                        std::pow(2.0, static_cast<double>(retry_count)));
    return exponential > max_retry_interval_ms ? max_retry_interval_ms : exponential;
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
                       {{"destination",          call.transaction.destination,                         false},
                        {"target",               call.transaction.target,                              false},
                        {"consecutive_failures", std::to_string(destination.consecutive_failures),    false},
                        {"retry_after_ts",       std::to_string(destination.retry_after_ts),          false}});
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
        log_diagnostic("transaction.delivered",
                       {{"destination", call.transaction.destination,              false},
                        {"method",      call.transaction.method,                   false},
                        {"target",      call.transaction.target,                   false},
                        {"http_status", std::to_string(result.http_status),        false}});
    }
    else
    {
        log_diagnostic("transaction.failed",
                       {{"destination", call.transaction.destination,              false},
                        {"method",      call.transaction.method,                   false},
                        {"target",      call.transaction.target,                   false},
                        {"http_status", std::to_string(result.http_status),        false},
                        {"error",       result.error,                              false},
                        {"failures",    std::to_string(destination.consecutive_failures), false}});
    }

    return result;
}

} // namespace merovingian::federation
