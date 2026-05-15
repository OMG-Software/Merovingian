// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/outbound_transaction.hpp"

#include <cmath>

namespace merovingian::federation
{

namespace
{

    constexpr auto base_retry_interval_ms = std::uint64_t{2000U};
    constexpr auto max_retry_interval_ms = std::uint64_t{300000U};
    constexpr auto max_consecutive_failures_before_circuit_open = std::uint32_t{3U};

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

} // namespace merovingian::federation