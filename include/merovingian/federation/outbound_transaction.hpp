// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/federation/server_discovery.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::federation
{

struct OutboundTransaction final
{
    std::string transaction_id{};
    std::string destination{};
    std::string method{"PUT"};
    std::string target{};
    std::string origin{};
    std::string origin_server_ts{};
    std::string body{};
    std::uint32_t retry_count{0U};
    std::uint64_t next_retry_ts{0U};
};

struct OutboundTransactionResult final
{
    bool sent{false};
    std::uint16_t http_status{0U};
    std::string response_body{};
    std::string error{};
};

[[nodiscard]] auto make_outbound_transaction(std::string_view destination, std::string_view method,
                                             std::string_view target, std::string_view origin, std::string_view body)
    -> OutboundTransaction;

[[nodiscard]] auto compute_backoff(std::uint32_t retry_count) noexcept -> std::uint64_t;

[[nodiscard]] auto destination_should_retry(FederationDestination const& destination, std::uint64_t now_ts) noexcept
    -> bool;

} // namespace merovingian::federation