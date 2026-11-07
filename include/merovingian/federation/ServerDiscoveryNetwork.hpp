// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/ResolvedAddressSet.hpp"
#include "merovingian/federation/SrvRecord.hpp"
#include "merovingian/federation/WellKnownServerResult.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::federation
{

class ServerDiscoveryNetwork
{
public:
    explicit ServerDiscoveryNetwork(std::vector<std::string> denied_ip_ranges = {},
                                    std::vector<std::string> allowed_private_ip_ranges = {})
        : denied_ip_ranges_{std::move(denied_ip_ranges)}
        , allowed_private_ip_ranges_{std::move(allowed_private_ip_ranges)}
    {
    }

    // Immutable operator policy shared by every cached/uncached discovery path.
    [[nodiscard]] auto denied_ip_ranges() const noexcept -> std::vector<std::string> const&
    {
        return denied_ip_ranges_;
    }

    // security.federation.allow_private_ip_ranges (ADR-0231). Applied by
    // discover_server, well-known fetches and the cache, which only federation
    // uses; resolve_federation_destination applies it only when the caller
    // passes it, so URL preview sharing this network never gets it.
    [[nodiscard]] auto allowed_private_ip_ranges() const noexcept -> std::vector<std::string> const&
    {
        return allowed_private_ip_ranges_;
    }
    virtual ~ServerDiscoveryNetwork() = default;

    ServerDiscoveryNetwork(ServerDiscoveryNetwork const&) = delete;
    auto operator=(ServerDiscoveryNetwork const&) -> ServerDiscoveryNetwork& = delete;
    ServerDiscoveryNetwork(ServerDiscoveryNetwork&&) noexcept = delete;
    auto operator=(ServerDiscoveryNetwork&&) noexcept -> ServerDiscoveryNetwork& = delete;

    [[nodiscard]] virtual auto fetch_well_known(std::string_view server_name, std::uint32_t timeout_seconds)
        -> WellKnownServerResult = 0;
    [[nodiscard]] virtual auto lookup_srv(std::string_view service_name) -> std::vector<SrvRecord> = 0;
    [[nodiscard]] virtual auto lookup_addresses(std::string_view host, std::uint16_t port) -> ResolvedAddressSet = 0;

private:
    std::vector<std::string> denied_ip_ranges_{};
    std::vector<std::string> allowed_private_ip_ranges_{};
};

} // namespace merovingian::federation
