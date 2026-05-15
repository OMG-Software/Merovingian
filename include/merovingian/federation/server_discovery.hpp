// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

struct ServerDiscoveryResult final
{
    std::string server_name{};
    std::string resolved_host{};
    std::uint16_t resolved_port{8448U};
    bool tls_required{true};
    bool discovery_allowed{false};
    std::string reason{};
};

struct FederationDestination final
{
    std::string server_name{};
    std::uint64_t retry_after_ts{0U};
    std::uint64_t last_success_ts{0U};
    std::uint32_t consecutive_failures{0U};
    std::string state{"idle"};
};

[[nodiscard]] auto discover_server(std::string_view server_name, std::string_view well_known_server)
    -> ServerDiscoveryResult;

} // namespace merovingian::federation