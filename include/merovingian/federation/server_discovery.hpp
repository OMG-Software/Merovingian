// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

struct WellKnownServerResult final
{
    bool found{false};
    bool ok{false};
    std::string body{};
    std::string reason{};
};

struct SrvRecord final
{
    std::string target{};
    std::uint16_t port{8448U};
    std::uint16_t priority{0U};
    std::uint16_t weight{0U};
};

struct ResolvedAddressSet final
{
    bool ok{false};
    std::vector<std::string> addresses{};
    std::string reason{};
};

struct ServerDiscoveryResult final
{
    std::string server_name{};
    std::string well_known_host{};
    std::string resolved_host{};
    std::uint16_t resolved_port{8448U};
    std::vector<std::string> pinned_addresses{};
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

class ServerDiscoveryNetwork
{
public:
    ServerDiscoveryNetwork() = default;
    virtual ~ServerDiscoveryNetwork() = default;

    ServerDiscoveryNetwork(ServerDiscoveryNetwork const&) = delete;
    auto operator=(ServerDiscoveryNetwork const&) -> ServerDiscoveryNetwork& = delete;
    ServerDiscoveryNetwork(ServerDiscoveryNetwork&&) noexcept = delete;
    auto operator=(ServerDiscoveryNetwork&&) noexcept -> ServerDiscoveryNetwork& = delete;

    [[nodiscard]] virtual auto fetch_well_known(std::string_view server_name, std::uint32_t timeout_seconds)
        -> WellKnownServerResult = 0;
    [[nodiscard]] virtual auto lookup_srv(std::string_view service_name) -> std::vector<SrvRecord> = 0;
    [[nodiscard]] virtual auto lookup_addresses(std::string_view host, std::uint16_t port) -> ResolvedAddressSet = 0;
};

[[nodiscard]] auto discover_server(std::string_view server_name, std::string_view well_known_server)
    -> ServerDiscoveryResult;
[[nodiscard]] auto discover_server(std::string_view server_name, ServerDiscoveryNetwork& network,
                                   std::uint32_t timeout_seconds) -> ServerDiscoveryResult;
[[nodiscard]] auto discover_server(std::string_view server_name) -> ServerDiscoveryResult;

// Creates a production ServerDiscoveryNetwork backed by real DNS and
// HTTP well-known lookups. Used by start_runtime to wire the remote key
// resolver and outbound membership fetch paths.
[[nodiscard]] auto make_system_server_discovery_network() -> std::unique_ptr<ServerDiscoveryNetwork>;

} // namespace merovingian::federation
