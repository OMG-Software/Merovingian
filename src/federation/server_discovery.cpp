// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/server_discovery.hpp"

#include "merovingian/federation/security.hpp"

#include <string>
#include <string_view>

namespace merovingian::federation
{

namespace
{

    [[nodiscard]] auto extract_host_and_port(std::string_view url) -> std::pair<std::string, std::uint16_t>
    {
        auto constexpr https_prefix = std::string_view{"https://"};
        auto constexpr http_prefix = std::string_view{"http://"};
        auto host = std::string{};
        auto port = std::uint16_t{8448U};

        auto start = std::size_t{0U};
        if (url.starts_with(https_prefix))
        {
            start = https_prefix.size();
        }
        else if (url.starts_with(http_prefix))
        {
            start = http_prefix.size();
            port = 8008U;
        }
        else
        {
            start = 0U;
        }

        auto const colon_pos = url.find(':', start);
        auto const slash_pos = url.find('/', start);
        auto const end = (colon_pos != std::string_view::npos && colon_pos < slash_pos) ? colon_pos : slash_pos;

        if (end != std::string_view::npos)
        {
            host = url.substr(start, end - start);
        }
        else
        {
            host = url.substr(start);
        }

        if (colon_pos != std::string_view::npos &&
            colon_pos < (slash_pos != std::string_view::npos ? slash_pos : url.size()))
        {
            auto const port_start = colon_pos + 1U;
            auto const port_end = slash_pos != std::string_view::npos ? slash_pos : url.size();
            auto port_str = std::string{url.substr(port_start, port_end - port_start)};
            try
            {
                port = static_cast<std::uint16_t>(std::stoul(port_str));
            }
            catch (...)
            {
                port = 8448U;
            }
        }

        return {host, port};
    }

} // namespace

auto discover_server(std::string_view server_name, std::string_view well_known_server) -> ServerDiscoveryResult
{
    auto result = ServerDiscoveryResult{};
    result.server_name = server_name;

    if (server_name.empty())
    {
        result.discovery_allowed = false;
        result.reason = "server name is empty";
        return result;
    }

    if (!server_name_is_valid(server_name))
    {
        result.discovery_allowed = false;
        result.reason = "server name is invalid";
        return result;
    }

    if (well_known_server.empty())
    {
        result.resolved_host = server_name;
        result.resolved_port = 8448U;
        result.tls_required = true;
        result.discovery_allowed = true;
        return result;
    }

    auto const [host, port] = extract_host_and_port(well_known_server);
    result.resolved_host = host;
    result.resolved_port = port;
    result.tls_required = (port != 8008U);

    if (ip_address_is_private_or_loopback(result.resolved_host))
    {
        result.discovery_allowed = false;
        result.reason = "resolved address is a private or loopback IP address";
        return result;
    }

    result.discovery_allowed = true;
    return result;
}

} // namespace merovingian::federation