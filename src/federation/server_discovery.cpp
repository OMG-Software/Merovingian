// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/server_discovery.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("server_discovery", event, std::move(fields)));
    }

    auto constexpr default_federation_port = std::uint16_t{8448U};
    auto constexpr default_https_port = std::uint16_t{443U};

    struct HostPort final
    {
        std::string host{};
        std::uint16_t port{default_federation_port};
        bool port_explicit{false};
    };

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto host_is_numeric_ip(std::string_view host) noexcept -> bool
    {
        auto v4 = in_addr{};
        auto v6 = in6_addr{};
        auto const text = std::string{host};
        return ::inet_pton(AF_INET, text.c_str(), &v4) == 1 || ::inet_pton(AF_INET6, text.c_str(), &v6) == 1;
    }

    [[nodiscard]] auto parse_port(std::string_view text) noexcept -> std::optional<std::uint16_t>
    {
        auto port = std::uint16_t{0U};
        auto const* begin = text.data();
        auto const* end = text.data() + text.size();
        auto const parsed = std::from_chars(begin, end, port);
        if (parsed.ec != std::errc{} || parsed.ptr != end || port == 0U)
        {
            return std::nullopt;
        }
        return port;
    }

    [[nodiscard]] auto parse_host_port(std::string_view value, std::uint16_t default_port) -> std::optional<HostPort>
    {
        if (value.empty())
        {
            return std::nullopt;
        }
        if (value.front() == '[')
        {
            auto const close = value.find(']');
            if (close == std::string_view::npos || close == 1U)
            {
                return std::nullopt;
            }
            auto port = default_port;
            auto port_explicit = false;
            if (close + 1U < value.size())
            {
                if (value[close + 1U] != ':')
                {
                    return std::nullopt;
                }
                auto const parsed_port = parse_port(value.substr(close + 2U));
                if (!parsed_port.has_value())
                {
                    return std::nullopt;
                }
                port = *parsed_port;
                port_explicit = true;
            }
            return HostPort{std::string{value.substr(1U, close - 1U)}, port, port_explicit};
        }

        auto const colon = value.rfind(':');
        if (colon != std::string_view::npos && value.find(':') == colon)
        {
            auto const parsed_port = parse_port(value.substr(colon + 1U));
            if (!parsed_port.has_value())
            {
                return std::nullopt;
            }
            if (colon == 0U)
            {
                return std::nullopt;
            }
            return HostPort{std::string{value.substr(0U, colon)}, *parsed_port, true};
        }

        return HostPort{std::string{value}, default_port, false};
    }

    [[nodiscard]] auto extract_host_and_port(std::string_view url) -> std::optional<HostPort>
    {
        auto port = default_federation_port;
        auto start = std::size_t{0U};
        if (starts_with(url, "https://"))
        {
            start = std::string_view{"https://"}.size();
            port = default_federation_port;
        }
        else if (starts_with(url, "http://"))
        {
            start = std::string_view{"http://"}.size();
            port = 8008U;
        }

        auto const slash = url.find('/', start);
        auto const authority = slash == std::string_view::npos ? url.substr(start) : url.substr(start, slash - start);
        return parse_host_port(authority, port);
    }

    [[nodiscard]] auto canonical_object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto extract_m_server(std::string_view body) -> std::optional<std::string>
    {
        auto const parsed = canonicaljson::parse_lossless(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* m_server = canonical_object_member(*object, "m.server");
        if (m_server == nullptr)
        {
            return std::nullopt;
        }
        auto const* text = std::get_if<std::string>(&m_server->storage());
        if (text == nullptr || text->empty())
        {
            return std::nullopt;
        }
        return *text;
    }

    [[nodiscard]] auto address_set_allowed(std::vector<std::string> const& addresses) noexcept -> bool
    {
        return !addresses.empty() && std::ranges::none_of(addresses, [](std::string const& address) {
            return ip_address_is_private_or_loopback(address);
        });
    }

    [[nodiscard]] auto resolve_destination(std::string_view server_name, HostPort host_port,
                                           ServerDiscoveryNetwork& network) -> ServerDiscoveryResult
    {
        auto result = ServerDiscoveryResult{};
        result.server_name = server_name;
        result.resolved_host = std::move(host_port.host);
        result.resolved_port = host_port.port;
        result.tls_required = result.resolved_port != 8008U;

        if (result.resolved_host.empty())
        {
            result.reason = "resolved host is empty";
            return result;
        }
        if (host_is_numeric_ip(result.resolved_host) && ip_address_is_private_or_loopback(result.resolved_host))
        {
            result.reason = "resolved address is a private or loopback IP address";
            return result;
        }

        auto addresses = network.lookup_addresses(result.resolved_host, result.resolved_port);
        if (!addresses.ok)
        {
            result.reason = addresses.reason.empty() ? "resolved host has no addresses" : addresses.reason;
            return result;
        }
        if (!address_set_allowed(addresses.addresses))
        {
            result.reason = "resolved address is a private or loopback IP address";
            return result;
        }

        result.pinned_addresses = std::move(addresses.addresses);
        result.discovery_allowed = true;
        return result;
    }

    [[nodiscard]] auto sort_srv_records(std::vector<SrvRecord> records) -> std::vector<SrvRecord>
    {
        std::ranges::sort(records, [](SrvRecord const& lhs, SrvRecord const& rhs) {
            if (lhs.priority != rhs.priority)
            {
                return lhs.priority < rhs.priority;
            }
            return lhs.weight > rhs.weight;
        });
        return records;
    }

    class LiteralDiscoveryNetwork final : public ServerDiscoveryNetwork
    {
    public:
        [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t) -> WellKnownServerResult override
        {
            return {};
        }

        [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<SrvRecord> override
        {
            return {};
        }

        [[nodiscard]] auto lookup_addresses(std::string_view host, std::uint16_t) -> ResolvedAddressSet override
        {
            if (host_is_numeric_ip(host))
            {
                return {true, {std::string{host}}, {}};
            }
            return {true, {"203.0.113.10"}, {}};
        }
    };

    class AddrInfoGuard final
    {
    public:
        explicit AddrInfoGuard(addrinfo* results) noexcept
            : results_{results}
        {
        }

        ~AddrInfoGuard()
        {
            if (results_ != nullptr)
            {
                ::freeaddrinfo(results_);
            }
        }

        AddrInfoGuard(AddrInfoGuard const&) = delete;
        auto operator=(AddrInfoGuard const&) -> AddrInfoGuard& = delete;
        AddrInfoGuard(AddrInfoGuard&&) noexcept = delete;
        auto operator=(AddrInfoGuard&&) noexcept -> AddrInfoGuard& = delete;

        [[nodiscard]] auto get() const noexcept -> addrinfo*
        {
            return results_;
        }

    private:
        addrinfo* results_{nullptr};
    };

    [[nodiscard]] auto decode_dns_name(unsigned char const* message, int message_length, unsigned char const* cursor,
                                       std::string& output) noexcept -> int
    {
        auto expanded = std::array<char, NS_MAXDNAME>{};
        auto const length =
            ::dn_expand(message, message + message_length, cursor, expanded.data(), static_cast<int>(expanded.size()));
        if (length < 0)
        {
            return length;
        }
        output = expanded.data();
        return length;
    }

    class SystemServerDiscoveryNetwork final : public ServerDiscoveryNetwork
    {
    public:
        [[nodiscard]] auto fetch_well_known(std::string_view server_name, std::uint32_t timeout_seconds)
            -> WellKnownServerResult override
        {
            auto const host_port = parse_host_port(server_name, default_https_port);
            if (!host_port.has_value())
            {
                return {false, false, {}, "server name is not a valid well-known host"};
            }

            auto addresses = lookup_addresses(host_port->host, host_port->port);
            if (!addresses.ok || !address_set_allowed(addresses.addresses))
            {
                return {false, false, {}, "well-known host address is private, loopback, or unresolved"};
            }

            auto request = http::OutboundRequest{};
            request.method = "GET";
            request.url = "https://" + std::string{server_name} + "/.well-known/matrix/server";
            request.pinned_addresses = std::move(addresses.addresses);
            request.connect_timeout_seconds = timeout_seconds;
            request.total_timeout_seconds = timeout_seconds;
            request.max_response_body_bytes = 64U * 1024U;

            auto client = http::OutboundClient{};
            auto response = client.perform(request);
            if (!response.ok)
            {
                return {false, false, {}, response.error_detail};
            }
            if (response.response.status != 200U)
            {
                return {false, true, {}, "well-known not present"};
            }
            return {true, true, std::move(response.response.body), {}};
        }

        [[nodiscard]] auto lookup_srv(std::string_view service_name) -> std::vector<SrvRecord> override
        {
            auto answer = std::array<unsigned char, 4096U>{};
            auto const service = std::string{service_name};
            auto const length =
                ::res_query(service.c_str(), ns_c_in, ns_t_srv, answer.data(), static_cast<int>(answer.size()));
            if (length <= 0)
            {
                return {};
            }

            auto handle = ns_msg{};
            if (::ns_initparse(answer.data(), length, &handle) != 0)
            {
                return {};
            }

            auto records = std::vector<SrvRecord>{};
            auto const count = ns_msg_count(handle, ns_s_an);
            for (auto index = int{0}; index < count; ++index)
            {
                auto record = ns_rr{};
                if (::ns_parserr(&handle, ns_s_an, index, &record) != 0 || ns_rr_type(record) != ns_t_srv)
                {
                    continue;
                }
                auto const* data = ns_rr_rdata(record);
                auto const data_length = ns_rr_rdlen(record);
                if (data_length < 7)
                {
                    continue;
                }
                auto target = std::string{};
                if (decode_dns_name(answer.data(), length, data + 6U, target) < 0 || target.empty())
                {
                    continue;
                }
                records.push_back(SrvRecord{
                    target,
                    static_cast<std::uint16_t>(ns_get16(data + 4U)),
                    static_cast<std::uint16_t>(ns_get16(data)),
                    static_cast<std::uint16_t>(ns_get16(data + 2U)),
                });
            }
            return sort_srv_records(std::move(records));
        }

        [[nodiscard]] auto lookup_addresses(std::string_view host, std::uint16_t port) -> ResolvedAddressSet override
        {
            auto hints = addrinfo{};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_NUMERICSERV;

            auto const host_string = std::string{host};
            auto const port_string = std::to_string(port);
            auto* raw_results = static_cast<addrinfo*>(nullptr);
            auto const status = ::getaddrinfo(host_string.c_str(), port_string.c_str(), &hints, &raw_results);
            auto results = AddrInfoGuard{raw_results};
            if (status != 0 || results.get() == nullptr)
            {
                return {false,
                        {},
                        status == 0 ? std::string{"address resolution failed"} : std::string{::gai_strerror(status)}};
            }

            auto addresses = std::vector<std::string>{};
            for (auto* candidate = results.get(); candidate != nullptr; candidate = candidate->ai_next)
            {
                auto storage = std::array<char, INET6_ADDRSTRLEN>{};
                void const* source = nullptr;
                if (candidate->ai_family == AF_INET)
                {
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    source = &reinterpret_cast<sockaddr_in const*>(candidate->ai_addr)->sin_addr;
                }
                else if (candidate->ai_family == AF_INET6)
                {
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    source = &reinterpret_cast<sockaddr_in6 const*>(candidate->ai_addr)->sin6_addr;
                }
                if (source == nullptr || ::inet_ntop(candidate->ai_family, source, storage.data(),
                                                     static_cast<socklen_t>(storage.size())) == nullptr)
                {
                    continue;
                }
                auto address = std::string{storage.data()};
                if (!address.empty() && std::ranges::find(addresses, address) == addresses.end())
                {
                    addresses.push_back(std::move(address));
                }
            }

            return addresses.empty() ? ResolvedAddressSet{false, {}, "address resolution returned no usable addresses"}
                                     : ResolvedAddressSet{true, std::move(addresses), {}};
        }
    };

} // namespace

auto discover_server(std::string_view server_name, std::string_view well_known_server) -> ServerDiscoveryResult
{
    auto result = ServerDiscoveryResult{};
    result.server_name = server_name;

    if (server_name.empty())
    {
        result.reason = "server name is empty";
        log_diagnostic("discovery.rejected", {{"reason", "server name is empty", false}});
        return result;
    }
    auto direct_host_port = parse_host_port(server_name, default_federation_port);
    if (!direct_host_port.has_value() ||
        (!server_name_is_valid(direct_host_port->host) && !host_is_numeric_ip(direct_host_port->host)))
    {
        result.reason = "server name is invalid";
        log_diagnostic("discovery.rejected",
                       {{"server_name", std::string{server_name}, false}, {"reason", "server name is invalid", false}});
        return result;
    }
    if (well_known_server.empty())
    {
        log_diagnostic("discovery.direct",
                       {{"server_name", std::string{server_name}, false}, {"method", "literal", false}});
        auto network = LiteralDiscoveryNetwork{};
        return resolve_destination(server_name, std::move(*direct_host_port), network);
    }

    auto host_port = extract_host_and_port(well_known_server);
    if (!host_port.has_value())
    {
        result.reason = "well-known delegation is invalid";
        log_diagnostic("discovery.rejected",
                       {{"server_name", std::string{server_name}, false},
                        {"reason",      "well-known delegation is invalid", false}});
        return result;
    }
    log_diagnostic("discovery.well_known",
                   {{"server_name",       std::string{server_name},     false},
                    {"delegated_to",      std::string{well_known_server}, false}});
    auto network = LiteralDiscoveryNetwork{};
    result = resolve_destination(server_name, std::move(*host_port), network);
    result.well_known_host = result.discovery_allowed ? result.resolved_host : std::string{};
    return result;
}

auto discover_server(std::string_view server_name, ServerDiscoveryNetwork& network, std::uint32_t timeout_seconds)
    -> ServerDiscoveryResult
{
    auto result = ServerDiscoveryResult{};
    result.server_name = server_name;

    if (server_name.empty())
    {
        result.reason = "server name is empty";
        log_diagnostic("discovery.rejected", {{"reason", "server name is empty", false}});
        return result;
    }
    auto direct_host_port = parse_host_port(server_name, default_federation_port);
    if (!direct_host_port.has_value() ||
        (!server_name_is_valid(direct_host_port->host) && !host_is_numeric_ip(direct_host_port->host)))
    {
        result.reason = "server name is invalid";
        log_diagnostic("discovery.rejected",
                       {{"server_name", std::string{server_name}, false}, {"reason", "server name is invalid", false}});
        return result;
    }

    // Matrix spec step 1: IP literal in server_name resolves directly.
    // Matrix spec step 2: explicit port (with non-IP host) resolves directly via A/AAAA,
    // skipping both well-known and SRV so the operator's port choice is honored.
    if (host_is_numeric_ip(direct_host_port->host) || direct_host_port->port_explicit)
    {
        log_diagnostic("discovery.direct",
                       {{"server_name", std::string{server_name}, false},
                        {"method",      host_is_numeric_ip(direct_host_port->host) ? "ip_literal" : "explicit_port", false}});
        return resolve_destination(server_name, std::move(*direct_host_port), network);
    }

    // Matrix spec step 3: consult /.well-known/matrix/server delegation.
    auto well_known = network.fetch_well_known(server_name, timeout_seconds);
    if (well_known.found && well_known.ok)
    {
        auto const delegated = extract_m_server(well_known.body);
        auto delegated_host_port =
            delegated.has_value() ? parse_host_port(*delegated, default_federation_port) : std::nullopt;
        if (delegated_host_port.has_value() &&
            (server_name_is_valid(delegated_host_port->host) || host_is_numeric_ip(delegated_host_port->host)))
        {
            log_diagnostic("discovery.well_known",
                           {{"server_name",   std::string{server_name},                false},
                            {"delegated_host", delegated_host_port->host,               false},
                            {"delegated_port", std::to_string(delegated_host_port->port), false}});
            // Step 3a: delegated IP literal resolves directly with the delegated port.
            // Step 3b: delegated host with an explicit port resolves directly.
            if (host_is_numeric_ip(delegated_host_port->host) || delegated_host_port->port_explicit)
            {
                result = resolve_destination(server_name, std::move(*delegated_host_port), network);
                result.well_known_host = result.discovery_allowed ? result.resolved_host : std::string{};
                return result;
            }
            // Step 3c: delegated host without a port tries SRV on the delegated host first,
            // then falls back to the delegated host on the default federation port.
            auto srv_records =
                sort_srv_records(network.lookup_srv(std::string{"_matrix-fed._tcp."} + delegated_host_port->host));
            if (!srv_records.empty())
            {
                auto const& first = srv_records.front();
                log_diagnostic("discovery.srv",
                               {{"server_name",  std::string{server_name}, false},
                                {"srv_target",   first.target,              false},
                                {"srv_port",     std::to_string(first.port), false},
                                {"via",          "well_known_delegated_srv", false}});
                result = resolve_destination(server_name, HostPort{first.target, first.port, true}, network);
                result.well_known_host = result.discovery_allowed ? result.resolved_host : std::string{};
                return result;
            }
            result = resolve_destination(server_name, std::move(*delegated_host_port), network);
            result.well_known_host = result.discovery_allowed ? result.resolved_host : std::string{};
            return result;
        }
        // Malformed body or missing m.server: fall through to SRV + direct resolution
        // on the original server name rather than failing closed.
        log_diagnostic("discovery.well_known_unusable",
                       {{"server_name", std::string{server_name}, false},
                        {"reason",      "malformed or missing m.server in well-known body", false}});
    }

    // Matrix spec step 4: SRV lookup on the original server name.
    auto srv_records = sort_srv_records(network.lookup_srv(std::string{"_matrix-fed._tcp."} + direct_host_port->host));
    if (!srv_records.empty())
    {
        auto const& first = srv_records.front();
        log_diagnostic("discovery.srv",
                       {{"server_name", std::string{server_name}, false},
                        {"srv_target",  first.target,              false},
                        {"srv_port",    std::to_string(first.port), false},
                        {"via",         "direct_srv",               false}});
        return resolve_destination(server_name, HostPort{first.target, first.port, true}, network);
    }

    // Matrix spec step 5: direct A/AAAA on the server name at the default port.
    log_diagnostic("discovery.direct",
                   {{"server_name", std::string{server_name}, false},
                    {"method",      "aaaa_fallback",           false},
                    {"port",        std::to_string(direct_host_port->port), false}});
    return resolve_destination(server_name, std::move(*direct_host_port), network);
}

auto discover_server(std::string_view server_name) -> ServerDiscoveryResult
{
    auto network = SystemServerDiscoveryNetwork{};
    return discover_server(server_name, network, 30U);
}

auto make_system_server_discovery_network() -> std::unique_ptr<ServerDiscoveryNetwork>
{
    return std::make_unique<SystemServerDiscoveryNetwork>();
}

} // namespace merovingian::federation
