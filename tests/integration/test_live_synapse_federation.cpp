// SPDX-License-Identifier: GPL-3.0-or-later

// Live integration tests against a real Synapse homeserver at
// matrix.ping.me.uk and a deployed Merovingian at pong.ping.me.uk.
//
// Tagged [live][federation] so they can be filtered with '[live]' and
// skipped in CI environments without network access. Each scenario
// checks connectivity first and SKIP()s if the remote is unreachable.

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_message.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace
{

// The Synapse homeserver controlled by the project maintainer.
constexpr auto synapse_server = std::string_view{"matrix.ping.me.uk"};

// The deployed Merovingian homeserver.
constexpr auto merovingian_server = std::string_view{"pong.ping.me.uk"};

// Default HTTPS port.
constexpr auto https_port = std::uint16_t{443U};

[[nodiscard]] auto sockaddr_address_string(sockaddr const& address) -> std::string
{
    auto buffer = std::array<char, INET6_ADDRSTRLEN>{};
    switch (address.sa_family)
    {
    case AF_INET:
    {
        auto const* ipv4 = reinterpret_cast<sockaddr_in const*>(&address);
        if (inet_ntop(AF_INET, &ipv4->sin_addr, buffer.data(), buffer.size()) != nullptr)
        {
            return std::string{buffer.data()};
        }
        break;
    }
    case AF_INET6:
    {
        auto const* ipv6 = reinterpret_cast<sockaddr_in6 const*>(&address);
        if (inet_ntop(AF_INET6, &ipv6->sin6_addr, buffer.data(), buffer.size()) != nullptr)
        {
            return std::string{buffer.data()};
        }
        break;
    }
    default:
        break;
    }
    return {};
}

// Resolve a hostname to a list of IPv4/IPv6 address strings suitable for
// OutboundRequest::pinned_addresses. Returns an empty vector on failure.
[[nodiscard]] auto resolve_host(std::string_view host, std::uint16_t port) -> std::vector<std::string>
{
    auto hints = addrinfo{};
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    auto* raw_results = static_cast<addrinfo*>(nullptr);
    auto const rc = getaddrinfo(std::string{host}.c_str(), std::to_string(port).c_str(), &hints, &raw_results);
    if (rc != 0)
    {
        return {};
    }
    auto addresses = std::vector<std::string>{};
    for (auto const* entry = raw_results; entry != nullptr; entry = entry->ai_next)
    {
        if (entry->ai_addr == nullptr)
        {
            continue;
        }
        auto const address = sockaddr_address_string(*entry->ai_addr);
        if (!address.empty())
        {
            addresses.push_back(address);
        }
    }
    freeaddrinfo(raw_results);
    return addresses;
}

// Check whether a remote server is reachable by attempting a TCP connection
// with a short timeout. Returns true if the connection succeeds.
[[nodiscard]] auto is_reachable(std::string_view host, std::uint16_t port) -> bool
{
    auto hints = addrinfo{};
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    auto const port_str = std::to_string(port);
    auto const host_str = std::string{host};
    auto* results = static_cast<addrinfo*>(nullptr);
    auto const rc = getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &results);
    if (rc != 0)
    {
        return false;
    }

    auto sockfd = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
    if (sockfd < 0)
    {
        freeaddrinfo(results);
        return false;
    }

    auto const tv = timeval{5, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    auto const connect_result = connect(sockfd, results->ai_addr, results->ai_addrlen);
    freeaddrinfo(results);
    close(sockfd);
    return connect_result == 0;
}

// Helper to look up a JSON object member.
[[nodiscard]] auto object_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> merovingian::canonicaljson::Value const*
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

// Helper to extract a string member from a JSON object.
[[nodiscard]] auto string_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::string const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
}

// Helper to extract an integer member from a JSON object.
[[nodiscard]] auto integer_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::int64_t const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
}

// Helper to extract an object member from a JSON object.
[[nodiscard]] auto object_member_as_object(merovingian::canonicaljson::Object const& object,
                                           std::string_view key) noexcept -> merovingian::canonicaljson::Object const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<merovingian::canonicaljson::Object>(&value->storage());
}

// Build a GET OutboundRequest for a given URL with DNS-pinned addresses.
[[nodiscard]] auto make_get_request(std::string const& url, std::vector<std::string> const& addresses)
    -> merovingian::http::OutboundRequest
{
    auto request = merovingian::http::OutboundRequest{};
    request.method = "GET";
    request.url = url;
    request.pinned_addresses = addresses;
    request.connect_timeout_seconds = 15U;
    request.total_timeout_seconds = 60U;
    return request;
}

} // namespace

SCENARIO("Fetch Synapse server keys via OutboundClient", "[live][federation]")
{
    GIVEN("network access to matrix.ping.me.uk")
    {
        if (!is_reachable(synapse_server, https_port))
        {
            SKIP("matrix.ping.me.uk is not reachable from this environment");
        }

        auto const addresses = resolve_host(synapse_server, https_port);
        REQUIRE_FALSE(addresses.empty());

        WHEN("fetching GET /_matrix/key/v2/server from matrix.ping.me.uk")
        {
            auto client = merovingian::http::OutboundClient{};
            auto const request =
                make_get_request("https://matrix.ping.me.uk/_matrix/key/v2/server", addresses);
            auto const result = client.perform(request);

            THEN("the response is valid JSON with server_name, verify_keys, and a future valid_until_ts")
            {
                INFO("Error: " << merovingian::http::outbound_error_name(result.error) << " - " << result.error_detail);
                REQUIRE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::none);
                REQUIRE(result.response.status == 200U);

                auto const parsed = merovingian::canonicaljson::parse_lossless(result.response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* server_name = string_member(*root, "server_name");
                REQUIRE(server_name != nullptr);
                REQUIRE(*server_name == "matrix.ping.me.uk");

                auto const* verify_keys = object_member_as_object(*root, "verify_keys");
                REQUIRE(verify_keys != nullptr);
                REQUIRE_FALSE(verify_keys->empty());

                auto const* valid_until_ts = integer_member(*root, "valid_until_ts");
                REQUIRE(valid_until_ts != nullptr);
                REQUIRE(*valid_until_ts > 0);
            }
        }
    }
}

SCENARIO("Fetch Synapse federation version via OutboundClient", "[live][federation]")
{
    GIVEN("network access to matrix.ping.me.uk")
    {
        if (!is_reachable(synapse_server, https_port))
        {
            SKIP("matrix.ping.me.uk is not reachable from this environment");
        }

        auto const addresses = resolve_host(synapse_server, https_port);
        REQUIRE_FALSE(addresses.empty());

        WHEN("fetching GET /_matrix/federation/v1/version from matrix.ping.me.uk")
        {
            auto client = merovingian::http::OutboundClient{};
            auto const request =
                make_get_request("https://matrix.ping.me.uk/_matrix/federation/v1/version", addresses);
            auto const result = client.perform(request);

            THEN("the response contains a server name and version")
            {
                INFO("Error: " << merovingian::http::outbound_error_name(result.error) << " - " << result.error_detail);
                REQUIRE(result.ok);
                REQUIRE(result.response.status == 200U);

                auto const parsed = merovingian::canonicaljson::parse_lossless(result.response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* server = string_member(*root, "server");
                REQUIRE(server != nullptr);
                REQUIRE(*server == "Synapse");

                auto const* version = string_member(*root, "version");
                REQUIRE(version != nullptr);
                REQUIRE_FALSE(version->empty());
            }
        }
    }
}

SCENARIO("Query Synapse user profile via OutboundClient", "[live][federation]")
{
    GIVEN("network access to matrix.ping.me.uk")
    {
        if (!is_reachable(synapse_server, https_port))
        {
            SKIP("matrix.ping.me.uk is not reachable from this environment");
        }

        auto const addresses = resolve_host(synapse_server, https_port);
        REQUIRE_FALSE(addresses.empty());

        WHEN("querying the displayname for @james:matrix.ping.me.uk")
        {
            auto client = merovingian::http::OutboundClient{};
            auto const request = make_get_request(
                "https://matrix.ping.me.uk/_matrix/federation/v1/query/profile?user_id=%40james%3Amatrix.ping.me.uk&field=displayname",
                addresses);
            auto const result = client.perform(request);

            THEN("the response is valid JSON")
            {
                INFO("Error: " << merovingian::http::outbound_error_name(result.error) << " - " << result.error_detail);
                REQUIRE(result.ok);
                REQUIRE(result.response.status == 200U);

                auto const parsed = merovingian::canonicaljson::parse_lossless(result.response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                // The response body must parse as valid JSON — the displayname
                // field may or may not be present depending on whether the user
                // has set one.
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
            }
        }
    }
}

SCENARIO("Discover Synapse via well-known", "[live][federation]")
{
    GIVEN("network access to matrix.ping.me.uk")
    {
        if (!is_reachable(synapse_server, https_port))
        {
            SKIP("matrix.ping.me.uk is not reachable from this environment");
        }

        auto const addresses = resolve_host(synapse_server, https_port);
        REQUIRE_FALSE(addresses.empty());

        WHEN("fetching GET /.well-known/matrix/server from matrix.ping.me.uk")
        {
            auto client = merovingian::http::OutboundClient{};
            auto const request =
                make_get_request("https://matrix.ping.me.uk/.well-known/matrix/server", addresses);
            auto const result = client.perform(request);

            THEN("the response contains a delegated server name")
            {
                INFO("Error: " << merovingian::http::outbound_error_name(result.error) << " - " << result.error_detail);
                REQUIRE(result.ok);
                REQUIRE(result.response.status == 200U);

                auto const parsed = merovingian::canonicaljson::parse_lossless(result.response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* mhs = object_member_as_object(*root, "m.homeserver");
                REQUIRE(mhs != nullptr);
                auto const* server_name = string_member(*mhs, "base_url");
                REQUIRE(server_name != nullptr);
                REQUIRE_FALSE(server_name->empty());
            }
        }
    }
}

SCENARIO("Full discovery and key fetch pipeline against Synapse", "[live][federation]")
{
    GIVEN("network access to matrix.ping.me.uk")
    {
        if (!is_reachable(synapse_server, https_port))
        {
            SKIP("matrix.ping.me.uk is not reachable from this environment");
        }

        WHEN("using fetch_remote_server_keys against matrix.ping.me.uk")
        {
            auto client = merovingian::http::OutboundClient{};
            auto network = merovingian::federation::make_system_server_discovery_network();
            REQUIRE(network != nullptr);

            auto const result =
                merovingian::federation::fetch_remote_server_keys(client, *network, synapse_server, 30U);

            THEN("the full pipeline succeeds and returns verified keys")
            {
                INFO("Error: " << result.reason);
                REQUIRE(result.ok);
                REQUIRE(result.response.server_name == "matrix.ping.me.uk");
                REQUIRE_FALSE(result.response.verify_keys.empty());
                REQUIRE(result.response.valid_until_ts > 0U);
                REQUIRE(result.reason.empty());
            }
        }
    }
}

SCENARIO("Fetch Merovingian server keys via OutboundClient", "[live][federation]")
{
    GIVEN("network access to pong.ping.me.uk")
    {
        if (!is_reachable(merovingian_server, https_port))
        {
            SKIP("pong.ping.me.uk is not reachable from this environment");
        }

        auto const addresses = resolve_host(merovingian_server, https_port);
        REQUIRE_FALSE(addresses.empty());

        WHEN("fetching GET /_matrix/key/v2/server from pong.ping.me.uk")
        {
            auto client = merovingian::http::OutboundClient{};
            auto const request =
                make_get_request("https://pong.ping.me.uk/_matrix/key/v2/server", addresses);
            auto const result = client.perform(request);

            THEN("the response is valid JSON with pong.ping.me.uk as server_name")
            {
                INFO("Error: " << merovingian::http::outbound_error_name(result.error) << " - " << result.error_detail);
                REQUIRE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::none);
                REQUIRE(result.response.status == 200U);

                auto const parsed = merovingian::canonicaljson::parse_lossless(result.response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* server_name = string_member(*root, "server_name");
                REQUIRE(server_name != nullptr);
                REQUIRE(*server_name == "pong.ping.me.uk");

                auto const* verify_keys = object_member_as_object(*root, "verify_keys");
                REQUIRE(verify_keys != nullptr);
                REQUIRE_FALSE(verify_keys->empty());

                auto const* valid_until_ts = integer_member(*root, "valid_until_ts");
                REQUIRE(valid_until_ts != nullptr);
                REQUIRE(*valid_until_ts > 0);
            }
        }
    }
}

SCENARIO("Discover Merovingian via well-known", "[live][federation]")
{
    GIVEN("network access to pong.ping.me.uk")
    {
        if (!is_reachable(merovingian_server, https_port))
        {
            SKIP("pong.ping.me.uk is not reachable from this environment");
        }

        auto const addresses = resolve_host(merovingian_server, https_port);
        REQUIRE_FALSE(addresses.empty());

        WHEN("fetching GET /.well-known/matrix/server from pong.ping.me.uk")
        {
            auto client = merovingian::http::OutboundClient{};
            auto const request =
                make_get_request("https://pong.ping.me.uk/.well-known/matrix/server", addresses);
            auto const result = client.perform(request);

            THEN("the response contains a delegated server name")
            {
                INFO("Error: " << merovingian::http::outbound_error_name(result.error) << " - " << result.error_detail);
                REQUIRE(result.ok);
                REQUIRE(result.response.status == 200U);

                auto const parsed = merovingian::canonicaljson::parse_lossless(result.response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* mhs = object_member_as_object(*root, "m.homeserver");
                REQUIRE(mhs != nullptr);
                auto const* server_name = string_member(*mhs, "base_url");
                REQUIRE(server_name != nullptr);
                REQUIRE_FALSE(server_name->empty());
            }
        }
    }
}
