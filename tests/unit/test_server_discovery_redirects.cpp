// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0483: the well-known fetch follows redirects, bounded and re-checked on every hop. The transport is a fake
// that answers from a table, so nothing here touches the network.

#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using merovingian::federation::WellKnownHopResponse;

class RedirectNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    using ServerDiscoveryNetwork::ServerDiscoveryNetwork;

    std::map<std::string, std::vector<std::string>> addresses{};

    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t)
        -> merovingian::federation::WellKnownServerResult override
    {
        return {};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view host, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
    {
        auto const found = addresses.find(std::string{host});
        if (found == addresses.end())
        {
            return {false, {}, "address not found"};
        }
        return {true, found->second, {}};
    }
};

struct HopLog final
{
    std::vector<std::string> urls{};
    std::vector<std::vector<std::string>> pins{};
    std::vector<std::uint32_t> budgets{};
};

[[nodiscard]] auto fetcher_for(std::map<std::string, WellKnownHopResponse> const& table, HopLog& log)
    -> merovingian::federation::WellKnownHopFetcher
{
    return [&table, &log](std::string const& url, std::vector<std::string> const& pins, std::uint32_t seconds) {
        log.urls.push_back(url);
        log.pins.push_back(pins);
        log.budgets.push_back(seconds);
        auto const found = table.find(url);
        return found == table.end() ? WellKnownHopResponse{false, 0U, {}, {}, "no such url"} : found->second;
    };
}

[[nodiscard]] auto redirect_to(std::string location, std::uint16_t status = 301U) -> WellKnownHopResponse
{
    return {true, status, std::move(location), {}, {}};
}

[[nodiscard]] auto answer(std::string body) -> WellKnownHopResponse
{
    return {true, 200U, {}, std::move(body), {}};
}

auto const first_url = std::string{"https://example.org/.well-known/matrix/server"};
auto const delegation = std::string{R"({"m.server":"matrix.example.org:8448"})"};

} // namespace

// Spec: Server-Server API v1.19, Resolving server names, step 3 ("30x redirects should be followed, however
// redirection loops should be avoided"). The hop limit, the per-hop address check and the shared deadline are this
// server's choice (ADR-0483).
SCENARIO("A well-known redirect is followed to the document it points at",
         "[federation][discovery][well-known][redirect]")
{
    GIVEN("a well-known URL that redirects to an absolute https URL and then to an absolute path")
    {
        auto network = RedirectNetwork{};
        network.addresses["example.org"] = {"198.51.100.1"};
        network.addresses["files.example.net"] = {"198.51.100.2"};
        auto const table = std::map<std::string, WellKnownHopResponse>{
            {first_url, redirect_to("https://files.example.net/matrix/server-a", 302U)},
            {"https://files.example.net/matrix/server-a", redirect_to("/matrix/server-b", 308U)},
            {"https://files.example.net/matrix/server-b", answer(delegation)},
        };
        auto log = HopLog{};

        WHEN("it is fetched")
        {
            auto const result = merovingian::federation::fetch_well_known_following_redirects(
                "example.org", 10U, network, fetcher_for(table, log));

            THEN("the document at the end is returned and each hop connected only to its own resolved addresses")
            {
                REQUIRE(result.found);
                REQUIRE(result.ok);
                REQUIRE(result.body == delegation);
                REQUIRE(log.urls.size() == 3U);
                REQUIRE(log.pins[0] == std::vector<std::string>{"198.51.100.1"});
                REQUIRE(log.pins[1] == std::vector<std::string>{"198.51.100.2"});
                REQUIRE(log.pins[2] == std::vector<std::string>{"198.51.100.2"});
            }
        }
    }
}

SCENARIO("A well-known redirect chain is bounded", "[federation][discovery][well-known][redirect]")
{
    GIVEN("a chain one redirect longer than the limit")
    {
        auto network = RedirectNetwork{};
        network.addresses["example.org"] = {"198.51.100.1"};
        auto table = std::map<std::string, WellKnownHopResponse>{};
        auto url = first_url;
        for (auto hop = 0U; hop <= merovingian::federation::well_known_max_redirects; ++hop)
        {
            auto const next = "https://example.org/hop" + std::to_string(hop);
            table[url] = redirect_to(next);
            url = next;
        }
        table[url] = answer(delegation);
        auto log = HopLog{};

        WHEN("it is fetched")
        {
            auto const result = merovingian::federation::fetch_well_known_following_redirects(
                "example.org", 10U, network, fetcher_for(table, log));

            THEN("it is refused and no more than the limit's worth of redirects was followed")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(log.urls.size() == merovingian::federation::well_known_max_redirects + 1U);
            }
        }
    }

    GIVEN("a chain exactly as long as the limit")
    {
        auto network = RedirectNetwork{};
        network.addresses["example.org"] = {"198.51.100.1"};
        auto table = std::map<std::string, WellKnownHopResponse>{};
        auto url = first_url;
        for (auto hop = 1U; hop <= merovingian::federation::well_known_max_redirects; ++hop)
        {
            auto const next = "https://example.org/hop" + std::to_string(hop);
            table[url] = redirect_to(next);
            url = next;
        }
        table[url] = answer(delegation);
        auto log = HopLog{};

        WHEN("it is fetched")
        {
            auto const result = merovingian::federation::fetch_well_known_following_redirects(
                "example.org", 10U, network, fetcher_for(table, log));

            THEN("the document is returned")
            {
                REQUIRE(result.ok);
            }
        }
    }

    GIVEN("two documents that redirect to each other")
    {
        auto network = RedirectNetwork{};
        network.addresses["example.org"] = {"198.51.100.1"};
        auto const table = std::map<std::string, WellKnownHopResponse>{
            {first_url,                  redirect_to("https://example.org/loop")},
            {"https://example.org/loop", redirect_to(first_url)                 },
        };
        auto log = HopLog{};

        WHEN("it is fetched")
        {
            auto const result = merovingian::federation::fetch_well_known_following_redirects(
                "example.org", 10U, network, fetcher_for(table, log));

            THEN("the loop is detected at the first repeat")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(log.urls.size() == 2U);
            }
        }
    }
}

SCENARIO("Every hop of a well-known redirect is checked before it is fetched",
         "[federation][discovery][well-known][redirect][ssrf]")
{
    auto network = RedirectNetwork{std::vector<std::string>{"10.0.0.0/8"}, std::vector<std::string>{}};
    network.addresses["example.org"] = {"198.51.100.1"};
    network.addresses["internal.example.net"] = {"10.1.2.3"};
    network.addresses["loopback.example.net"] = {"127.0.0.1"};
    network.addresses["public.example.net"] = {"198.51.100.9"};

    GIVEN("redirects to a host the deny-list covers, to loopback, to cleartext http, to a relative path, to an "
          "unresolvable host, to userinfo, to another scheme and to nothing")
    {
        auto const refused_targets = std::vector<std::string>{
            "https://internal.example.net/x", "https://loopback.example.net/x",
            "http://public.example.net/x",    "elsewhere",
            "https://nowhere.example.net/x",  "https://user@public.example.net/x",
            "ftp://public.example.net/x",     "",
        };

        WHEN("each is followed")
        {
            THEN("none is fetched, the first request's own address check having passed")
            {
                for (auto const& target : refused_targets)
                {
                    CAPTURE(target);
                    auto const table = std::map<std::string, WellKnownHopResponse>{
                        {first_url, redirect_to(target)}
                    };
                    auto log = HopLog{};
                    auto const result = merovingian::federation::fetch_well_known_following_redirects(
                        "example.org", 10U, network, fetcher_for(table, log));
                    REQUIRE_FALSE(result.ok);
                    REQUIRE(log.urls == std::vector<std::string>{first_url});
                }
            }
        }
    }

    GIVEN("a first request whose own host resolves into the deny-list")
    {
        network.addresses["example.org"] = {"10.9.9.9"};
        auto log = HopLog{};
        auto const table = std::map<std::string, WellKnownHopResponse>{};

        WHEN("it is fetched")
        {
            auto const result = merovingian::federation::fetch_well_known_following_redirects(
                "example.org", 10U, network, fetcher_for(table, log));

            THEN("nothing is requested")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(log.urls.empty());
            }
        }
    }
}

SCENARIO("A well-known redirect chain shares one deadline", "[federation][discovery][well-known][redirect][deadline]")
{
    GIVEN("a chain whose first hop takes the whole budget")
    {
        auto network = RedirectNetwork{};
        network.addresses["example.org"] = {"198.51.100.1"};
        auto const table = std::map<std::string, WellKnownHopResponse>{
            {first_url,                    redirect_to("https://example.org/second")},
            {"https://example.org/second", answer(delegation)                       },
        };
        auto log = HopLog{};
        auto const slow = merovingian::federation::WellKnownHopFetcher{
            [&table, &log](std::string const& url, std::vector<std::string> const&, std::uint32_t seconds) {
                log.urls.push_back(url);
                log.budgets.push_back(seconds);
                if (url == first_url)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{1100});
                }
                return table.at(url);
            }};

        WHEN("it is fetched with a one second budget")
        {
            auto const result =
                merovingian::federation::fetch_well_known_following_redirects("example.org", 1U, network, slow);

            THEN("the second hop is never started")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(log.urls == std::vector<std::string>{first_url});
                REQUIRE(log.budgets.front() == 1U);
            }
        }
    }

    GIVEN("a chain with a generous budget")
    {
        auto network = RedirectNetwork{};
        network.addresses["example.org"] = {"198.51.100.1"};
        auto const table = std::map<std::string, WellKnownHopResponse>{
            {first_url,                    redirect_to("https://example.org/second")},
            {"https://example.org/second", answer(delegation)                       },
        };
        auto log = HopLog{};

        WHEN("it is fetched")
        {
            std::ignore = merovingian::federation::fetch_well_known_following_redirects("example.org", 30U, network,
                                                                                        fetcher_for(table, log));

            THEN("no hop is given more than the whole budget")
            {
                REQUIRE(log.budgets.size() == 2U);
                for (auto const budget : log.budgets)
                {
                    REQUIRE(budget >= 1U);
                    REQUIRE(budget <= 30U);
                }
            }
        }
    }
}

SCENARIO("A well-known answer that is not a redirect or a 200 is reported as absent",
         "[federation][discovery][well-known][redirect]")
{
    GIVEN("a 404 at the end of a redirect")
    {
        auto network = RedirectNetwork{};
        network.addresses["example.org"] = {"198.51.100.1"};
        auto const table = std::map<std::string, WellKnownHopResponse>{
            {first_url,                  redirect_to("https://example.org/gone")     },
            {"https://example.org/gone", WellKnownHopResponse{true, 404U, {}, {}, {}}},
        };
        auto log = HopLog{};

        WHEN("it is fetched")
        {
            auto const result = merovingian::federation::fetch_well_known_following_redirects(
                "example.org", 10U, network, fetcher_for(table, log));

            THEN("discovery moves on as for any non-200: no document was found")
            {
                REQUIRE_FALSE(result.found);
            }
        }
    }
}
