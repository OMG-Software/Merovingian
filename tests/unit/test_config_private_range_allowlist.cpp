// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// security.federation.allow_private_ip_ranges (ADR-0230): the explicit,
// operator-named exception to the built-in private-address block. Only
// RFC 1918 and ULA networks may be named; loopback, link-local, CGNAT,
// multicast, reserved and public space can never be opened by it.

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"
#include "merovingian/config/reload_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>

namespace
{
constexpr auto allowlist_key = std::string_view{"security.federation.allow_private_ip_ranges"};

[[nodiscard]] auto allowlist_findings(merovingian::config::ConfigParseResult const& result) -> std::size_t
{
    return static_cast<std::size_t>(
        std::ranges::count_if(result.findings, [](merovingian::config::ConfigValidationFinding const& finding) {
            return finding.field == allowlist_key;
        }));
}

[[nodiscard]] auto parse_allowlist(std::string_view value) -> merovingian::config::ConfigParseResult
{
    return merovingian::config::parse_key_value_config(std::string{allowlist_key} + "=" + std::string{value} + "\n");
}
} // namespace

SCENARIO("The private-range allowlist is empty by default", "[config][federation][private-allowlist]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the federation allowlist is read")
        {
            auto const& ranges = config.security().federation.allow_private_ip_ranges;

            THEN("no private address is opened")
            {
                REQUIRE(ranges.empty());
            }
        }
    }
}

SCENARIO("The private-range allowlist is parsed as a list", "[config][federation][private-allowlist][parser]")
{
    GIVEN("a config naming two private networks")
    {
        auto const input = std::string_view{"172.16.0.0/12, 10.5.0.0/16"};

        WHEN("it is parsed")
        {
            auto const result = parse_allowlist(input);

            THEN("both networks are kept in order and neither is a finding")
            {
                auto const& ranges = result.config.security().federation.allow_private_ip_ranges;
                REQUIRE(ranges.size() == 2U);
                REQUIRE(ranges[0] == "172.16.0.0/12");
                REQUIRE(ranges[1] == "10.5.0.0/16");
                REQUIRE(allowlist_findings(result) == 0U);
            }
        }
    }
}

SCENARIO("Only RFC 1918 and ULA networks may be allowlisted", "[config][federation][private-allowlist][security]")
{
    GIVEN("networks inside the private blocks")
    {
        auto const accepted = {"10.0.0.0/8",  "172.16.0.0/12", "172.18.0.0/16", "192.168.0.0/16", "192.168.65.0/24",
                               "10.1.2.3/32", "fc00::/7",      "fd00::/8",      "fd12:3456::/32"};

        WHEN("each is validated")
        {
            THEN("each is allowable and parses without a finding")
            {
                for (auto const* range : accepted)
                {
                    INFO(range);
                    REQUIRE(merovingian::config::private_ip_range_is_allowable(range));
                    REQUIRE(allowlist_findings(parse_allowlist(range)) == 0U);
                }
            }
        }
    }

    GIVEN("networks outside the private blocks, wider than them, or malformed")
    {
        auto const refused = {
            "127.0.0.0/8",         // loopback
            "127.0.0.1/32",        // loopback host
            "169.254.0.0/16",      // link-local, cloud metadata
            "169.254.169.254/32",  // the metadata endpoint itself
            "100.64.0.0/10",       // CGNAT
            "0.0.0.0/0",           // everything
            "0.0.0.0/8",           // "this network"
            "224.0.0.0/4",         // multicast
            "240.0.0.0/4",         // reserved
            "8.8.8.0/24",          // public
            "172.0.0.0/8",         // wider than 172.16/12
            "10.0.0.0/7",          // wider than 10/8
            "192.168.0.0/15",      // wider than 192.168/16
            "10.0.0.5/8",          // host bits set
            "172.18.0.3",          // no prefix
            "::1/128",             // IPv6 loopback
            "fe80::/10",           // IPv6 link-local
            "::/0",                // everything
            "fc00::/6",            // wider than ULA
            "::ffff:10.0.0.0/104", // IPv4-mapped: name the IPv4 network instead
            "64:ff9b::/96",        // NAT64
            "garbage",
            "10.0.0.0/",
            "10.0.0.0/+8",
        };

        WHEN("each is validated")
        {
            THEN("each is refused and is a startup finding")
            {
                for (auto const* range : refused)
                {
                    INFO(range);
                    REQUIRE_FALSE(merovingian::config::private_ip_range_is_allowable(range));
                    REQUIRE(allowlist_findings(parse_allowlist(range)) == 1U);
                }
            }
        }
    }

    GIVEN("an empty value")
    {
        auto const input = std::string_view{""};

        WHEN("it is validated and parsed")
        {
            auto const result = parse_allowlist(input);

            THEN("the empty string is no network, and an empty setting opens nothing")
            {
                REQUIRE_FALSE(merovingian::config::private_ip_range_is_allowable(input));
                REQUIRE(result.config.security().federation.allow_private_ip_ranges.empty());
                REQUIRE(allowlist_findings(result) == 0U);
            }
        }
    }

    GIVEN("one allowable network listed next to a refused one")
    {
        auto const input = std::string_view{"172.16.0.0/12, 127.0.0.0/8"};

        WHEN("it is parsed")
        {
            auto const result = parse_allowlist(input);

            THEN("the whole setting is a startup finding")
            {
                REQUIRE(allowlist_findings(result) == 1U);
            }
        }
    }
}

SCENARIO("Changing the private-range allowlist requires a restart", "[config][federation][private-allowlist][reload]")
{
    GIVEN("a running config and a next config that names a private network")
    {
        auto const current = merovingian::config::Config{};
        auto const next = parse_allowlist("172.16.0.0/12").config;

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the change is reported and needs a restart")
            {
                auto const change = std::ranges::find_if(plan.changes(), [](auto const& candidate) {
                    return candidate.key == allowlist_key;
                });
                REQUIRE(change != plan.changes().end());
                REQUIRE(change->policy == merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key(allowlist_key) ==
                        merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}
