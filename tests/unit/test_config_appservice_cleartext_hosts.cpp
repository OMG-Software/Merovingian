// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// appservice.allow_cleartext_hosts (ADR-0515): the hosts, besides loopback IP literals, to which an
// appservice registration url may use plain http. Each entry is a bare host name or IP literal.

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParseResult.hpp"
#include "merovingian/config/ConfigValidationFinding.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/ReloadPolicy.hpp"
#include "merovingian/config/config_parser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

namespace
{
constexpr auto hosts_key = std::string_view{"appservice.allow_cleartext_hosts"};

[[nodiscard]] auto hosts_findings(merovingian::config::ConfigParseResult const& result) -> std::size_t
{
    return static_cast<std::size_t>(
        std::ranges::count_if(result.findings, [](merovingian::config::ConfigValidationFinding const& finding) {
            return finding.field == hosts_key;
        }));
}

[[nodiscard]] auto parse_hosts(std::string_view value) -> merovingian::config::ConfigParseResult
{
    return merovingian::config::parse_key_value_config(std::string{hosts_key} + "=" + std::string{value} + "\n");
}
} // namespace

SCENARIO("No host may receive cleartext appservice traffic by default", "[config][appservice][cleartext]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the cleartext host list is read")
        {
            THEN("it is empty")
            {
                REQUIRE(config.appservice().allow_cleartext_hosts.empty());
            }
        }
    }
}

SCENARIO("The cleartext host list is parsed as a list", "[config][appservice][cleartext][parser]")
{
    GIVEN("a config naming a host name and an IP literal")
    {
        WHEN("it is parsed")
        {
            auto const result = parse_hosts("host.docker.internal, 10.0.0.5");

            THEN("both entries are kept in order and neither is a finding")
            {
                auto const& hosts = result.config.appservice().allow_cleartext_hosts;
                REQUIRE(hosts.size() == 2U);
                REQUIRE(hosts[0] == "host.docker.internal");
                REQUIRE(hosts[1] == "10.0.0.5");
                REQUIRE(hosts_findings(result) == 0U);
            }
        }
    }

    GIVEN("an empty value")
    {
        WHEN("it is parsed")
        {
            auto const result = parse_hosts("");

            THEN("no host is listed and there is no finding")
            {
                REQUIRE(result.config.appservice().allow_cleartext_hosts.empty());
                REQUIRE(hosts_findings(result) == 0U);
            }
        }
    }
}

SCENARIO("A cleartext host entry must be a bare host name or IP literal", "[config][appservice][cleartext][security]")
{
    GIVEN("entries that are acceptable")
    {
        auto const accepted = {"host.docker.internal", "bridge", "Bridge.Example.ORG", "10.1.2.3", "fd00::5", "::1"};

        WHEN("each is parsed")
        {
            THEN("none is a finding")
            {
                for (auto const* entry : accepted)
                {
                    INFO(entry);
                    REQUIRE(hosts_findings(parse_hosts(entry)) == 0U);
                }
            }
        }
    }

    GIVEN("entries carrying a scheme, port, path, userinfo, brackets, a wildcard or a stray dot")
    {
        auto const refused = {"http://bridge", "bridge:9000",  "bridge/path", "user@bridge", "[::1]",
                              "*.example.org", "bridge..test", ".bridge",     "bridge.",     "-bridge",
                              "br idge",       "bridge?x",     "bridge#x",    "br%69dge",    "10.0.0.1:80"};

        WHEN("each is parsed")
        {
            THEN("each is a startup finding")
            {
                for (auto const* entry : refused)
                {
                    INFO(entry);
                    REQUIRE(hosts_findings(parse_hosts(entry)) == 1U);
                }
            }
        }
    }

    GIVEN("a good entry listed next to a bad one")
    {
        WHEN("it is parsed")
        {
            auto const result = parse_hosts("bridge, bridge:9000");

            THEN("the setting is a finding, so a half-valid list never starts")
            {
                REQUIRE(hosts_findings(result) == 1U);
            }
        }
    }
}

SCENARIO("Changing the cleartext host list requires a restart", "[config][appservice][cleartext][reload]")
{
    GIVEN("a running config and a next config that lists a host")
    {
        auto const current = merovingian::config::Config{};
        auto const next = parse_hosts("host.docker.internal").config;

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the change is reported and needs a restart")
            {
                auto const change = std::ranges::find_if(plan.changes(), [](auto const& candidate) {
                    return candidate.key == hosts_key;
                });
                REQUIRE(change != plan.changes().end());
                REQUIRE(change->policy == merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key(hosts_key) ==
                        merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}
