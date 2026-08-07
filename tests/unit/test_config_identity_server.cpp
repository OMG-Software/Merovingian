// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |       IDENTITY SERVICE API CONFIGURATION PARSING & VALIDATION TESTS    |
// |                                                                         |
// |  Spec: Matrix Identity Service API v1.19                               |
// |  URL:  ../../docs/matrix-v1.19-spec/identity-service-api.md             |
// +-------------------------------------------------------------------------+

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto contains_finding(std::vector<merovingian::config::ConfigValidationFinding> const& findings,
                                    std::string_view field) -> bool
{
    for (auto const& finding : findings)
    {
        if (finding.field == field)
        {
            return true;
        }
    }
    return false;
}

} // namespace

SCENARIO("Identity server config is empty and valid by default", "[config][identity-server]")
{
    GIVEN("a default server configuration")
    {
        auto config = merovingian::config::Config{};

        WHEN("validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("no identity-server findings are reported and the allowlist is empty")
            {
                REQUIRE(merovingian::config::is_valid(config));
                REQUIRE_FALSE(contains_finding(findings, "server.identity_server.trusted_servers"));
                REQUIRE_FALSE(contains_finding(findings, "server.identity_server.default_server"));
                REQUIRE(config.server().identity_server.trusted_servers.empty());
                REQUIRE(config.server().identity_server.default_server.empty());
            }
        }
    }
}

SCENARIO("Identity server config parses the trusted list, default, bind domains, and timeouts",
         "[config][identity-server]")
{
    GIVEN("a config string configuring a trusted identity server")
    {
        auto const input =
            std::string{"server.identity_server.trusted_servers=https://is.example.org,https://is2.example.org\n"
                        "server.identity_server.default_server=https://is.example.org\n"
                        "server.identity_server.allowed_bind_domains=example.org,example.com\n"
                        "server.identity_server.connect_timeout_seconds=5\n"
                        "server.identity_server.total_timeout_seconds=20\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("all fields are populated and the configuration is accepted")
            {
                REQUIRE(merovingian::config::is_valid(result.config));
                REQUIRE(result.config.server().identity_server.trusted_servers.size() == 2U);
                REQUIRE(result.config.server().identity_server.trusted_servers[0U] == "https://is.example.org");
                REQUIRE(result.config.server().identity_server.default_server == "https://is.example.org");
                REQUIRE(result.config.server().identity_server.allowed_bind_domains.size() == 2U);
                REQUIRE(result.config.server().identity_server.connect_timeout_seconds == 5U);
                REQUIRE(result.config.server().identity_server.total_timeout_seconds == 20U);
            }
        }
    }
}

SCENARIO("Identity server trusted servers and default must use HTTPS", "[config][identity-server]")
{
    GIVEN("a config string with a cleartext trusted server and a cleartext default")
    {
        auto const input = std::string{"server.identity_server.trusted_servers=http://is.example.org\n"
                                       "server.identity_server.default_server=http://is2.example.org\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("both are rejected with HTTPS findings")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.identity_server.trusted_servers"));
                REQUIRE(contains_finding(result.findings, "server.identity_server.default_server"));
            }
        }
    }
}

SCENARIO("Identity server default must be a member of the trusted list", "[config][identity-server]")
{
    GIVEN("a config string whose default server is not in the trusted list")
    {
        auto const input = std::string{"server.identity_server.trusted_servers=https://is.example.org\n"
                                       "server.identity_server.default_server=https://other.example.org\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the default is rejected even though both URLs are HTTPS")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.identity_server.default_server"));
            }
        }
    }
}

SCENARIO("Identity server total timeout must be at least the connect timeout", "[config][identity-server]")
{
    GIVEN("a config string with total_timeout < connect_timeout")
    {
        auto const input = std::string{"server.identity_server.trusted_servers=https://is.example.org\n"
                                       "server.identity_server.connect_timeout_seconds=30\n"
                                       "server.identity_server.total_timeout_seconds=10\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the timeout ordering finding is reported")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.identity_server.total_timeout_seconds"));
            }
        }
    }
}

SCENARIO("Identity server config changes require a restart", "[config][identity-server][reload]")
{
    GIVEN("identity server config keys")
    {
        auto constexpr trusted = "server.identity_server.trusted_servers";
        auto constexpr default_server = "server.identity_server.default_server";
        auto constexpr bind_domains = "server.identity_server.allowed_bind_domains";
        auto constexpr connect_timeout = "server.identity_server.connect_timeout_seconds";
        auto constexpr total_timeout = "server.identity_server.total_timeout_seconds";

        WHEN("their reload policies are requested")
        {
            THEN("all are restart_required (the IS client and resolver are built at startup)")
            {
                REQUIRE(merovingian::config::reload_policy_for_key(trusted) ==
                        merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key(default_server) ==
                        merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key(bind_domains) ==
                        merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key(connect_timeout) ==
                        merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key(total_timeout) ==
                        merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}