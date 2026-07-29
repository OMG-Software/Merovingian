// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              OIDC CONFIGURATION PARSING AND VALIDATION TESTS           |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 — MSC2965 discovery metadata    |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// +-------------------------------------------------------------------------+

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"

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

SCENARIO("OIDC is disabled by default and requires no endpoints", "[config][oidc]")
{
    GIVEN("a default server configuration")
    {
        auto config = merovingian::config::Config{};

        WHEN("validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("no OIDC findings are reported")
            {
                REQUIRE(merovingian::config::is_valid(config));
                REQUIRE_FALSE(contains_finding(findings, "server.oidc.enabled"));
                REQUIRE_FALSE(contains_finding(findings, "server.oidc.issuer"));
            }
        }
    }
}

SCENARIO("OIDC configuration with all required HTTPS endpoints is valid", "[config][oidc]")
{
    GIVEN("a config string enabling OIDC with valid endpoints")
    {
        auto const input = std::string{
            "server.oidc.enabled=true\n"
            "server.oidc.issuer=https://account.example.com/\n"
            "server.oidc.authorization_endpoint=https://account.example.com/oauth2/auth\n"
            "server.oidc.token_endpoint=https://account.example.com/oauth2/token\n"
            "server.oidc.registration_endpoint=https://account.example.com/oauth2/clients/register\n"
            "server.oidc.revocation_endpoint=https://account.example.com/oauth2/revoke\n"
            "server.oidc.device_authorization_endpoint=https://account.example.com/oauth2/device\n"
            "server.oidc.account_management_uri=https://account.example.com/manage\n"
            "server.oidc.account_management_actions_supported=org.matrix.profile,org.matrix.devices_list\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the configuration is accepted")
            {
                REQUIRE(merovingian::config::is_valid(result.config));
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.server().oidc.enabled);
                REQUIRE(result.config.server().oidc.issuer == "https://account.example.com/");
                REQUIRE(result.config.server().oidc.account_management_actions_supported.size() == 2U);
            }
        }
    }
}

SCENARIO("OIDC enabled without required fields is rejected", "[config][oidc]")
{
    GIVEN("a config string enabling OIDC but omitting endpoints")
    {
        auto const input = std::string{"server.oidc.enabled=true\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("missing required fields are reported")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.oidc.issuer"));
                REQUIRE(contains_finding(result.findings, "server.oidc.authorization_endpoint"));
                REQUIRE(contains_finding(result.findings, "server.oidc.token_endpoint"));
                REQUIRE(contains_finding(result.findings, "server.oidc.registration_endpoint"));
                REQUIRE(contains_finding(result.findings, "server.oidc.revocation_endpoint"));
            }
        }
    }
}

SCENARIO("OIDC issuer must be an HTTPS origin URL with no query or fragment", "[config][oidc]")
{
    GIVEN("config inputs with invalid issuers")
    {
        auto const missing = std::string{"server.oidc.enabled=true\n"
                                         "server.oidc.authorization_endpoint=https://example.com/auth\n"
                                         "server.oidc.token_endpoint=https://example.com/token\n"
                                         "server.oidc.registration_endpoint=https://example.com/register\n"
                                         "server.oidc.revocation_endpoint=https://example.com/revoke\n"};

        auto const http = missing + "server.oidc.issuer=http://example.com/\n";
        auto const with_query = missing + "server.oidc.issuer=https://example.com/?foo=bar\n";
        auto const with_fragment = missing + "server.oidc.issuer=https://example.com/#section\n";

        WHEN("validated")
        {
            auto const missing_result = merovingian::config::parse_key_value_config(missing);
            auto const http_result = merovingian::config::parse_key_value_config(http);
            auto const query_result = merovingian::config::parse_key_value_config(with_query);
            auto const fragment_result = merovingian::config::parse_key_value_config(with_fragment);

            THEN("each invalid issuer is rejected")
            {
                REQUIRE(contains_finding(missing_result.findings, "server.oidc.issuer"));
                REQUIRE(contains_finding(http_result.findings, "server.oidc.issuer"));
                REQUIRE(contains_finding(query_result.findings, "server.oidc.issuer"));
                REQUIRE(contains_finding(fragment_result.findings, "server.oidc.issuer"));
            }
        }
    }
}

SCENARIO("OIDC endpoints must use HTTPS when present", "[config][oidc]")
{
    GIVEN("a config with a non-HTTPS endpoint")
    {
        auto const input = std::string{"server.oidc.enabled=true\n"
                                       "server.oidc.issuer=https://example.com/\n"
                                       "server.oidc.authorization_endpoint=http://example.com/auth\n"
                                       "server.oidc.token_endpoint=https://example.com/token\n"
                                       "server.oidc.registration_endpoint=https://example.com/register\n"
                                       "server.oidc.revocation_endpoint=https://example.com/revoke\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the cleartext endpoint is rejected")
            {
                REQUIRE(contains_finding(result.findings, "server.oidc.authorization_endpoint"));
            }
        }
    }

    GIVEN("a config with an optional non-HTTPS endpoint")
    {
        auto const input = std::string{"server.oidc.enabled=true\n"
                                       "server.oidc.issuer=https://example.com/\n"
                                       "server.oidc.authorization_endpoint=https://example.com/auth\n"
                                       "server.oidc.token_endpoint=https://example.com/token\n"
                                       "server.oidc.registration_endpoint=https://example.com/register\n"
                                       "server.oidc.revocation_endpoint=https://example.com/revoke\n"
                                       "server.oidc.account_management_uri=http://example.com/manage\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the optional cleartext URI is rejected")
            {
                REQUIRE(contains_finding(result.findings, "server.oidc.account_management_uri"));
            }
        }
    }
}

SCENARIO("is_valid_https_url requires an HTTPS scheme and non-empty authority", "[config][oidc][helpers]")
{
    GIVEN("a set of URLs to validate")
    {
        WHEN("checked")
        {
            THEN("HTTPS URLs are accepted")
            {
                REQUIRE(merovingian::config::is_valid_https_url("https://example.com/"));
                REQUIRE(merovingian::config::is_valid_https_url("https://example.com/path?query=1"));
            }

            THEN("non-HTTPS, empty, and malformed URLs are rejected")
            {
                REQUIRE_FALSE(merovingian::config::is_valid_https_url("http://example.com/"));
                REQUIRE_FALSE(merovingian::config::is_valid_https_url("https://"));
                REQUIRE_FALSE(merovingian::config::is_valid_https_url(""));
                REQUIRE_FALSE(merovingian::config::is_valid_https_url("https://exam ple.com/"));
            }
        }
    }
}

SCENARIO("is_valid_https_origin_url forbids query and fragment components", "[config][oidc][helpers]")
{
    GIVEN("a set of origin URLs to validate")
    {
        WHEN("checked")
        {
            THEN("plain HTTPS origins are accepted")
            {
                REQUIRE(merovingian::config::is_valid_https_origin_url("https://example.com/"));
                REQUIRE(merovingian::config::is_valid_https_origin_url("https://example.com"));
            }

            THEN("non-HTTPS, query, fragment, and malformed origins are rejected")
            {
                REQUIRE_FALSE(merovingian::config::is_valid_https_origin_url("http://example.com/"));
                REQUIRE_FALSE(merovingian::config::is_valid_https_origin_url("https://example.com/?q=1"));
                REQUIRE_FALSE(merovingian::config::is_valid_https_origin_url("https://example.com/#frag"));
                REQUIRE_FALSE(merovingian::config::is_valid_https_origin_url("https://"));
            }
        }
    }
}

SCENARIO("server.oidc.enabled rejects non-boolean values", "[config][oidc][parser]")
{
    GIVEN("a config string with a malformed boolean")
    {
        auto const input = std::string{"server.oidc.enabled=maybe\n"};

        WHEN("parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("a parse finding is reported")
            {
                REQUIRE(contains_finding(result.findings, "server.oidc.enabled"));
            }
        }
    }
}
