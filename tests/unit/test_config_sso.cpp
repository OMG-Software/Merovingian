// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              SSO CONFIGURATION PARSING AND VALIDATION TESTS             |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 — "Client login via SSO"         |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// +-------------------------------------------------------------------------+

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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

SCENARIO("SSO is disabled by default and requires no configuration", "[config][sso]")
{
    GIVEN("a default server configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("validated")
        {
            auto const findings = merovingian::config::validate(config);

            THEN("SSO is disabled and no SSO findings are reported")
            {
                REQUIRE(merovingian::config::is_valid(config));
                REQUIRE_FALSE(config.server().sso.enabled);
                REQUIRE_FALSE(contains_finding(findings, "server.sso.authorization_url"));
                REQUIRE_FALSE(contains_finding(findings, "server.sso.redirect_url_allowlist"));
            }
        }
    }
}

SCENARIO("SSO configuration with authorization_url and a redirect allowlist is valid", "[config][sso]")
{
    GIVEN("a config string enabling SSO with a valid authorization_url and allowlist")
    {
        auto const input = std::string{"server.sso.enabled=true\n"
                                       "server.sso.authorization_url=https://sso.example.org/authorize\n"
                                       "server.sso.redirect_url_allowlist=https://client.example.com/,https://"
                                       "app.example.com/\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the configuration is accepted")
            {
                REQUIRE(merovingian::config::is_valid(result.config));
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.server().sso.enabled);
                REQUIRE(result.config.server().sso.authorization_url == "https://sso.example.org/authorize");
                REQUIRE(result.config.server().sso.redirect_url_allowlist.size() == 2U);
            }
        }
    }
}

SCENARIO("SSO enabled without authorization_url or a redirect allowlist is rejected (fail closed)",
         "[config][sso][security]")
{
    GIVEN("a config string enabling SSO but omitting both required fields")
    {
        auto const input = std::string{"server.sso.enabled=true\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("both missing required fields are reported and the config is invalid")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.sso.authorization_url"));
                REQUIRE(contains_finding(result.findings, "server.sso.redirect_url_allowlist"));
            }
        }
    }

    GIVEN("SSO enabled with an authorization_url but an empty redirect allowlist")
    {
        auto const input = std::string{"server.sso.enabled=true\n"
                                       "server.sso.authorization_url=https://sso.example.org/authorize\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the empty allowlist is rejected -- an enabled flow must not silently reject every redirect")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.sso.redirect_url_allowlist"));
            }
        }
    }
}

SCENARIO("SSO authorization_url and redirect allowlist entries must use HTTPS", "[config][sso]")
{
    GIVEN("a config with a non-HTTPS authorization_url")
    {
        auto const input = std::string{"server.sso.enabled=true\n"
                                       "server.sso.authorization_url=http://sso.example.org/authorize\n"
                                       "server.sso.redirect_url_allowlist=https://client.example.com/\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the cleartext authorization_url is rejected")
            {
                REQUIRE(contains_finding(result.findings, "server.sso.authorization_url"));
            }
        }
    }

    GIVEN("a config with a non-HTTPS redirect allowlist entry")
    {
        auto const input = std::string{"server.sso.enabled=true\n"
                                       "server.sso.authorization_url=https://sso.example.org/authorize\n"
                                       "server.sso.redirect_url_allowlist=http://client.example.com/\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the cleartext allowlist entry is rejected")
            {
                REQUIRE(contains_finding(result.findings, "server.sso.redirect_url_allowlist"));
            }
        }
    }
}

SCENARIO("SSO identity providers are parsed from dotted keys keyed by opaque idpId", "[config][sso][parser]")
{
    GIVEN("dotted identity_providers keys, including an idpId containing dots")
    {
        auto const input = std::string{"server.sso.identity_providers.com.example.idp.github.name=GitHub\n"
                                       "server.sso.identity_providers.com.example.idp.github.brand=github\n"
                                       "server.sso.identity_providers.com.example.idp.github.icon=mxc://example.com/"
                                       "abc123\n"
                                       "server.sso.identity_providers.gitlab.name=GitLab\n"};

        WHEN("parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("two identity providers are produced with the correct id/name/icon/brand")
            {
                REQUIRE(result.findings.empty());
                auto const& idps = result.config.server().sso.identity_providers;
                REQUIRE(idps.size() == 2U);

                auto const github = std::ranges::find_if(idps, [](auto const& idp) {
                    return idp.id == "com.example.idp.github";
                });
                REQUIRE(github != idps.end());
                REQUIRE(github->name == "GitHub");
                REQUIRE(github->brand == "github");
                REQUIRE(github->icon == "mxc://example.com/abc123");

                auto const gitlab = std::ranges::find_if(idps, [](auto const& idp) {
                    return idp.id == "gitlab";
                });
                REQUIRE(gitlab != idps.end());
                REQUIRE(gitlab->name == "GitLab");
                REQUIRE(gitlab->icon.empty());
            }
        }
    }
}

SCENARIO("SSO identity providers require a non-empty id, name, and an mxc:// icon", "[config][sso][security]")
{
    GIVEN("an identity provider missing its required name")
    {
        auto const input = std::string{"server.sso.enabled=true\n"
                                       "server.sso.authorization_url=https://sso.example.org/authorize\n"
                                       "server.sso.redirect_url_allowlist=https://client.example.com/\n"
                                       "server.sso.identity_providers.github.brand=github\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the missing name is reported")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.sso.identity_providers.github.name"));
            }
        }
    }

    GIVEN("an identity provider with a non-mxc:// icon")
    {
        auto const input = std::string{"server.sso.enabled=true\n"
                                       "server.sso.authorization_url=https://sso.example.org/authorize\n"
                                       "server.sso.redirect_url_allowlist=https://client.example.com/\n"
                                       "server.sso.identity_providers.github.name=GitHub\n"
                                       "server.sso.identity_providers.github.icon=https://evil.example.com/x.png\n"};

        WHEN("parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the non-mxc:// icon is rejected")
            {
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
                REQUIRE(contains_finding(result.findings, "server.sso.identity_providers.github.icon"));
            }
        }
    }
}

SCENARIO("server.sso.enabled rejects non-boolean values", "[config][sso][parser]")
{
    GIVEN("a config string with a malformed boolean")
    {
        auto const input = std::string{"server.sso.enabled=maybe\n"};

        WHEN("parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("a parse finding is reported")
            {
                REQUIRE(contains_finding(result.findings, "server.sso.enabled"));
            }
        }
    }
}

SCENARIO("a malformed identity_providers key without a field segment is rejected", "[config][sso][parser]")
{
    GIVEN("a dotted key with no trailing field name")
    {
        auto const input = std::string{"server.sso.identity_providers.github=oops\n"};

        WHEN("parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("a parse finding is reported rather than silently accepted")
            {
                REQUIRE(contains_finding(result.findings, "server.sso.identity_providers.github"));
            }
        }
    }
}
