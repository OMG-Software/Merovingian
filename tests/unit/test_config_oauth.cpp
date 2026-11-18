// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              server.oauth.* PARSING, VALIDATION AND RELOAD TESTS        |
// |                                                                         |
// |  Plan: docs/todos/oauth-2-0-api.md, "Configuration"                     |
// |  ADR-0813 (legacy API switch), ADR-0816 (server.oidc.* refused),        |
// |  ADR-0773 (issuer from public_baseurl), ADR-0774 (hand-off allowlist)   |
// +-------------------------------------------------------------------------+

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParser.hpp"
#include "merovingian/config/ConfigValidationFinding.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/ReloadPolicy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::config::ConfigValidationFinding;

[[nodiscard]] auto finding_for(std::vector<ConfigValidationFinding> const& findings, std::string_view field)
    -> ConfigValidationFinding const*
{
    for (auto const& finding : findings)
    {
        if (finding.field == field)
        {
            return &finding;
        }
    }
    return nullptr;
}

[[nodiscard]] auto contains_finding(std::vector<ConfigValidationFinding> const& findings, std::string_view field)
    -> bool
{
    return finding_for(findings, field) != nullptr;
}

[[nodiscard]] auto parse(std::string const& input) -> std::vector<ConfigValidationFinding>
{
    return merovingian::config::parse_key_value_config(input).findings;
}

} // namespace

SCENARIO("server.oauth.* defaults leave the OAuth 2.0 API off and the legacy API on", "[config][oauth]")
{
    GIVEN("a configuration that sets no server.oauth key")
    {
        WHEN("it is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config("");
            auto const& oauth = result.config.server().oauth;

            THEN("each key has its documented default and nothing is refused")
            {
                REQUIRE(result.findings.empty());
                CHECK_FALSE(oauth.enabled);
                CHECK(oauth.legacy_api_enabled);
                CHECK_FALSE(oauth.device_grant_enabled);
                CHECK(oauth.hand_off_redirect_allowlist.empty());
            }
        }
    }
}

SCENARIO("server.oauth.* keys are parsed into the configuration", "[config][oauth][parser]")
{
    GIVEN("a configuration that sets all four keys")
    {
        auto const input = std::string{"server.oauth.enabled=true\n"
                                       "server.oauth.legacy_api_enabled=false\n"
                                       "server.oauth.device_grant_enabled=true\n"
                                       "server.oauth.hand_off_redirect_allowlist=https://app.example.com, "
                                       "io.element.app:\n"};

        WHEN("it is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);
            auto const& oauth = result.config.server().oauth;

            THEN("every value is stored and the combination is accepted")
            {
                REQUIRE(result.findings.empty());
                CHECK(oauth.enabled);
                CHECK_FALSE(oauth.legacy_api_enabled);
                CHECK(oauth.device_grant_enabled);
                CHECK(oauth.hand_off_redirect_allowlist ==
                      std::vector<std::string>{"https://app.example.com", "io.element.app:"});
            }
        }
    }
}

SCENARIO("server.oauth.* boolean keys refuse a value that is not a boolean", "[config][oauth][parser]")
{
    GIVEN("each boolean key set to maybe")
    {
        auto const key = GENERATE(as<std::string>{}, "server.oauth.enabled", "server.oauth.legacy_api_enabled",
                                  "server.oauth.device_grant_enabled");

        WHEN("it is parsed")
        {
            auto const findings = parse(key + "=maybe\n");

            THEN("the key is refused")
            {
                INFO(key);
                REQUIRE(contains_finding(findings, key));
            }
        }
    }
}

SCENARIO("every server.oidc.* key is refused with a message naming server.oauth.enabled", "[config][oauth][oidc]")
{
    GIVEN("a configuration that still sets a server.oidc.* key")
    {
        auto const key = GENERATE(as<std::string>{}, "server.oidc.enabled", "server.oidc.issuer",
                                  "server.oidc.authorization_endpoint", "server.oidc.account_management_uri",
                                  "server.oidc.no_such_key");
        auto const value = std::string{key == "server.oidc.enabled" ? "false" : "https://auth.example.org/"};

        WHEN("it is parsed")
        {
            auto const findings = parse(key + "=" + value + "\n");

            THEN("start-up is refused, and the message points at server.oauth.enabled")
            {
                INFO(key);
                auto const* finding = finding_for(findings, key);
                REQUIRE(finding != nullptr);
                CHECK(finding->message.find("server.oauth.enabled") != std::string::npos);
                CHECK(finding->message.find("unknown configuration key") == std::string::npos);
            }
        }
    }
}

SCENARIO("server.oauth.legacy_api_enabled=false needs server.oauth.enabled=true", "[config][oauth]")
{
    GIVEN("the legacy API switched off")
    {
        WHEN("the OAuth 2.0 API is off")
        {
            auto const findings = parse("server.oauth.legacy_api_enabled=false\n");

            THEN("the configuration is refused: no user could log in")
            {
                REQUIRE(contains_finding(findings, "server.oauth.legacy_api_enabled"));
            }
        }

        WHEN("the OAuth 2.0 API is on")
        {
            auto const findings = parse("server.oauth.enabled=true\nserver.oauth.legacy_api_enabled=false\n");

            THEN("it is accepted")
            {
                REQUIRE(findings.empty());
            }
        }
    }
}

SCENARIO("server.oauth.device_grant_enabled=true needs server.oauth.enabled=true", "[config][oauth]")
{
    GIVEN("the device grant switched on")
    {
        WHEN("the OAuth 2.0 API is off")
        {
            auto const findings = parse("server.oauth.device_grant_enabled=true\n");

            THEN("the configuration is refused")
            {
                REQUIRE(contains_finding(findings, "server.oauth.device_grant_enabled"));
            }
        }

        WHEN("the OAuth 2.0 API is on")
        {
            auto const findings = parse("server.oauth.enabled=true\nserver.oauth.device_grant_enabled=true\n");

            THEN("it is accepted")
            {
                REQUIRE(findings.empty());
            }
        }
    }
}

SCENARIO("server.oauth.hand_off_redirect_allowlist needs server.oauth.enabled=true and valid entries",
         "[config][oauth][allowlist]")
{
    GIVEN("a hand-off allowlist")
    {
        WHEN("it is set while the OAuth 2.0 API is off")
        {
            auto const findings = parse("server.oauth.hand_off_redirect_allowlist=https://app.example.com\n");

            THEN("the configuration is refused")
            {
                REQUIRE(contains_finding(findings, "server.oauth.hand_off_redirect_allowlist"));
            }
        }

        WHEN("it names an entry twice while the OAuth 2.0 API is on")
        {
            auto const findings = parse("server.oauth.enabled=true\n"
                                        "server.oauth.hand_off_redirect_allowlist=io.element.app:,io.element.app:\n");

            THEN("the configuration is refused")
            {
                REQUIRE(contains_finding(findings, "server.oauth.hand_off_redirect_allowlist"));
            }
        }

        WHEN("it holds 33 entries while the OAuth 2.0 API is on")
        {
            auto list = std::string{};
            for (auto index = 0; index < 33; ++index)
            {
                list += (index == 0 ? "" : ",") + std::string{"https://h"} + std::to_string(index) + ".example.com";
            }
            auto const findings =
                parse("server.oauth.enabled=true\nserver.oauth.hand_off_redirect_allowlist=" + list + "\n");

            THEN("the configuration is refused")
            {
                REQUIRE(contains_finding(findings, "server.oauth.hand_off_redirect_allowlist"));
            }
        }
    }
}

SCENARIO("a hand-off allowlist entry of neither shape is refused", "[config][oauth][allowlist]")
{
    GIVEN("an entry that is neither an https origin nor a bare private-use scheme")
    {
        auto const entry = GENERATE(as<std::string>{}, "https://app.example.com/", "https://app.example.com/cb",
                                    "http://app.example.com", "app.example.com",
                                    "https:", "javascript:", "io.element.app:/callback", "https://App.example.com");

        WHEN("it is configured while the OAuth 2.0 API is on")
        {
            auto const findings =
                parse("server.oauth.enabled=true\nserver.oauth.hand_off_redirect_allowlist=" + entry + "\n");

            THEN("the configuration is refused")
            {
                INFO(entry);
                REQUIRE(contains_finding(findings, "server.oauth.hand_off_redirect_allowlist"));
            }
        }
    }
}

SCENARIO("an https server.public_baseurl, with or without a path, is accepted while OAuth is on",
         "[config][oauth][public_baseurl]")
{
    GIVEN("a plain https base URL, with or without a path and a trailing slash")
    {
        auto const base = GENERATE(as<std::string>{}, "https://matrix.example.org", "https://matrix.example.org/",
                                   "https://example.org/matrix", "https://example.org:8448/matrix/");

        WHEN("it is configured with server.oauth.enabled=true")
        {
            auto const findings = parse("server.oauth.enabled=true\nserver.public_baseurl=" + base + "\n");

            THEN("it is accepted")
            {
                INFO(base);
                REQUIRE(findings.empty());
            }
        }
    }
}

SCENARIO("a server.public_baseurl that breaks a rule is refused while OAuth is on, naming both keys",
         "[config][oauth][public_baseurl]")
{
    GIVEN("a base URL that is not https, has a query, fragment or userinfo, no host, or a space")
    {
        auto const base = GENERATE(as<std::string>{}, "http://matrix.example.org", "https://matrix.example.org/?a=b",
                                   "https://matrix.example.org/#top", "https://user@matrix.example.org", "https://",
                                   "https://matrix example.org", "https://matrix.example.org/a b");

        WHEN("it is configured with server.oauth.enabled=true")
        {
            auto const findings = parse("server.oauth.enabled=true\nserver.public_baseurl=" + base + "\n");

            THEN("start-up is refused with a message that names both keys")
            {
                INFO(base);
                // The generic public_baseurl check may report as well; one finding must name both keys.
                auto named = false;
                for (auto const& candidate : findings)
                {
                    named = named || (candidate.field == "server.public_baseurl" &&
                                      candidate.message.find("server.oauth.enabled") != std::string::npos &&
                                      candidate.message.find("server.public_baseurl") != std::string::npos);
                }
                REQUIRE(named);
            }
        }
    }
}

SCENARIO("server.public_baseurl with an upper-case scheme, or a query while OAuth is off",
         "[config][oauth][public_baseurl]")
{
    GIVEN("the OAuth 2.0 API switched on")
    {
        WHEN("server.public_baseurl is written with an upper-case scheme")
        {
            auto const findings =
                parse("server.oauth.enabled=true\nserver.public_baseurl=HTTPS://matrix.example.org\n");

            THEN("it is refused, not repaired")
            {
                REQUIRE(contains_finding(findings, "server.public_baseurl"));
            }
        }
    }

    GIVEN("the OAuth 2.0 API left off")
    {
        WHEN("server.public_baseurl has a query, which only the OAuth rule refuses")
        {
            auto const findings = parse("server.public_baseurl=https://matrix.example.org/?a=b\n");

            THEN("the validation that applied before is unchanged and accepts it")
            {
                REQUIRE_FALSE(contains_finding(findings, "server.public_baseurl"));
            }
        }
    }
}

SCENARIO("server.sso.authorization_url cannot be set while the OAuth 2.0 API is on", "[config][oauth][sso]")
{
    GIVEN("an external SSO authorization URL")
    {
        WHEN("the OAuth 2.0 API is on")
        {
            auto const findings = parse("server.oauth.enabled=true\n"
                                        "server.sso.authorization_url=https://sso.example.org/login\n");

            THEN("start-up is refused")
            {
                auto const* finding = finding_for(findings, "server.sso.authorization_url");
                REQUIRE(finding != nullptr);
                CHECK(finding->message.find("server.oauth.enabled") != std::string::npos);
            }
        }

        WHEN("the OAuth 2.0 API is off")
        {
            auto const findings = parse("server.sso.authorization_url=https://sso.example.org/login\n");

            THEN("the URL alone is not refused")
            {
                REQUIRE_FALSE(contains_finding(findings, "server.sso.authorization_url"));
            }
        }
    }
}

SCENARIO("every server.oauth.* key needs a restart", "[config][oauth][reload]")
{
    GIVEN("the four keys")
    {
        auto const key = GENERATE(as<std::string>{}, "server.oauth.enabled", "server.oauth.legacy_api_enabled",
                                  "server.oauth.device_grant_enabled", "server.oauth.hand_off_redirect_allowlist");

        WHEN("their reload policy is read")
        {
            auto const policy = merovingian::config::reload_policy_for_key(key);

            THEN("it is restart_required")
            {
                INFO(key);
                REQUIRE(policy == merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}

SCENARIO("the reload plan reports a change of each server.oauth.* key", "[config][oauth][reload]")
{
    GIVEN("a current configuration with OAuth off and a next one with every key changed")
    {
        auto const current = merovingian::config::parse_key_value_config("").config;
        auto const next =
            merovingian::config::parse_key_value_config("server.oauth.enabled=true\n"
                                                        "server.oauth.legacy_api_enabled=false\n"
                                                        "server.oauth.device_grant_enabled=true\n"
                                                        "server.oauth.hand_off_redirect_allowlist=io.element.app:\n")
                .config;

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("it lists all four keys as restart_required changes")
            {
                REQUIRE(plan.restart_required_change_count() == 4U);
                for (auto const* key :
                     {"server.oauth.enabled", "server.oauth.legacy_api_enabled", "server.oauth.device_grant_enabled",
                      "server.oauth.hand_off_redirect_allowlist"})
                {
                    INFO(key);
                    auto found = false;
                    for (auto const& change : plan.changes())
                    {
                        found = found || (change.key == key &&
                                          change.policy == merovingian::config::ReloadPolicy::restart_required);
                    }
                    CHECK(found);
                }
            }
        }
    }
}
